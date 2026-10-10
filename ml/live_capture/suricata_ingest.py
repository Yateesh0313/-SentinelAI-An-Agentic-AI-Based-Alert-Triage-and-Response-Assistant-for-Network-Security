"""SentinelAI — Suricata IDS Ingestor (Phase 22).

Manages Suricata as a subprocess and tails its eve.json output to feed
signature-based alerts into the SentinelAI triage pipeline.

DESIGN:
    Suricata alerts are ALREADY positive detections by definition — a fired
    signature means a known-bad pattern was matched against curated rules
    (ET Open, 47k+ signatures).  Therefore these alerts SKIP the ML detection
    layer and go straight to agent triage, exactly like honeypot events.

    This is architecturally identical to the honeypot listener: the detection
    signal comes from Suricata (not ML), and the rest of the pipeline
    (triage, enrichment, risk scoring, storage, WebSocket broadcast) runs
    unchanged.

MODES:
    - Live capture: ``suricata -i <interface>`` (requires Npcap on Windows)
    - PCAP replay:  ``suricata -r <file.pcap>`` (no driver needed)

SCOPE LIMIT:
    Live capture monitors loopback / own-network interfaces ONLY.
    Same safety scope as Phase 14/15 — never a network you don't own.

EVE.JSON FORMAT (alert events):
    {
        "timestamp": "2024-01-01T00:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024897,
            "rev": 3,
            "signature": "ET SCAN Nmap Scripting Engine User-Agent",
            "category": "Attempted Information Leak",
            "severity": 2   // 1=High, 2=Medium, 3=Low, 4=Informational
        }
    }
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Awaitable


# ---------------------------------------------------------------------------
# Suricata severity mapping (1-based integer → string label)
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[int, str] = {
    1: "Critical",   # Suricata severity 1 = highest
    2: "High",
    3: "Medium",
    4: "Low",
}

# Category → approximate MITRE ATT&CK tactic mapping
_CATEGORY_TO_TACTIC: dict[str, str] = {
    "A Network Trojan was detected":        "Command and Control",
    "Attempted Administrator Privilege Gain": "Privilege Escalation",
    "Attempted Information Leak":           "Discovery",
    "Attempted User Privilege Gain":        "Privilege Escalation",
    "Crypto Currency Mining Activity Detected": "Resource Hijacking",
    "Denial of Service":                    "Impact",
    "Executable Code was Detected":         "Execution",
    "Exploit Kit Activity Detected":        "Initial Access",
    "Malware Command and Control Activity Detected": "Command and Control",
    "Misc Attack":                          "Execution",
    "Misc activity":                        "Discovery",
    "Not Suspicious Traffic":               "Benign",
    "Potentially Bad Traffic":              "Discovery",
    "Potential Corporate Privacy Violation": "Collection",
    "Web Application Attack":               "Initial Access",
}


# ---------------------------------------------------------------------------
# Suricata Ingestor
# ---------------------------------------------------------------------------

class SuricataIngestor:
    """Manage a Suricata subprocess and ingest eve.json alerts.

    Parameters
    ----------
    suricata_bin : str
        Path to suricata.exe.
    config_path : str
        Path to suricata.yaml.
    log_dir : str
        Directory where Suricata writes eve.json.
    interface : str or None
        Network interface for live capture (e.g. "127.0.0.1").
        If None, defaults to pcap replay mode.
    pcap_file : str or None
        Path to .pcap file for offline replay mode.
    on_alert : callable
        Async callback invoked for each parsed alert event dict.
    """

    # Default paths for the Windows installation
    DEFAULT_BIN = r"C:\Users\User\suricata\suricata.exe"
    DEFAULT_CONFIG = r"C:\Users\User\suricata\suricata.yaml"
    DEFAULT_LOG_DIR = r"C:\Users\User\suricata\log\sentinel"

    def __init__(
        self,
        suricata_bin: str | None = None,
        config_path: str | None = None,
        log_dir: str | None = None,
        interface: str | None = "127.0.0.1",
        pcap_file: str | None = None,
        on_alert: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ):
        self.suricata_bin = suricata_bin or self.DEFAULT_BIN
        self.config_path = config_path or self.DEFAULT_CONFIG
        self.log_dir = log_dir or self.DEFAULT_LOG_DIR
        self.interface = interface
        self.pcap_file = pcap_file
        self.on_alert = on_alert

        self._process: subprocess.Popen | None = None
        self._tail_task: asyncio.Task | None = None
        self._running = False
        self._alert_count = 0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def alert_count(self) -> int:
        return self._alert_count

    @property
    def eve_json_path(self) -> Path:
        return Path(self.log_dir) / "eve.json"

    # ------------------------------------------------------------------
    # Start / Stop
    # ------------------------------------------------------------------

    async def start(self) -> dict[str, Any]:
        """Start the Suricata subprocess and begin tailing eve.json.

        Returns a status dict with process info.
        """
        if self._running:
            return {"status": "already_running", "alerts": self._alert_count}

        # Validate binary
        if not Path(self.suricata_bin).exists():
            return {"status": "error", "detail": f"Suricata binary not found: {self.suricata_bin}"}

        # Create log directory
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)

        # Clear old eve.json so we don't re-process stale alerts
        eve = self.eve_json_path
        if eve.exists():
            eve.unlink()

        # Build command
        cmd = [
            self.suricata_bin,
            "-c", self.config_path,
            "-l", self.log_dir,
        ]

        if self.pcap_file:
            cmd.extend(["-r", self.pcap_file])
            mode = f"pcap_replay:{self.pcap_file}"
        elif self.interface:
            cmd.extend(["-i", self.interface])
            mode = f"live:{self.interface}"
        else:
            return {"status": "error", "detail": "No interface or pcap file specified"}

        print(f"  [suricata] Starting: {' '.join(cmd)}")

        console_log_path = Path(self.log_dir) / "suricata_console.log"
        self._console_log = open(console_log_path, "w", encoding="utf-8", errors="ignore")

        try:
            self._process = subprocess.Popen(
                cmd,
                cwd=str(Path(self.suricata_bin).parent),
                stdout=self._console_log,
                stderr=self._console_log,
            )
        except Exception as exc:
            self._console_log.close()
            return {"status": "error", "detail": f"Failed to start Suricata: {exc}"}

        self._running = True
        self._alert_count = 0

        # Start tailing eve.json in background
        self._tail_task = asyncio.create_task(self._tail_eve_json())

        print(f"  [suricata] Started (PID {self._process.pid}, mode={mode})")
        return {
            "status": "started",
            "pid": self._process.pid,
            "mode": mode,
            "eve_json": str(eve),
        }

    async def stop(self) -> dict[str, Any]:
        """Stop the Suricata subprocess and tailing task."""
        if not self._running:
            return {"status": "not_running"}

        self._running = False

        # Cancel tail task
        if self._tail_task:
            self._tail_task.cancel()
            try:
                await self._tail_task
            except asyncio.CancelledError:
                pass
            self._tail_task = None

        # Terminate Suricata process
        alerts = self._alert_count
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        if hasattr(self, "_console_log") and self._console_log and not self._console_log.closed:
            try:
                self._console_log.close()
            except Exception:
                pass
            self._console_log = None

        print(f"  [suricata] Stopped. Total alerts ingested: {alerts}")
        return {"status": "stopped", "total_alerts": alerts}

    # ------------------------------------------------------------------
    # Eve.json tailer
    # ------------------------------------------------------------------

    async def _tail_eve_json(self) -> None:
        """Continuously tail eve.json for new alert events."""
        eve = self.eve_json_path

        # Wait for eve.json to appear (Suricata takes a moment to start)
        for _ in range(30):  # Wait up to 30 seconds
            if eve.exists():
                break
            if not self._running:
                return
            # Also check if process died
            if self._process and self._process.poll() is not None:
                rc = self._process.returncode
                print(f"  [suricata] Process exited early (rc={rc})")
                # Read stderr for diagnostics
                try:
                    stderr = self._process.stderr.read().decode(errors="ignore")[:500] if self._process.stderr else ""
                    if stderr:
                        print(f"  [suricata] stderr: {stderr}")
                except Exception:
                    pass
                self._running = False
                return
            await asyncio.sleep(1.0)
        else:
            print("  [suricata] WARNING: eve.json did not appear within 30s")
            self._running = False
            return

        print(f"  [suricata] Tailing {eve}")

        with open(eve, "r", encoding="utf-8") as f:
            while self._running:
                line = f.readline()
                if not line:
                    # Check if Suricata process is still alive
                    if self._process and self._process.poll() is not None:
                        # Process finished — drain remaining lines
                        for remaining in f:
                            await self._process_line(remaining)
                        print(f"  [suricata] Process finished. Total alerts: {self._alert_count}")
                        self._running = False
                        return
                    # No new data yet — wait briefly
                    await asyncio.sleep(0.5)
                    continue

                await self._process_line(line)

    async def _process_line(self, line: str) -> None:
        """Parse a single eve.json line and dispatch alerts."""
        line = line.strip()
        if not line:
            return

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return

        event_type = record.get("event_type", "")

        # Only process alert events
        if event_type != "alert":
            return

        alert = record.get("alert", {})
        self._alert_count += 1

        event = self._build_event(record, alert)

        sig = alert.get("signature", "unknown")
        src = record.get("src_ip", "?")
        dst = record.get("dest_ip", "?")
        sev = _SEVERITY_MAP.get(alert.get("severity", 4), "Low")
        print(
            f"  [suricata] Alert #{self._alert_count}: "
            f"{src} -> {dst} | {sig} | severity={sev}"
        )

        if self.on_alert:
            try:
                await self.on_alert(event)
            except Exception as exc:
                print(f"  [suricata] Alert callback error: {exc}")

    # ------------------------------------------------------------------
    # Event builder
    # ------------------------------------------------------------------

    def _build_event(
        self,
        record: dict[str, Any],
        alert: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a pipeline-ready event dict from a Suricata alert.

        The event contains:
          - Suricata metadata (signature, category, severity)
          - Network 5-tuple (src/dst IP, src/dst port, proto)
          - Pre-set fields for the triage pipeline
        """
        suricata_severity = alert.get("severity", 4)
        severity_label = _SEVERITY_MAP.get(suricata_severity, "Low")
        category = alert.get("category", "Unknown")
        tactic = _CATEGORY_TO_TACTIC.get(category, "Unknown")

        return {
            # Pipeline fields
            "event_index": self._alert_count,
            "prediction": "suricata_alert",  # Not ML-derived
            "confidence": 1.0,               # Signature match = 100%
            "source": "suricata",

            # Suricata-specific metadata
            "suricata_meta": {
                "signature": alert.get("signature", "Unknown Signature"),
                "signature_id": alert.get("signature_id", 0),
                "category": category,
                "severity": suricata_severity,
                "severity_label": severity_label,
                "tactic": tactic,
                "action": alert.get("action", "allowed"),
                "gid": alert.get("gid", 1),
                "rev": alert.get("rev", 0),
            },

            # Network metadata
            "network_meta": {
                "src_ip": record.get("src_ip", "unknown"),
                "src_port": record.get("src_port", 0),
                "dst_ip": record.get("dest_ip", "unknown"),
                "dst_port": record.get("dest_port", 0),
                "proto": record.get("proto", "TCP"),
                "timestamp": record.get("timestamp", ""),
            },

            # Raw event in NSL-KDD-ish shape (for pipeline compatibility)
            "raw_event": {
                "duration": 0,
                "protocol_type": record.get("proto", "tcp").lower(),
                "service": self._guess_service(record.get("dest_port", 0)),
                "flag": "SF",
                "src_bytes": 0,
                "dst_bytes": 0,
                "land": 0,
                "logged_in": 0,
            },
        }

    @staticmethod
    def _guess_service(port: int) -> str:
        """Map destination port to NSL-KDD service name."""
        service_map = {
            80: "http", 443: "http", 8080: "http",
            21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "domain_u", 110: "pop_3",
            143: "imap4", 3389: "other", 445: "other",
        }
        return service_map.get(port, "other")
