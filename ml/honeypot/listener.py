"""SentinelAI — Low-Interaction Honeypot Listener (Phase 15).

A simple TCP socket server that binds to a local port and logs every
incoming connection.  By definition, any connection to an unadvertised
honeypot port is suspicious — the honeypot IS the detection signal.

SCOPE LIMIT:
    Default bind: 127.0.0.1 (localhost ONLY).
    Do NOT bind to 0.0.0.0 without explicitly understanding what that
    exposes to your network.  This is a deliberate safety default.

DESIGN — Low-interaction honeypot:
    - Accept -> log first bytes -> close.  That's it.
    - No service emulation, no banner response, no interaction.
    - Every connection is logged and pushed through the agent triage
      pipeline (skipping ML, since the honeypot is the detection signal).
    - Events are tagged with "source": "honeypot" for dashboard filtering.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any, Callable, Awaitable


# ---------------------------------------------------------------------------
# Honeypot server
# ---------------------------------------------------------------------------

class HoneypotListener:
    """Async TCP honeypot that logs connections on a local port.

    Parameters
    ----------
    host : str
        Bind address.  Default 127.0.0.1 (localhost only).
    port : int
        Port to listen on.  Default 8899.
    on_connection : callable
        Async callback invoked for each connection with an event dict.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8899,
        on_connection: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ):
        self.host = host
        self.port = port
        self.on_connection = on_connection
        self._server: asyncio.AbstractServer | None = None
        self._running = False
        self._connection_count = 0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def connection_count(self) -> int:
        return self._connection_count

    async def start(self) -> None:
        """Start the honeypot listener."""
        if self._running:
            return

        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        self._running = True
        self._connection_count = 0
        print(f"  [honeypot] Listening on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the honeypot listener."""
        if not self._running:
            return

        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        print(f"  [honeypot] Stopped. Total connections logged: {self._connection_count}")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single incoming connection: log, read probe, close."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"
        src_port = peer[1] if peer else 0
        timestamp = time.time()

        self._connection_count += 1
        conn_id = self._connection_count

        # Read first bytes (probe/banner grab) with a short timeout
        probe_bytes = b""
        try:
            probe_bytes = await asyncio.wait_for(
                reader.read(512),
                timeout=2.0,
            )
        except (asyncio.TimeoutError, ConnectionError):
            pass

        # Close immediately — no response, no interaction
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        probe_text = probe_bytes.decode("utf-8", errors="replace").strip()[:200]

        print(
            f"  [honeypot] #{conn_id} Connection from {src_ip}:{src_port} "
            f"probe={repr(probe_text[:60])} ({len(probe_bytes)} bytes)"
        )

        # Build event for the triage pipeline
        event = build_honeypot_event(
            src_ip=src_ip,
            src_port=src_port,
            dst_port=self.port,
            probe_bytes=probe_bytes,
            probe_text=probe_text,
            timestamp=timestamp,
            connection_id=conn_id,
        )

        # Fire callback (async)
        if self.on_connection:
            try:
                await self.on_connection(event)
            except Exception as exc:
                print(f"  [honeypot] Callback error: {exc}")


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def build_honeypot_event(
    src_ip: str,
    src_port: int,
    dst_port: int,
    probe_bytes: bytes,
    probe_text: str,
    timestamp: float,
    connection_id: int,
) -> dict[str, Any]:
    """Build an NSL-KDD-shaped event dict from a honeypot connection.

    The honeypot IS the detection signal — every connection is anomalous
    by construction.  We approximate what we can and zero-fill the rest.
    """
    # Approximate duration from probe read (very short, ~0)
    duration = 0

    # Guess service from dst_port (though the honeypot port is unlikely
    # to map to a real service — that's the point)
    service = "other"

    event: dict[str, Any] = {
        # Fields we can approximate
        "duration": duration,
        "protocol_type": "tcp",
        "service": service,
        "flag": "S0",  # Most honeypot connections are short / SYN-only
        "src_bytes": len(probe_bytes),
        "dst_bytes": 0,  # We never respond
        "land": 0,
        "logged_in": 0,

        # Content / host features (not applicable for honeypot)
        "wrong_fragment": 0, "urgent": 0, "hot": 0,
        "num_failed_logins": 0, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0,
        "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0,

        # Connection-level stats
        "count": 0, "srv_count": 0,
        "serror_rate": 0.0, "srv_serror_rate": 0.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,

        # Host-level stats
        "dst_host_count": 0, "dst_host_srv_count": 0,
        "dst_host_same_srv_rate": 0.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    }

    # Honeypot-specific metadata
    event["_honeypot"] = {
        "source": "honeypot",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "probe_text": probe_text,
        "probe_bytes_len": len(probe_bytes),
        "timestamp": timestamp,
        "connection_id": connection_id,
    }

    return event
