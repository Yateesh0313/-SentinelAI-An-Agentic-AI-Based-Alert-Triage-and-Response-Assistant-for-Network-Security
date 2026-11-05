"use client";

import { useSentinelWS, type SentinelEvent, type AttackTechnique, type IPEnrichment, type SignatureMatch, type HoneypotMeta, type SuricataMeta, type NetworkMeta, type SuricataStatus, type LiveCaptureStatus, type LiveInterface } from "@/hooks/use-sentinel-ws";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { Search, Check, X, Flag, ShieldAlert, Info, Zap, Copy } from "lucide-react";
import { DatasetUploadView } from "@/components/dataset-upload-view";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { SentinelLogo } from "@/components/ui/sentinel-logo";
import dynamic from "next/dynamic";

const API_BASE = "http://localhost:8000";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("sentinel_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Tiny mini-sparkline using SVG path                                         */
/* ────────────────────────────────────────────────────────────────────────── */

function MiniSparkline({
  data,
  color = "#4f46e5",
  height = 32,
}: {
  data: number[];
  color?: string;
  height?: number;
}) {
  if (!data || data.length < 2) return <div style={{ height }} className="trend-sparkline rounded" />;
  const w = 80;
  const h = height;
  const max = Math.max(...data, 1);
  const pts = data
    .map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * (h - 4)}`)
    .join(" ");
  return (
    <svg width={w} height={h} className="overflow-visible">
      <defs>
        <linearGradient id={`sg-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.18" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>
      <polyline
        points={pts}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}



/* ────────────────────────────────────────────────────────────────────────── */
/* Capture Status Bar                                                          */
/* ────────────────────────────────────────────────────────────────────────── */

function CaptureStatusBar({
  connected,
  wsStatus,
  replaying,
  honeypotRunning,
  suricataRunning,
  suricataStatus,
  liveCaptureRunning,
  liveCaptureStatus,
  activeInterface,
  eventCount,
}: {
  connected: boolean;
  wsStatus: "connecting" | "connected" | "reconnecting" | "failed";
  replaying: boolean;
  honeypotRunning: boolean;
  suricataRunning: boolean;
  suricataStatus?: SuricataStatus | null;
  liveCaptureRunning?: boolean;
  liveCaptureStatus?: LiveCaptureStatus | null;
  activeInterface?: string;
  eventCount: number;
}) {
  let statusText = "Connecting…";
  if (connected) {
    if (liveCaptureRunning && liveCaptureStatus?.interface) {
      const pkts = liveCaptureStatus.total_packets ?? 0;
      const anom = liveCaptureStatus.anomalies_detected ?? 0;
      statusText = `Live Sniffer: ${liveCaptureStatus.interface} — ${pkts} pkts (${anom} anomalies)`;
    } else if (suricataRunning && suricataStatus?.interface) {
      const epm = suricataStatus.events_per_minute ?? 0;
      statusText = `Live capture: ${suricataStatus.interface} — ${epm} evt/min (${suricataStatus.alerts ?? 0} alerts)`;
    } else if (replaying) {
      statusText = `Live capture: ${activeInterface || "replaying"} — ${eventCount} events`;
    } else {
      statusText = "Live capture: idle";
    }
  } else if (wsStatus === "reconnecting") {
    statusText = "Reconnecting…";
  } else if (wsStatus === "failed") {
    statusText = "Live capture: offline";
  }

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-white dark:bg-[#111827] border border-slate-200 dark:border-slate-700 shadow-sm mb-5">
      {/* Status dot */}
      <div className="relative flex-shrink-0">
        <span
          className={`w-2.5 h-2.5 rounded-full block transition-all duration-500 ${
            connected
              ? "bg-emerald-500"
              : wsStatus === "reconnecting"
              ? "bg-amber-400 animate-pulse"
              : wsStatus === "failed"
              ? "bg-red-500"
              : "bg-slate-400 animate-pulse"
          }`}
        />
        {connected && (
          <span className="absolute inset-0 rounded-full bg-emerald-500 opacity-30 animate-ping" />
        )}
      </div>
      <span className="text-sm font-medium text-slate-700">{statusText}</span>
      <div className="flex items-center gap-2 ml-auto flex-wrap">
        {replaying && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[0.65rem] font-bold bg-blue-50 text-blue-700 border border-blue-200">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
            LIVE
          </span>
        )}
        {honeypotRunning && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[0.65rem] font-bold bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200">
            <span className="w-1.5 h-1.5 rounded-full bg-fuchsia-500 animate-pulse" />
            HONEYPOT :8899
          </span>
        )}
        {/* Live-capture / Suricata status chip (interface, running/stopped, evt/min) */}
        <span
          className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold border shadow-sm ${
            suricataRunning
              ? "bg-cyan-50 text-cyan-800 border-cyan-200"
              : "bg-slate-50 text-slate-600 border-slate-200"
          }`}
          title={`Suricata IDS ${suricataRunning ? "running" : "stopped"} on ${suricataStatus?.interface || activeInterface || "interface"} — ${suricataStatus?.events_per_minute ?? 0} evt/min, ${suricataStatus?.alerts ?? 0} alerts total`}
        >
          <span className={`w-2 h-2 rounded-full ${suricataRunning ? "bg-cyan-500 animate-pulse" : "bg-slate-400"}`} />
          <span>Suricata: {suricataRunning ? "Running" : "Stopped"}</span>
          <span className="font-mono text-[0.7rem] bg-white/80 px-1.5 py-0.5 rounded border border-slate-200">
            {suricataStatus?.interface || activeInterface || "eth0"}
          </span>
          <span className="text-[0.7rem] font-medium opacity-80">
            {suricataStatus?.events_per_minute ?? 0} evt/min
          </span>
        </span>
        {liveCaptureRunning && (
          <span
            className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-teal-50 text-teal-800 border border-teal-200 shadow-sm"
            title={`Live Traffic Sniffer active on ${liveCaptureStatus?.interface || "interface"} — ${liveCaptureStatus?.total_packets ?? 0} pkts, ${liveCaptureStatus?.events_processed ?? 0} events`}
          >
            <span className="w-2 h-2 rounded-full bg-teal-500 animate-pulse" />
            <span>LIVE SNIFFER</span>
            {liveCaptureStatus?.interface && (
              <span className="font-mono text-[0.7rem] bg-teal-100 text-teal-800 px-1.5 py-0.5 rounded border border-teal-200">
                {liveCaptureStatus.interface}
              </span>
            )}
            <span className="text-teal-700 text-[0.7rem] font-medium">
              {liveCaptureStatus?.total_packets !== undefined ? `${liveCaptureStatus.total_packets} pkts` : "sniffing"}
            </span>
            {(liveCaptureStatus?.anomalies_detected ?? 0) > 0 && (
              <span className="text-[0.65rem] bg-red-100 text-red-700 font-bold px-1.5 py-0.5 rounded-full border border-red-200">
                {liveCaptureStatus?.anomalies_detected} anomalies
              </span>
            )}
          </span>
        )}
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Severity badge                                                              */
/* ────────────────────────────────────────────────────────────────────────── */

function SeverityBadge({ level }: { level: string | null | undefined }) {
  if (!level) return null;

  const config: Record<string, { bg: string; text: string; icon: string; label: string; ring?: string }> = {
    Critical: { bg: "bg-red-50 border-red-200", text: "text-red-700", icon: "⚠", label: "Critical", ring: "ring-red-200" },
    High:     { bg: "bg-orange-50 border-orange-200", text: "text-orange-700", icon: "⚠", label: "High" },
    Medium:   { bg: "bg-amber-50 border-amber-200", text: "text-amber-700", icon: "●", label: "Medium" },
    Low:      { bg: "bg-emerald-50 border-emerald-200", text: "text-emerald-700", icon: "✓", label: "Low" },
  };

  const c = config[level] || {
    bg: "bg-slate-100 border-slate-200",
    text: "text-slate-600",
    icon: "—",
    label: level,
  };

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold border ${c.bg} ${c.text}`}
      role="status"
      aria-label={`Severity: ${c.label}`}
    >
      <span aria-hidden="true">{c.icon}</span>
      {c.label}
    </span>
  );
}

function PredictionBadge({ prediction }: { prediction: string }) {
  const isAnomaly = prediction === "anomaly";
  const isHoneypot = prediction === "honeypot";
  const isSuricata = prediction === "suricata_alert";

  const config = isAnomaly
    ? "bg-red-50 text-red-700 border-red-200"
    : isHoneypot
    ? "bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200"
    : isSuricata
    ? "bg-cyan-50 text-cyan-700 border-cyan-200"
    : "bg-emerald-50 text-emerald-700 border-emerald-200";

  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.65rem] font-semibold uppercase tracking-wider border ${config}`}>
      {prediction === "suricata_alert" ? "suricata" : prediction}
    </span>
  );
}

function SourceBadge({ source }: { source?: string }) {
  if (!source) return null;
  const config: Record<string, { bg: string; text: string; label: string }> = {
    honeypot:       { bg: "bg-fuchsia-50 border-fuchsia-200", text: "text-fuchsia-700", label: "Honeypot" },
    suricata:       { bg: "bg-cyan-50 border-cyan-200",       text: "text-cyan-700",    label: "Suricata IDS" },
    replay:         { bg: "bg-blue-50 border-blue-200",       text: "text-blue-700",    label: "Replay" },
    live_capture:   { bg: "bg-teal-50 border-teal-200",       text: "text-teal-700",    label: "Live Capture" },
    dataset_upload: { bg: "bg-indigo-50 border-indigo-200",   text: "text-indigo-700",  label: "Dataset Upload" },
  };
  const c = config[source] || { bg: "bg-slate-50 border-slate-200", text: "text-slate-600", label: source };
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.6rem] font-semibold uppercase tracking-wider border ${c.bg} ${c.text}`}>
      <svg className="w-2 h-2" viewBox="0 0 8 8" fill="currentColor"><circle cx="4" cy="4" r="3" /></svg>
      {c.label}
    </span>
  );
}

function HoneypotProbePanel({ meta }: { meta?: HoneypotMeta | null }) {
  if (!meta) return null;
  return (
    <div className="mt-2 p-3 rounded-xl bg-fuchsia-50 dark:bg-fuchsia-950/30 border border-fuchsia-200 dark:border-fuchsia-900/50">
      <div className="flex items-center gap-2 mb-2">
        <svg className="w-3.5 h-3.5 text-fuchsia-600 dark:text-fuchsia-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <circle cx="12" cy="10" r="3" />
        </svg>
        <span className="text-xs font-semibold text-fuchsia-700 dark:text-fuchsia-300">Honeypot Probe</span>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Source</div>
          <code className="text-[0.7rem] font-mono text-fuchsia-700 dark:text-fuchsia-300 bg-fuchsia-100/60 dark:bg-fuchsia-900/40 px-1.5 py-0.5 rounded border border-fuchsia-200 dark:border-fuchsia-800">
            {meta.src_ip}:{meta.src_port}
          </code>
        </div>
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Target Port</div>
          <code className="text-[0.7rem] font-mono text-fuchsia-700 dark:text-fuchsia-300 bg-fuchsia-100/60 dark:bg-fuchsia-900/40 px-1.5 py-0.5 rounded border border-fuchsia-200 dark:border-fuchsia-800">
            :{meta.dst_port}
          </code>
        </div>
      </div>
      {meta.probe_text && (
        <div className="mt-2">
          <div className="text-[0.65rem] text-slate-500 dark:text-slate-400 mb-1">Probe Data ({meta.probe_bytes_len} bytes)</div>
          <pre className="text-[0.65rem] font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-[#111827] p-2 rounded border border-slate-200 dark:border-slate-700 overflow-x-auto max-h-16">{meta.probe_text}</pre>
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* ATT&CK technique badges                                                    */
/* ────────────────────────────────────────────────────────────────────────── */

function AttackBadges({ techniques }: { techniques?: AttackTechnique[] | null }) {
  if (!techniques || techniques.length === 0) return null;
  return (
    <>
      {techniques.map((t) => {
        const url = `https://attack.mitre.org/techniques/${t.id}/`;
        return (
          <a
            key={t.id}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            title={`MITRE ATT&CK: ${t.name}`}
            className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.65rem] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200 hover:bg-indigo-100 transition-colors duration-150 cursor-pointer no-underline"
          >
            <svg className="w-2.5 h-2.5 opacity-60" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L2 7l10 5 10-5-10-5z" />
              <path d="M2 17l10 5 10-5" />
              <path d="M2 12l10 5 10-5" />
            </svg>
            {t.id}
          </a>
        );
      })}
    </>
  );
}

function StatusLabel({ status }: { status: string | null | undefined }) {
  if (!status || status === "pending_review") return null;

  if (status === "approved") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
        Action executed
      </span>
    );
  }
  if (status === "rejected") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
        Action declined
      </span>
    );
  }
  if (status === "investigating") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-full border border-indigo-200 animate-pulse">
        <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
        Investigating…
      </span>
    );
  }
  if (status === "false_positive") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-400">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-300" />
        False Positive
      </span>
    );
  }
  return null;
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Signature match badges                                                     */
/* ────────────────────────────────────────────────────────────────────────── */

function SignatureBadges({ matches }: { matches?: SignatureMatch[] | null }) {
  if (!matches || matches.length === 0) return null;
  return (
    <>
      {matches.map((m) => {
        const severityColor =
          m.severity === "critical"
            ? "bg-red-50 text-red-700 border-red-200"
            : m.severity === "high"
            ? "bg-amber-50 text-amber-700 border-amber-200"
            : "bg-amber-50/70 text-amber-600 border-amber-200";
        return (
          <span
            key={m.rule}
            title={m.description}
            className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[0.6rem] font-medium border ${severityColor} cursor-help transition-colors`}
          >
            <svg className="w-2.5 h-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            {m.rule.replace(/_/g, " ")}
          </span>
        );
      })}
    </>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* IP Enrichment panel                                                         */
/* ────────────────────────────────────────────────────────────────────────── */

function countryCodeToFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return "🌐";
  const offset = 0x1f1e6;
  return (
    String.fromCodePoint(code.charCodeAt(0) - 65 + offset) +
    String.fromCodePoint(code.charCodeAt(1) - 65 + offset)
  );
}

function EnrichmentPanel({ enrichment }: { enrichment?: IPEnrichment | null }) {
  if (!enrichment) return null;

  const { ip, ip_type, reputation, geolocation } = enrichment;
  const hasGeo = geolocation && geolocation.source !== "unavailable" && geolocation.country;
  const hasRep = reputation && reputation.source !== "unavailable" && reputation.abuse_confidence_score !== null;

  if (!hasGeo && !hasRep) return null;

  const abuseScore = reputation?.abuse_confidence_score ?? 0;
  const abuseColor =
    abuseScore >= 75 ? "text-red-600" :
    abuseScore >= 40 ? "text-amber-600" :
    abuseScore >= 10 ? "text-amber-500" :
    "text-emerald-600";

  const countryCode = geolocation?.country_code || reputation?.country_code || null;
  const flag = countryCodeToFlag(countryCode);

  return (
    <div className="mt-2 p-3 rounded-xl bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900/50">
      <div className="flex items-center gap-2 mb-2">
        <svg className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M2 12h20" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <span className="text-xs font-semibold text-blue-700 dark:text-blue-300">IP Enrichment</span>
        <code className="text-[0.65rem] font-mono text-slate-600 dark:text-slate-300 bg-white dark:bg-[#111827] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
          {ip}
        </code>
        {ip_type === "simulated" && (
          <span className="text-[0.6rem] text-amber-600 dark:text-amber-400 italic">(simulated IP — NSL-KDD)</span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        {hasGeo && (
          <div className="space-y-1">
            <div className="flex items-center gap-1.5">
              <span className="text-base leading-none">{flag}</span>
              <span className="text-slate-700 dark:text-slate-200 font-medium">
                {geolocation.city && `${geolocation.city}, `}{geolocation.country}
              </span>
            </div>
            {geolocation.region && <div className="text-slate-500 dark:text-slate-400 pl-6">{geolocation.region}</div>}
            {geolocation.isp && <div className="text-slate-500 dark:text-slate-400 pl-6 truncate" title={geolocation.isp}>ISP: {geolocation.isp}</div>}
            {geolocation.lat !== null && geolocation.lon !== null && (
              <div className="text-slate-400 dark:text-slate-500 pl-6 font-mono text-[0.6rem]">
                {geolocation.lat.toFixed(2)}, {geolocation.lon.toFixed(2)}
              </div>
            )}
          </div>
        )}
        {hasRep && (
          <div className="space-y-1">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 dark:text-slate-400">Abuse Score:</span>
              <span className={`font-bold ${abuseColor}`}>{abuseScore}%</span>
            </div>
            <div className="text-slate-400 dark:text-slate-500">Reports: {reputation.total_reports ?? 0}</div>
            {reputation.isp && <div className="text-slate-400 dark:text-slate-500 truncate" title={reputation.isp}>ISP: {reputation.isp}</div>}
            {reputation.domain && <div className="text-slate-400 dark:text-slate-500 truncate" title={reputation.domain}>Domain: {reputation.domain}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

function SuricataAlertPanel({ meta, network }: { meta?: SuricataMeta | null; network?: NetworkMeta | null }) {
  if (!meta) return null;
  const sevColors: Record<string, string> = {
    Critical: "text-red-700 bg-red-50 border-red-200",
    High: "text-red-600 bg-red-50 border-red-200",
    Medium: "text-amber-700 bg-amber-50 border-amber-200",
    Low: "text-emerald-700 bg-emerald-50 border-emerald-200",
  };
  const sevClass = sevColors[meta.severity_label] ?? "text-slate-600 bg-slate-50 border-slate-200";
  return (
    <div className="mt-2 p-3 rounded-xl bg-cyan-50 dark:bg-cyan-950/30 border border-cyan-200 dark:border-cyan-900/50">
      <div className="flex items-center gap-2 mb-2">
        <svg className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span className="text-xs font-semibold text-cyan-700 dark:text-cyan-300">Suricata IDS Alert</span>
        <span className={`text-[0.65rem] px-1.5 py-0.5 rounded font-medium border ${sevClass}`}>
          {meta.severity_label}
        </span>
      </div>
      <div className="mb-1.5">
        <code className="text-[0.7rem] font-mono text-cyan-700 dark:text-cyan-300 bg-white dark:bg-[#111827] px-1.5 py-0.5 rounded border border-cyan-200 dark:border-cyan-800">
          SID:{meta.signature_id} — {meta.signature}
        </code>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Category</div>
          <span className="text-cyan-700 dark:text-cyan-300 font-medium">{meta.category}</span>
        </div>
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Tactic</div>
          <span className="text-cyan-700 dark:text-cyan-300 font-medium">{meta.tactic}</span>
        </div>
        {network && (
          <>
            <div className="space-y-1">
              <div className="text-slate-500 dark:text-slate-400">Source</div>
              <code className="text-[0.7rem] font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-[#111827] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                {network.src_ip}:{network.src_port}
              </code>
            </div>
            <div className="space-y-1">
              <div className="text-slate-500 dark:text-slate-400">Destination</div>
              <code className="text-[0.7rem] font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-[#111827] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                {network.dst_ip}:{network.dst_port}
              </code>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function LiveTrafficMetaPanel({ network, raw }: { network?: NetworkMeta | null; raw?: Record<string, string | number> }) {
  if (!network && !raw) return null;
  return (
    <div className="mt-2 p-3 rounded-xl bg-teal-50 dark:bg-teal-950/30 border border-teal-200 dark:border-teal-900/50">
      <div className="flex items-center gap-2 mb-2">
        <svg className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M5 12.55a11 11 0 0 1 14.08 0" />
          <path d="M1.42 9a16 16 0 0 1 21.16 0" />
          <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
          <circle cx="12" cy="20" r="1" />
        </svg>
        <span className="text-xs font-semibold text-teal-700 dark:text-teal-300">Live Traffic Capture (WiFi / Ethernet)</span>
        {network?.packets !== undefined && (
          <span className="text-[0.65rem] px-1.5 py-0.5 rounded font-medium bg-teal-100 dark:bg-teal-900/60 text-teal-800 dark:text-teal-300 border border-teal-200 dark:border-teal-800">
            {network.packets} pkt{network.packets === 1 ? "" : "s"}
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Source Host</div>
          <code className="text-[0.7rem] font-mono text-slate-800 dark:text-slate-200 bg-white dark:bg-[#111827] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
            {network?.src_ip || raw?.src_ip || "unknown"}:{network?.src_port || raw?.src_port || 0}
          </code>
        </div>
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Destination Host</div>
          <code className="text-[0.7rem] font-mono text-slate-800 dark:text-slate-200 bg-white dark:bg-[#111827] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
            {network?.dst_ip || raw?.dst_ip || "unknown"}:{network?.dst_port || raw?.dst_port || 0}
          </code>
        </div>
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Traffic Volume</div>
          <span className="text-[0.7rem] font-mono text-teal-800 dark:text-teal-300 font-medium">
            ▲ {Number(raw?.src_bytes || 0).toLocaleString()} B &nbsp; ▼ {Number(raw?.dst_bytes || 0).toLocaleString()} B
          </span>
        </div>
        <div className="space-y-1">
          <div className="text-slate-500 dark:text-slate-400">Flags / State</div>
          <span className="inline-flex items-center gap-1 font-mono text-[0.7rem] bg-white dark:bg-[#111827] text-slate-700 dark:text-slate-300 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
            {String(raw?.flag || "SF")}
            <span className="text-[0.6rem] text-slate-500 dark:text-slate-400">
              {raw?.flag === "S0" ? "(SYN flood/scan)" : raw?.flag === "REJ" ? "(Rejected)" : raw?.flag === "SF" ? "(Normal)" : ""}
            </span>
          </span>
        </div>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Event card                                                                  */
/* ────────────────────────────────────────────────────────────────────────── */

function TruncatedId({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);
  const displayId = id.length > 14 ? `${id.slice(0, 8)}...${id.slice(-4)}` : id;
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handleCopy}
      title={`Copy full ID: ${id}`}
      className="inline-flex items-center gap-1 text-[0.6rem] font-mono text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 px-1.5 py-0.5 rounded transition-colors cursor-pointer"
    >
      <span>{displayId}</span>
      {copied ? <Check className="w-2.5 h-2.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-2.5 h-2.5 opacity-60" />}
    </button>
  );
}

function EventCard({
  event,
  onApprove,
  onReject,
  onInvestigate,
  onFalsePositive,
  showActions = true,
}: {
  event: SentinelEvent;
  onApprove?: (id: string) => Promise<boolean>;
  onReject?: (id: string) => Promise<boolean>;
  onInvestigate?: (id: string) => Promise<boolean>;
  onFalsePositive?: (id: string) => Promise<boolean>;
  showActions?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [actionInFlight, setActionInFlight] = useState(false);
  const isAnomaly = event.prediction === "anomaly";
  const isHoneypot = event.prediction === "honeypot";
  const isSuricata = event.prediction === "suricata_alert";
  const hasSigMatch = (event.signature_matches?.length ?? 0) > 0;
  const isFlagged = isAnomaly || isHoneypot || isSuricata || hasSigMatch;
  const raw = event.raw_event;
  const isPending = event.status === "pending_review";
  const isApproved = event.status === "approved";
  const isRejected = event.status === "rejected";
  const isInvestigating = event.status === "investigating";
  const isFalsePositiveStatus = event.status === "false_positive";

  const riskScore = event.risk_score ?? undefined;
  const riskClass = event.risk_classification ?? undefined;

  const riskColors: Record<string, string> = {
    CRITICAL: "bg-red-50 text-red-700 border-red-200",
    HIGH:     "bg-orange-50 text-orange-700 border-orange-200",
    MEDIUM:   "bg-amber-50 text-amber-700 border-amber-200",
    LOW:      "bg-emerald-50 text-emerald-700 border-emerald-200",
  };
  const riskBarColors: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH:     "bg-orange-500",
    MEDIUM:   "bg-amber-500",
    LOW:      "bg-emerald-500",
  };

  const handleAction = (fn?: (id: string) => Promise<boolean>) => async () => {
    if (!event.event_id || actionInFlight || !fn) return;
    setActionInFlight(true);
    await fn(event.event_id);
    setActionInFlight(false);
  };

  // Left border stripe class
  const stripeClass = isApproved
    ? "event-card-approved"
    : isRejected
    ? "event-card-rejected"
    : isHoneypot
    ? "event-card-honeypot"
    : isSuricata
    ? "event-card-suricata"
    : isAnomaly
    ? "event-card-anomaly"
    : hasSigMatch
    ? "event-card-anomaly"
    : "event-card-normal";

  const cardBg = isApproved
    ? "bg-emerald-50/40 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800"
    : isRejected
    ? "bg-slate-50/60 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 opacity-70"
    : isInvestigating
    ? "bg-indigo-50/40 dark:bg-indigo-950/20 border-indigo-200 dark:border-indigo-800"
    : isFalsePositiveStatus
    ? "bg-slate-50/40 dark:bg-slate-900/40 border-slate-200 dark:border-slate-800 opacity-60"
    : isHoneypot
    ? "bg-fuchsia-50/20 dark:bg-fuchsia-950/20 border-fuchsia-200 dark:border-fuchsia-800 hover:border-fuchsia-300 dark:hover:border-fuchsia-700"
    : isSuricata
    ? "bg-cyan-50/20 dark:bg-cyan-950/20 border-cyan-200 dark:border-cyan-800 hover:border-cyan-300 dark:hover:border-cyan-700"
    : isAnomaly
    ? "bg-red-50/20 dark:bg-red-950/20 border-red-200 dark:border-red-800 hover:border-red-300 dark:hover:border-red-700"
    : hasSigMatch
    ? "bg-amber-50/20 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800 hover:border-amber-300 dark:hover:border-amber-700"
    : "bg-white dark:bg-[#111827] border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600";

  return (
    <div className={`mb-3 rounded-xl border transition-all duration-200 overflow-hidden shadow-sm hover:shadow-md ${cardBg} ${stripeClass}`}>
      <div className="p-4">
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400">#{event.event_index}</span>
            {(() => {
              const proto = raw?.protocol_type ? String(raw.protocol_type).toUpperCase() : event.network_meta?.proto ? String(event.network_meta.proto).toUpperCase() : raw?.proto ? String(raw.proto).toUpperCase() : "TCP";
              const srv = raw?.service && String(raw.service) !== "undefined" ? String(raw.service) : event.network_meta?.dst_port ? `port ${event.network_meta.dst_port}` : raw?.dst_port ? `port ${raw.dst_port}` : "network";
              const flg = raw?.flag && String(raw.flag) !== "undefined" ? String(raw.flag) : raw?.flags ? String(raw.flags) : (event.source === "live_capture" ? "LIVE" : "—");
              return (
                <span className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1">
                  <span>{proto}</span>
                  <span className="text-slate-400 mx-0.5">/</span>
                  <span className="text-slate-700 dark:text-slate-300">{srv}</span>
                  <span className="text-slate-400 mx-0.5">/</span>
                  <span className="text-slate-400 text-xs font-normal">{flg}</span>
                </span>
              );
            })()}
            {event.event_id && <TruncatedId id={event.event_id} />}
          </div>
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge level={event.severity} />
              <SourceBadge source={event.source} />
              <AttackBadges techniques={event.attack_techniques} />
              <SignatureBadges matches={event.signature_matches} />
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <PredictionBadge prediction={event.prediction} />
              <span className="text-[0.65rem] font-medium text-slate-400 bg-slate-100 px-1.5 py-0.5 rounded-full">
                {(event.confidence * 100).toFixed(0)}%
              </span>
              {event.ml_confidence_note && (
                <span className="text-[0.6rem] font-medium text-amber-500 bg-amber-50 px-1.5 py-0.5 rounded-full">
                  ⚠ {event.ml_confidence_note}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Plain-English Explanation */}
        {(event.triage || event.severity_justification || event.recommended_action) && (
          <div className="mt-3 p-3 rounded-xl bg-indigo-50/50 dark:bg-indigo-950/40 border border-indigo-100 dark:border-indigo-900/50 text-xs sm:text-sm leading-relaxed space-y-1.5">
            <span className="text-[0.6rem] font-bold uppercase tracking-wider text-indigo-700 dark:text-indigo-300 bg-indigo-100 dark:bg-indigo-900/60 px-1.5 py-0.5 rounded inline-block mb-1">
              AI Triage
            </span>
            {event.triage && (
              <div className="flex items-start gap-2">
                <Info className="w-3.5 h-3.5 text-indigo-500 shrink-0 mt-0.5" />
                <p className="text-slate-800 dark:text-slate-200"><span className="font-semibold text-slate-700 dark:text-slate-300">What happened: </span>{event.triage}</p>
              </div>
            )}
            {event.severity_justification && (
              <div className="flex items-start gap-2">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
                <p className="text-slate-600 dark:text-slate-300"><span className="font-semibold text-slate-700 dark:text-slate-300">Why it matters: </span>{event.severity_justification}</p>
              </div>
            )}
            {event.recommended_action && (
              <div className="flex items-start gap-2">
                <Zap className="w-3.5 h-3.5 text-cyan-500 shrink-0 mt-0.5" />
                <p className="text-slate-600 dark:text-slate-300"><span className="font-semibold text-slate-700 dark:text-slate-300">Recommended action: </span>{event.recommended_action}</p>
              </div>
            )}
          </div>
        )}

        {/* Risk chip */}
        {riskScore !== undefined && riskClass && (() => {
          const llmTier = ({"Critical": 3, "High": 2, "Medium": 1, "Low": 0} as Record<string, number>)[event.severity as string] ?? -1;
          const formulaTier = ({"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0})[riskClass] ?? -1;
          const agree = llmTier === formulaTier;
          const diff = Math.abs(llmTier - formulaTier);
          const agreeTip = agree ? "LLM and formula agree" : `${diff}-tier difference: ${agree ? "✓ agree" : diff > 1 ? "⚠ disagree" : "~ close"}`;
          return (
            <div className="mt-2 flex items-center gap-2" title={agreeTip}>
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold border ${riskColors[riskClass] ?? "bg-slate-100 text-slate-500 border-slate-200"}`}>
                <ShieldAlert className="w-3.5 h-3.5" />
                Risk {riskScore}/100 – {riskClass}
              </span>
              <div className="w-20 h-1.5 rounded-full bg-slate-200 overflow-hidden">
                <div
                  className={`h-full rounded-full progress-bar-fill ${riskBarColors[riskClass] ?? "bg-slate-400"}`}
                  style={{ width: `${riskScore}%` }}
                />
              </div>
            </div>
          );
        })()}

        <div className="flex items-center justify-between mt-2">
          <div className="flex items-center gap-2">
            {event.agent_latency_seconds !== undefined && event.agent_latency_seconds > 0 && (
              <span className="text-[0.65rem] text-slate-400">⏱ {event.agent_latency_seconds}s</span>
            )}
            <StatusLabel status={event.status} />
          </div>

          {/* Action buttons */}
          {showActions && event.event_id && (isPending || isInvestigating) && (
            <div className="flex items-center gap-1.5 flex-wrap justify-end">
              {isPending && (
                <Button size="xs" variant="investigate" onClick={handleAction(onInvestigate)} disabled={actionInFlight} title="Mark as Investigating">
                  <Search className="w-3.5 h-3.5 mr-1" /> Investigate
                </Button>
              )}
              <Button size="xs" variant="success" onClick={handleAction(onApprove)} disabled={actionInFlight}>
                {actionInFlight ? "…" : <><Check className="w-3.5 h-3.5 mr-1" /> Approve</>}
              </Button>
              <Button size="xs" variant="secondary" onClick={handleAction(onFalsePositive)} disabled={actionInFlight} title="Mark as False Positive">
                <Flag className="w-3.5 h-3.5 mr-1" /> FP
              </Button>
              <Button size="xs" variant="slate" onClick={handleAction(onReject)} disabled={actionInFlight}>
                {actionInFlight ? "…" : <><X className="w-3.5 h-3.5 mr-1" /> Reject</>}
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Technical details — available for ALL events */}
      <div className="px-4 pb-3 pt-0 border-t border-slate-100 dark:border-slate-800 mt-2">
        <Collapsible open={expanded} onOpenChange={setExpanded}>
          <CollapsibleTrigger className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 transition-colors cursor-pointer flex items-center gap-1.5 mt-2 font-medium">
            <svg className={`w-3 h-3 transition-transform ${expanded ? "rotate-90" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
            <span>{expanded ? "Hide technical details" : "Show technical details"}</span>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <div className="mt-2 p-3 rounded-xl bg-slate-50 dark:bg-[#1E293B] border border-slate-200 dark:border-slate-700 text-sm leading-relaxed space-y-2">
              <EnrichmentPanel enrichment={event.ip_enrichment} />
              <HoneypotProbePanel meta={event.honeypot_meta} />
              <SuricataAlertPanel meta={event.suricata_meta} network={event.network_meta} />
              {event.source === "live_capture" && (
                <LiveTrafficMetaPanel network={event.network_meta} raw={event.raw_event} />
              )}
              {/* Raw event features for all events */}
              <div className="mt-2">
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <svg className="w-3.5 h-3.5 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                    <path d="M14 2v6h6" />
                    <path d="M16 13H8" />
                    <path d="M16 17H8" />
                    <path d="M10 9H8" />
                  </svg>
                  <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">Raw Event Features</span>
                  {event.model_used && (
                    <span className="text-[0.6rem] px-1.5 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/50 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800 font-medium">
                      Model: {event.model_used}
                    </span>
                  )}
                  {event.dataset_schema && (
                    <span className="text-[0.6rem] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-600 font-medium">
                      Schema: {event.dataset_schema}
                    </span>
                  )}
                  {event.actual && (
                    <span className="text-[0.6rem] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-600 font-mono">
                      Actual: {event.actual}
                    </span>
                  )}
                </div>
                {raw && Object.keys(raw).length > 0 ? (
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5">
                    {Object.entries(raw).slice(0, 24).map(([key, val]) => (
                      <div key={key} className="flex items-baseline gap-1 text-[0.65rem] truncate">
                        <span className="text-slate-400 font-medium truncate">{key}:</span>
                        <span className="text-slate-700 dark:text-slate-200 font-mono truncate">{String(val)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-400 italic">No raw attributes recorded.</div>
                )}
                {raw && Object.keys(raw).length > 24 && (
                  <div className="text-[0.6rem] text-slate-400 mt-1 italic">
                    +{Object.keys(raw).length - 24} more features
                  </div>
                )}
              </div>
            </div>
          </CollapsibleContent>
        </Collapsible>
      </div>
    </div>
  );
}



/* ────────────────────────────────────────────────────────────────────────── */
/* MongoDB Stats Overview (redesigned with trending tiles)                    */
/* ────────────────────────────────────────────────────────────────────────── */

interface StatsData {
  total_events: number;
  pending_review: number;
  investigating: number;
  false_positives: number;
  critical_severity: number;
  risk_critical: number;
  honeypot_sourced: number;
  suricata_sourced?: number;
  by_status: Record<string, number>;
  by_llm_severity: Record<string, number>;
  by_risk_class: Record<string, number>;
  by_source: Record<string, number>;
}

function StatsOverview({
  onApprove,
  onReject,
  onInvestigate,
  onFalsePositive,
}: {
  onApprove?: (id: string) => Promise<boolean>;
  onReject?: (id: string) => Promise<boolean>;
  onInvestigate?: (id: string) => Promise<boolean>;
  onFalsePositive?: (id: string) => Promise<boolean>;
}) {
  const [stats, setStats] = useState<StatsData | null>(null);
  const [activeModal, setActiveModal] = useState<{ title: string; filter: Record<string, string> } | null>(null);
  const [modalEvents, setModalEvents] = useState<SentinelEvent[]>([]);
  const [modalLoading, setModalLoading] = useState(false);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/stats/overview`, { headers: getAuthHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      if (data && typeof data.total_events === "number") {
        setStats(data);
      }
    } catch { /* silent fail */ }
  }, []);

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 15000);
    return () => clearInterval(id);
  }, [fetchStats]);

  const openFilterModal = async (title: string, filter: Record<string, string>) => {
    setActiveModal({ title, filter });
    setModalLoading(true);
    try {
      const query = new URLSearchParams(filter).toString();
      const res = await fetch(`${API_BASE}/events/filter?${query}`, { headers: getAuthHeaders() });
      if (!res.ok) {
        setModalEvents([]);
        return;
      }
      const data = await res.json();
      setModalEvents(data.events || []);
    } catch (err) {
      console.error("Filter fetch error:", err);
      setModalEvents([]);
    } finally {
      setModalLoading(false);
    }
  };

  const closeModal = () => {
    setActiveModal(null);
    setModalEvents([]);
  };

  if (!stats || !stats.total_events || stats.total_events <= 0) return null;

  const tiles: { label: string; value: number; accent: string; color: string; icon: string; filter: Record<string, string>; subtitle?: string }[] = [
    { label: "Total",           value: stats.total_events,     accent: "accent-indigo",  color: "#4f46e5", icon: "📁", filter: { status: "all" } },
    { label: "Pending",         value: stats.pending_review ?? 0,   accent: "accent-amber",   color: "#d97706", icon: "⏳", filter: { status: "pending_review" }, subtitle: "needs action" },
    { label: "Investigating",   value: stats.investigating ?? 0,    accent: "accent-cyan",    color: "#0891b2", icon: "🔍", filter: { status: "investigating" } },

    { label: "Critical",        value: stats.critical_severity ?? 0,accent: "accent-red",     color: "#dc2626", icon: "🚨", filter: { llm_severity: "Critical" } },
    { label: "Honeypot",        value: stats.honeypot_sourced ?? 0, accent: "accent-fuchsia", color: "#a21caf", icon: "🍯", filter: { source: "honeypot" } },
    { label: "Suricata",        value: stats.suricata_sourced ?? stats.by_source?.["suricata"] ?? 0, accent: "accent-teal", color: "#0d9488", icon: "🛡️", filter: { source: "suricata" } },
    { label: "Live",            value: stats.by_source?.["live_capture"] ?? 0, accent: "accent-cyan", color: "#0891b2", icon: "📡", filter: { source: "live_capture" } },
    { label: "False Positives", value: stats.false_positives ?? 0,  accent: "accent-violet",  color: "#7c3aed", icon: "❌", filter: { status: "false_positive" } },
  ];

  return (
    <div className="mb-5 relative">
      {/* Section header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-5 rounded-full bg-gradient-to-b from-indigo-500 to-indigo-300" />
          <span className="text-sm font-bold text-slate-700">MongoDB Live Stats</span>
          <span className="relative flex h-2 w-2 ml-1">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
        </div>
        <span className="text-[0.6rem] text-slate-400 italic">💡 Click any tile to inspect matching events</span>
      </div>

      {/* Trending tiles grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2">
        {tiles.map((t) => (
          <button
            key={t.label}
            onClick={() => openFilterModal(t.label, t.filter)}
            className={`stat-card ${t.accent} p-3 text-center cursor-pointer hover:shadow-md hover:-translate-y-0.5 active:translate-y-0 transition-all duration-150`}
          >
            <div className="text-lg mb-0.5">{t.icon}</div>
            <div className="text-xl font-black text-slate-900 tabular-nums count-animate">{t.value}</div>
            <div className="text-[0.58rem] font-semibold text-slate-500 uppercase tracking-wider mt-0.5 leading-tight">{t.label}</div>
          </button>
        ))}
      </div>

      {/* Severity distribution charts */}
      {stats.by_llm_severity && Object.keys(stats.by_llm_severity).length > 0 && (
        <div className="mt-3 grid grid-cols-2 gap-3">
          {/* LLM distribution */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#111827] p-4 shadow-sm">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-1 h-4 rounded-full bg-indigo-400" />
              <span className="text-[0.65rem] font-bold uppercase tracking-widest text-slate-500">LLM Severity Distribution</span>
            </div>
            <div className="space-y-2">
              {["Critical", "High", "Medium", "Low"].map((sev) => {
                const count = stats.by_llm_severity?.[sev] ?? 0;
                const pct = stats.total_events > 0 ? Math.round((count / stats.total_events) * 100) : 0;
                const col = { Critical: "bg-red-500", High: "bg-orange-400", Medium: "bg-amber-400", Low: "bg-emerald-400" }[sev] ?? "bg-slate-400";
                const textCol = { Critical: "text-red-600", High: "text-orange-600", Medium: "text-amber-600", Low: "text-emerald-600" }[sev] ?? "text-slate-500";
                return (
                  <button
                    key={sev}
                    onClick={() => openFilterModal(`LLM Severity: ${sev}`, { llm_severity: sev })}
                    className="w-full flex items-center gap-2 group p-1 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 text-left transition-colors cursor-pointer"
                  >
                    <span className={`text-[0.65rem] font-semibold w-14 ${textCol} group-hover:text-slate-900 dark:group-hover:text-white`}>{sev}</span>
                    <div className="flex-1 h-2 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
                      <div className={`h-full rounded-full ${col} progress-bar-fill group-hover:brightness-110 transition-all`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-[0.6rem] font-bold text-slate-400 group-hover:text-indigo-600 w-7 text-right font-mono">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
          {/* Formula risk distribution */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#111827] p-4 shadow-sm">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-1 h-4 rounded-full bg-amber-400" />
              <span className="text-[0.65rem] font-bold uppercase tracking-widest text-slate-500">Formula Risk Distribution</span>
            </div>
            <div className="space-y-2">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((cls) => {
                const count = stats.by_risk_class?.[cls] ?? 0;
                const pct = stats.total_events > 0 ? Math.round((count / stats.total_events) * 100) : 0;
                const col = { CRITICAL: "bg-red-500", HIGH: "bg-orange-400", MEDIUM: "bg-amber-400", LOW: "bg-emerald-400" }[cls] ?? "bg-slate-400";
                const textCol = { CRITICAL: "text-red-600", HIGH: "text-orange-600", MEDIUM: "text-amber-600", LOW: "text-emerald-600" }[cls] ?? "text-slate-500";
                return (
                  <button
                    key={cls}
                    onClick={() => openFilterModal(`Formula Risk: ${cls}`, { risk_classification: cls })}
                    className="w-full flex items-center gap-2 group p-1 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 text-left transition-colors cursor-pointer"
                  >
                    <span className={`text-[0.65rem] font-semibold w-16 ${textCol} group-hover:text-slate-900 dark:group-hover:text-white`}>{cls}</span>
                    <div className="flex-1 h-2 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
                      <div className={`h-full rounded-full ${col} progress-bar-fill group-hover:brightness-110 transition-all`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-[0.6rem] font-bold text-slate-400 group-hover:text-indigo-600 w-7 text-right font-mono">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Filter Modal Overlay ── */}
      <AnimatePresence>
        {activeModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ type: "spring", stiffness: 350, damping: 28 }}
              className="relative w-full max-w-4xl max-h-[85vh] flex flex-col rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#111827] shadow-2xl overflow-hidden"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-gradient-to-r from-indigo-50 dark:from-indigo-950/30 to-slate-50 dark:to-[#111827]">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-indigo-100 border border-indigo-200 flex items-center justify-center text-indigo-600 text-lg">
                    🔍
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-900 tracking-tight">{activeModal.title}</h3>
                    <p className="text-xs text-slate-500">
                      Showing events matched from MongoDB ({modalEvents.length} results)
                    </p>
                  </div>
                </div>
                <Button size="iconSm" variant="ghost" onClick={closeModal} className="rounded-full hover:bg-slate-100 text-slate-500">
                  ✕
                </Button>
              </div>

              {/* Modal Body */}
              <div className="p-6 overflow-y-auto space-y-3 flex-1 custom-scrollbar bg-slate-50 dark:bg-[#0B1120]">
                {modalLoading ? (
                  <div className="py-16 text-center">
                    <div className="inline-flex items-center gap-3 text-slate-400">
                      <svg className="w-5 h-5 animate-spin text-indigo-500" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      <span className="text-sm">Loading events from MongoDB…</span>
                    </div>
                  </div>
                ) : modalEvents.length === 0 ? (
                  <div className="py-16 text-center">
                    <div className="text-4xl mb-3">🗄️</div>
                    <p className="text-slate-500 text-sm">No stored events match this filter.</p>
                  </div>
                ) : (
                  modalEvents.map((ev, i) => (
                    <EventCard
                      key={`modal-${i}-${ev.event_id || ev.event_index}`}
                      event={ev}
                      onApprove={async (id) => {
                        const ok = onApprove ? await onApprove(id) : false;
                        if (ok) setModalEvents(prev => prev.map(e => e.event_id === id ? { ...e, status: "approved" } : e));
                        fetchStats();
                        return ok;
                      }}
                      onReject={async (id) => {
                        const ok = onReject ? await onReject(id) : false;
                        if (ok) setModalEvents(prev => prev.map(e => e.event_id === id ? { ...e, status: "rejected" } : e));
                        fetchStats();
                        return ok;
                      }}
                      onInvestigate={async (id) => {
                        const ok = onInvestigate ? await onInvestigate(id) : false;
                        if (ok) setModalEvents(prev => prev.map(e => e.event_id === id ? { ...e, status: "investigating" } : e));
                        fetchStats();
                        return ok;
                      }}
                      onFalsePositive={async (id) => {
                        const ok = onFalsePositive ? await onFalsePositive(id) : false;
                        if (ok) setModalEvents(prev => prev.map(e => e.event_id === id ? { ...e, status: "false_positive" } : e));
                        fetchStats();
                        return ok;
                      }}
                    />
                  ))
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* History view                                                               */
/* ────────────────────────────────────────────────────────────────────────── */

interface HistoryEvent {
  event_id: string;
  event_index: number;
  raw_event: Record<string, string | number>;
  prediction: string;
  confidence: number;
  triage: string;
  severity: string;
  severity_justification: string;
  recommended_action: string;
  attack_techniques: AttackTechnique[];
  signature_matches: SignatureMatch[];
  ip_enrichment: IPEnrichment | null;
  ml_flagged: boolean;
  sig_flagged: boolean;
  status: string;
  resolved_at: string;
  resolved_by: string;
  agent_latency_seconds: number;
}

function HistoryView({ onExportCsv }: { onExportCsv?: (source: "suricata" | "honeypot") => void }) {
  const [history, setHistory] = useState<HistoryEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/events/history?limit=50`, { headers: getAuthHeaders() });
      if (!res.ok) {
        setHistory([]);
        return;
      }
      const data = await res.json();
      setHistory(data.events || []);
    } catch (err) {
      console.error("History fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  return (
    <div>
      <div className="flex items-center justify-between mb-5 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-5 rounded-full bg-gradient-to-b from-violet-500 to-violet-300" />
          <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">
            {history.length} resolved events
            <span className="text-slate-400 font-normal ml-1">(persisted in MongoDB)</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          {onExportCsv && (
            <>
              <Button id="history-export-suricata-csv-btn" size="sm" variant="outline" onClick={() => onExportCsv("suricata")}
                className="text-xs gap-1.5" title="Download Suricata alerts formatted for Excel">
                <span>📊</span> Download Suricata CSV
              </Button>
              <Button id="history-export-honeypot-csv-btn" size="sm" variant="outline" onClick={() => onExportCsv("honeypot")}
                className="text-xs gap-1.5" title="Download Honeypot events formatted for Excel">
                <span>🍯</span> Download Honeypot CSV
              </Button>
            </>
          )}
          <Button size="sm" variant="outline" onClick={fetchHistory} className="text-xs">Refresh</Button>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-16">
          <svg className="w-6 h-6 animate-spin text-indigo-500 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <p className="text-slate-400 text-sm">Loading history...</p>
        </div>
      ) : history.length === 0 ? (
        <div className="text-center py-16 rounded-2xl border border-dashed border-slate-300 bg-slate-50">
          <div className="text-4xl mb-3">📋</div>
          <p className="text-slate-500 text-sm max-w-xs mx-auto">
            No resolved events yet. Approve or reject some events from the Live Feed first.
          </p>
        </div>
      ) : (
        <div>
          {history.map((ev) => (
            <EventCard key={ev.event_id} event={ev as unknown as SentinelEvent} showActions={false} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Main Dashboard Page                                                        */
/* ────────────────────────────────────────────────────────────────────────── */

export default function Home() {
  const {
    events,
    connected,
    replaying,
    honeypotRunning,
    suricataRunning,
    suricataStatus,
    interfaces,
    defaultInterface,
    authError,
    wsStatus,
    researchMode,
    reconnect,
    startReplay,
    stopReplay,
    startHoneypot,
    stopHoneypot,
    startSuricata,
    stopSuricata,
    liveCaptureRunning,
    liveCaptureStatus,
    liveInterfaces,
    defaultLiveInterface,
    liveCaptureLoading,
    startLiveCapture,
    stopLiveCapture,
    fetchLiveInterfaces,
    checkLiveCaptureStatus,
    clearEvents,
    approveEvent,
    rejectEvent,
    investigateEvent,
    markFalsePositive,
  } = useSentinelWS();

  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [selectedLiveInterface, setSelectedLiveInterface] = useState<string>("");
  const [livePacketLimit, setLivePacketLimit] = useState<number>(0);
  const [liveTimeLimit, setLiveTimeLimit] = useState<number>(0);
  const [showLiveSnifferPanel, setShowLiveSnifferPanel] = useState<boolean>(true);
  const [mounted, setMounted] = useState(false);
  const [currentUser, setCurrentUser] = useState<string>("");

  useEffect(() => {
    setMounted(true);
    const token = localStorage.getItem("sentinel_token");
    const user = localStorage.getItem("sentinel_user");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    if (user) {
      setCurrentUser(user);
    }
  }, []);

  useEffect(() => {
    if (!selectedInterface && defaultInterface) setSelectedInterface(defaultInterface);
  }, [defaultInterface, selectedInterface]);

  useEffect(() => {
    if (!selectedLiveInterface && defaultLiveInterface) setSelectedLiveInterface(defaultLiveInterface);
  }, [defaultLiveInterface, selectedLiveInterface]);

  const activeLiveIfaceObj = useMemo(() => {
    return (
      liveInterfaces.find((i) => i.name === (selectedLiveInterface || defaultLiveInterface)) ||
      liveInterfaces.find((i) => i.is_up && i.ip) ||
      liveInterfaces[0]
    );
  }, [liveInterfaces, selectedLiveInterface, defaultLiveInterface]);

  const [activeTab, setActiveTab] = useState<"live" | "history" | "upload" | "rnd">("live");
  const [downloadingCsv, setDownloadingCsv] = useState<string | null>(null);
  const [csvNotice, setCsvNotice] = useState<{ msg: string; isError: boolean } | null>(null);

  const handleDownloadCsv = async (source: "suricata" | "honeypot") => {
    setDownloadingCsv(source);
    setCsvNotice(null);
    try {
      const res = await fetch(`${API_BASE}/logs/export/csv/${source}`, { headers: getAuthHeaders() });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Failed to export ${source} CSV (${res.status})`);
      }
      const disposition = res.headers.get("Content-Disposition");
      let filename = `${source}_logs.csv`;
      if (disposition) {
        const match = disposition.match(/filename="?([^";]+)"?/i);
        if (match && match[1]) filename = match[1];
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
      setCsvNotice({ msg: `Downloaded ${filename} successfully (ready for Excel).`, isError: false });
      setTimeout(() => setCsvNotice(null), 5000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "CSV download failed";
      setCsvNotice({ msg, isError: true });
      setTimeout(() => setCsvNotice(null), 6000);
    } finally {
      setDownloadingCsv(null);
    }
  };

  const tabs: { key: "live" | "history" | "upload" | "rnd"; label: string; icon: string }[] = [
    { key: "live",    label: "Live Feed",          icon: "🟢" },
    { key: "history", label: "History",            icon: "📋" },
    { key: "upload",  label: "Dataset Upload",     icon: "📁" },
    { key: "rnd",     label: "Comparative R&D",   icon: "🔬" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#F4F7FE] via-[#F0F9FF] to-[#F0FDF4] dark:from-[#0B1120] dark:via-[#0F172A] dark:to-[#0B1120] text-[#0B1B3A] dark:text-slate-200">

      {/* Auth error banner */}
      {authError && (
        <div className="fixed top-0 inset-x-0 z-50 flex items-center justify-between px-6 py-3 bg-red-600 text-white text-sm font-medium shadow-lg">
          <span>🔒 {authError}</span>
          <Link href="/login" className="underline font-bold hover:text-red-100">Sign In</Link>
        </div>
      )}

      {/* ── Top Nav ── */}
      <nav className="sticky top-0 z-40 bg-white dark:bg-[#111827] border-b border-slate-200 dark:border-slate-700 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            {/* Logo */}
            <SentinelLogo href="/" size="md" showBadge badgeText="SOC" />

            {/* Right nav */}
            <div className="flex items-center gap-3">
              <ThemeToggle />
              <span className="text-xs text-slate-500 dark:text-slate-400 hidden sm:block" id="dashboard-username">
                {mounted && currentUser ? `👤 ${currentUser}` : ""}
              </span>
              <Button
                id="dashboard-signout"
                size="xs"
                variant="outline"
                onClick={() => {
                  localStorage.removeItem("sentinel_token");
                  localStorage.removeItem("sentinel_user");
                  window.location.href = "/login";
                }}
              >
                Sign Out
              </Button>
            </div>
          </div>
        </div>
      </nav>

      {/* ── Main Content ── */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">

        {/* Page header with gradient */}
        <div className="mb-6 p-5 rounded-2xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-blue-500 text-white shadow-lg shadow-indigo-500/20">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <h1 className="text-2xl font-black tracking-tight">SentinelAI Dashboard</h1>
              <p className="text-indigo-200 text-sm mt-0.5">
                Agentic AI Alert Triage &amp; Response Assistant
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/20 backdrop-blur text-xs font-semibold`}>
                <span className={`w-2 h-2 rounded-full ${connected ? "bg-emerald-400" : "bg-red-400 animate-pulse"}`} />
                <span className="text-white">{connected ? "WebSocket Live" : "Disconnected"}</span>
              </div>
              <div className="px-3 py-1.5 rounded-full bg-white/20 backdrop-blur text-xs font-semibold text-white">
                {events.length} events
              </div>
            </div>
          </div>
        </div>

        {/* KPI Skeleton Row */}
        {!mounted ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="stat-card accent-indigo p-4">
                <div className="skeleton h-10 w-10 rounded-xl mb-3" />
                <div className="skeleton h-7 w-20 mb-1" />
                <div className="skeleton h-3 w-16" />
              </div>
            ))}
          </div>
        ) : null}

        {/* Capture Status Bar */}
        <CaptureStatusBar
          connected={connected}
          wsStatus={wsStatus}
          replaying={replaying}
          honeypotRunning={honeypotRunning}
          suricataRunning={suricataRunning}
          suricataStatus={suricataStatus}
          liveCaptureRunning={liveCaptureRunning}
          liveCaptureStatus={liveCaptureStatus}
          activeInterface={
            (liveCaptureRunning ? liveCaptureStatus?.interface : null) ||
            suricataStatus?.interface ||
            selectedLiveInterface ||
            defaultLiveInterface ||
            selectedInterface ||
            defaultInterface
          }
          eventCount={events.length}
        />

        {/* ── Tab Bar ── */}
        <div className="flex items-center gap-1 mb-6 bg-white dark:bg-[#111827] rounded-xl border border-slate-200 dark:border-slate-700 p-1 shadow-sm">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold transition-all duration-200 ${
                activeTab === tab.key
                  ? "bg-indigo-600 text-white shadow-sm"
                  : "text-slate-500 hover:text-slate-800 hover:bg-slate-50"
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {/* ── Tab Content ── */}
        {activeTab === "live" ? (
          <>
            {/* Controls bar */}
            <div className="flex items-center gap-2 mb-5 flex-wrap bg-white dark:bg-[#111827] rounded-xl border border-slate-200 dark:border-slate-700 px-4 py-3 shadow-sm">
              {/* Connection indicator */}
              <div className="flex items-center gap-2 mr-2">
                <span
                  className={`w-2.5 h-2.5 rounded-full transition-all duration-500 ${
                    connected ? "bg-emerald-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]"
                    : wsStatus === "reconnecting" ? "bg-amber-400 animate-pulse"
                    : wsStatus === "failed" ? "bg-red-500"
                    : "bg-slate-400 animate-pulse"
                  }`}
                />
                <span className="text-xs font-medium text-slate-600">
                  {connected ? "Live" : wsStatus === "reconnecting" ? "Reconnecting…" : wsStatus === "failed" ? "Offline" : "Connecting…"}
                </span>
                {wsStatus === "failed" && (
                  <Button size="xs" variant="outline" onClick={reconnect} className="ml-1">Retry</Button>
                )}
              </div>

              {/* Replay */}
              {!replaying ? (
                <Button size="sm" variant="investigate" onClick={startReplay} disabled={!connected}>▶ Start Replay</Button>
              ) : (
                <Button size="sm" variant="destructive" onClick={stopReplay}>■ Stop Replay</Button>
              )}

              {/* Live Sniffer */}
              {!liveCaptureRunning ? (
                <Button id="quick-start-live-capture-btn" size="sm" variant="live"
                  onClick={() => startLiveCapture(selectedLiveInterface || defaultLiveInterface, livePacketLimit, liveTimeLimit)}
                  disabled={!connected || liveCaptureLoading}
                  className="gap-1.5 font-medium" title="Sniff real raw packets from local WiFi/Ethernet adapter via Scapy">
                  <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                  <span>{liveCaptureLoading ? "Starting Sniffer…" : "Start Live Sniffer"}</span>
                </Button>
              ) : (
                <Button id="quick-stop-live-capture-btn" size="sm" variant="destructive"
                  onClick={stopLiveCapture} disabled={liveCaptureLoading} className="gap-1.5 font-medium animate-pulse">
                  <span>{liveCaptureLoading ? "Stopping…" : "■ Stop Live Sniffer"}</span>
                </Button>
              )}

              {/* Research Mode controls */}
              {researchMode && (
                <>
                  {!honeypotRunning ? (
                    <Button size="sm" variant="honeypot" onClick={startHoneypot} disabled={!connected}>🍯 Start Honeypot</Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={stopHoneypot} className="bg-fuchsia-50 hover:bg-fuchsia-100 text-fuchsia-700 border-fuchsia-200">Stop Honeypot</Button>
                  )}
                  <div className="flex items-center gap-1.5">
                    {!suricataRunning && interfaces.length > 0 && (
                      <select
                        id="suricata-interface-select"
                        value={selectedInterface || defaultInterface}
                        onChange={(e) => setSelectedInterface(e.target.value)}
                        className="h-8 px-2 py-1 text-xs bg-white border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        title="Select network interface for Suricata live capture"
                      >
                        {interfaces.map((iface) => (
                          <option key={iface.name} value={iface.name}>
                            {iface.name} {iface.ip ? `(${iface.ip})` : ""} {iface.is_default ? "★ default" : ""}
                          </option>
                        ))}
                      </select>
                    )}
                    {!suricataRunning ? (
                      <Button id="suricata-start-btn" size="sm" variant="suricata"
                        onClick={() => startSuricata(selectedInterface || defaultInterface)} disabled={!connected}>
                        🛡️ Start Suricata
                      </Button>
                    ) : (
                      <Button id="suricata-stop-btn" size="sm" variant="outline" onClick={stopSuricata}
                        className="bg-cyan-50 hover:bg-cyan-100 text-cyan-700 border-cyan-200">
                        Stop Suricata
                      </Button>
                    )}
                  </div>
                </>
              )}

              <Button size="sm" variant="outline" onClick={clearEvents}>Clear</Button>

              {/* Right-aligned exports */}
              <div className="flex items-center gap-2 sm:ml-auto flex-wrap">
                <Button id="live-upload-dataset-btn" size="sm" variant="outline" onClick={() => setActiveTab("upload")}
                  className="text-xs bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border-indigo-200 gap-1.5 font-semibold">
                  <span>📁</span><span>Upload Dataset</span>
                </Button>
                <Button id="export-suricata-csv-btn" size="sm" variant="outline"
                  onClick={() => handleDownloadCsv("suricata")} disabled={downloadingCsv === "suricata"}
                  className="text-xs gap-1.5">
                  <span>📊</span><span>{downloadingCsv === "suricata" ? "Exporting…" : "Suricata CSV"}</span>
                </Button>
                <Button id="export-honeypot-csv-btn" size="sm" variant="outline"
                  onClick={() => handleDownloadCsv("honeypot")} disabled={downloadingCsv === "honeypot"}
                  className="text-xs gap-1.5">
                  <span>🍯</span><span>{downloadingCsv === "honeypot" ? "Exporting…" : "Honeypot CSV"}</span>
                </Button>
              </div>
            </div>

            {/* CSV feedback alert */}
            <AnimatePresence>
              {csvNotice && (
                <motion.div
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  className={`mb-4 px-4 py-2.5 rounded-xl border text-xs font-medium flex items-center justify-between shadow-sm ${
                    csvNotice.isError ? "bg-red-50 text-red-700 border-red-200" : "bg-emerald-50 text-emerald-700 border-emerald-200"
                  }`}
                >
                  <span>{csvNotice.isError ? "⚠ " : "✓ "}{csvNotice.msg}</span>
                  <button type="button" onClick={() => setCsvNotice(null)} className="text-slate-400 hover:text-slate-600 font-bold ml-4">✕</button>
                </motion.div>
              )}
            </AnimatePresence>

            {/* ── Live Network Traffic Capture Command Center ── */}
            <div className="mb-5 rounded-2xl border border-teal-200 dark:border-teal-800 bg-white dark:bg-[#111827] shadow-sm overflow-hidden">
              <div className="px-5 py-4 flex flex-col md:flex-row md:items-center justify-between gap-3 bg-gradient-to-r from-teal-50 to-white border-b border-teal-100">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${
                    liveCaptureRunning ? "bg-teal-600 text-white shadow-md shadow-teal-500/30 animate-pulse" : "bg-teal-100 text-teal-700"
                  }`}>
                    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M5 12.55a11 11 0 0 1 14.08 0" />
                      <path d="M1.42 9a16 16 0 0 1 21.16 0" />
                      <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
                      <circle cx="12" cy="20" r="1" />
                    </svg>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-bold text-slate-900">Live Network Traffic Capture</h3>
                      <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[0.65rem] font-bold border ${
                        liveCaptureRunning
                          ? "bg-teal-100 text-teal-800 border-teal-300"
                          : "bg-slate-100 text-slate-600 border-slate-200"
                      }`}>
                        {liveCaptureRunning ? (
                          <><span className="w-1.5 h-1.5 rounded-full bg-teal-500 animate-ping" />SNIFFING LIVE</>
                        ) : "SCAPY PACKET SNIFFER"}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Real-time packet capture on WiFi &amp; Ethernet → NSL-KDD extraction → XGBoost ML triage
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <div className="flex items-center gap-1.5">
                    <label htmlFor="live-iface-select" className="text-xs text-slate-600 font-medium whitespace-nowrap">Adapter:</label>
                    <select
                      id="live-iface-select"
                      disabled={liveCaptureRunning || liveCaptureLoading}
                      value={selectedLiveInterface || defaultLiveInterface}
                      onChange={(e) => setSelectedLiveInterface(e.target.value)}
                      className="h-8 px-2.5 py-1 text-xs bg-white border border-slate-200 rounded-lg text-slate-700 focus:outline-none focus:ring-2 focus:ring-teal-500 disabled:opacity-60 max-w-[210px] font-mono"
                    >
                      {liveInterfaces.length > 0 ? (
                        liveInterfaces.map((iface) => (
                          <option key={iface.guid || iface.name} value={iface.name}>
                            {iface.name} {iface.ip ? `(${iface.ip})` : ""} {iface.is_up ? "● UP" : "○ DOWN"}
                          </option>
                        ))
                      ) : (
                        <option value="Wi-Fi">Wi-Fi (Default)</option>
                      )}
                    </select>
                  </div>

                  {!liveCaptureRunning ? (
                    <Button id="panel-start-live-capture-btn" size="sm" variant="live"
                      disabled={!connected || liveCaptureLoading}
                      onClick={() => startLiveCapture(selectedLiveInterface || defaultLiveInterface, livePacketLimit, liveTimeLimit)}
                      className="bg-teal-600 hover:bg-teal-700 text-white gap-1.5">
                      <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" />
                      </svg>
                      <span>{liveCaptureLoading ? "Starting…" : "Start Sniffing"}</span>
                    </Button>
                  ) : (
                    <Button id="panel-stop-live-capture-btn" size="sm" variant="destructive"
                      disabled={liveCaptureLoading} onClick={stopLiveCapture} className="gap-1.5 animate-pulse">
                      <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="6" y="6" width="12" height="12" fill="currentColor" />
                      </svg>
                      <span>{liveCaptureLoading ? "Stopping…" : "Stop Sniffing"}</span>
                    </Button>
                  )}

                  <button type="button" onClick={() => fetchLiveInterfaces()} disabled={liveCaptureRunning || liveCaptureLoading}
                    title="Rescan network adapters"
                    className="p-2 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-500 hover:text-slate-800 disabled:opacity-40 transition-colors">
                    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
                    </svg>
                  </button>

                  <button type="button" onClick={() => setShowLiveSnifferPanel(!showLiveSnifferPanel)}
                    className="text-xs text-teal-700 hover:text-teal-900 font-medium px-2.5 py-1.5 rounded-lg bg-teal-50 hover:bg-teal-100 border border-teal-200 transition-colors">
                    {showLiveSnifferPanel ? "Hide Details" : "Show Details"}
                  </button>
                </div>
              </div>

              {/* Live Telemetry Meters */}
              {showLiveSnifferPanel && (
                <div className="p-4">
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                    {[
                      { label: "Sniffer State", value: liveCaptureRunning ? "Capturing" : "Idle", valueClass: liveCaptureRunning ? "text-teal-700" : "text-slate-500", sub: liveCaptureStatus?.interface || selectedLiveInterface || defaultLiveInterface || "None", icon: liveCaptureRunning ? "🟢" : "⚪" },
                      { label: "Packets Sniffed", value: (liveCaptureStatus?.total_packets ?? 0).toLocaleString(), valueClass: "text-slate-900", sub: "Raw IP frames", icon: "📦" },
                      { label: "Active Conns", value: String(liveCaptureStatus?.active_connections ?? 0), valueClass: "text-cyan-700", sub: "TCP/UDP streams", icon: "🔗" },
                      { label: "ML Inferences", value: String(liveCaptureStatus?.events_processed ?? 0), valueClass: "text-indigo-700", sub: "NSL-KDD 41-feature", icon: "🧠" },
                      { label: "Anomalies Triaged", value: String(liveCaptureStatus?.anomalies_detected ?? 0), valueClass: "text-red-600", sub: "Flagged by ML/YARA", icon: "⚠" },
                      { label: "Capture Uptime", value: liveCaptureStatus?.uptime_seconds !== undefined ? `${liveCaptureStatus.uptime_seconds}s` : "0.0s", valueClass: "text-slate-700", sub: "Elapsed time", icon: "⏱" },
                    ].map((m) => (
                      <div key={m.label} className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                        <div className="flex items-center gap-1.5 mb-1">
                          <span className="text-base leading-none">{m.icon}</span>
                          <div className="text-[0.6rem] font-semibold uppercase tracking-wider text-slate-500">{m.label}</div>
                        </div>
                        <div className={`text-lg font-bold font-mono ${m.valueClass}`}>{m.value}</div>
                        <div className="text-[0.6rem] text-slate-400 mt-0.5 truncate">{m.sub}</div>
                      </div>
                    ))}
                  </div>

                  {/* Adapter details & config row */}
                  <div className="mt-3 pt-3 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-600">
                    <div className="flex items-center gap-3 flex-wrap">
                      {activeLiveIfaceObj && (
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-700">Adapter:</span>
                          <span className="text-slate-800 font-mono text-[0.75rem]">{activeLiveIfaceObj.description}</span>
                          {activeLiveIfaceObj.ip && (
                            <code className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-mono text-[0.7rem] font-semibold">
                              {activeLiveIfaceObj.ip}
                            </code>
                          )}
                          {activeLiveIfaceObj.mac && (
                            <span className="text-slate-400 font-mono text-[0.65rem]">({activeLiveIfaceObj.mac})</span>
                          )}
                        </div>
                      )}
                    </div>

                    {!liveCaptureRunning && (
                      <div className="flex items-center gap-3 flex-wrap">
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-500">Packet Limit:</span>
                          <select value={livePacketLimit} onChange={(e) => setLivePacketLimit(Number(e.target.value))}
                            className="h-7 px-2 text-xs bg-white border border-slate-200 rounded text-slate-700">
                            <option value={0}>Unlimited</option>
                            <option value={50}>50 pkts</option>
                            <option value={100}>100 pkts</option>
                            <option value={500}>500 pkts</option>
                            <option value={1000}>1,000 pkts</option>
                          </select>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-500">Timeout:</span>
                          <select value={liveTimeLimit} onChange={(e) => setLiveTimeLimit(Number(e.target.value))}
                            className="h-7 px-2 text-xs bg-white border border-slate-200 rounded text-slate-700">
                            <option value={0}>Unlimited</option>
                            <option value={30}>30 sec</option>
                            <option value={60}>60 sec</option>
                            <option value={300}>5 min</option>
                          </select>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* MongoDB live stats overview */}
            <StatsOverview
              onApprove={approveEvent}
              onReject={rejectEvent}
              onInvestigate={investigateEvent}
              onFalsePositive={markFalsePositive}
            />



            {/* Event Feed */}
            {wsStatus === "connecting" && events.length === 0 ? (
              <div className="space-y-3">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="p-4 rounded-xl border border-slate-200 bg-white shadow-sm space-y-3">
                    <div className="flex justify-between items-center">
                      <div className="skeleton h-5 w-40" />
                      <div className="skeleton h-5 w-20 rounded-full" />
                    </div>
                    <div className="skeleton h-12 w-full rounded-lg" />
                    <div className="flex gap-2">
                      <div className="skeleton h-6 w-24 rounded-full" />
                      <div className="skeleton h-6 w-24 rounded-full" />
                    </div>
                  </div>
                ))}
              </div>
            ) : wsStatus === "failed" && events.length === 0 ? (
              <div className="text-center py-16 rounded-2xl border border-dashed border-red-200 bg-red-50/30">
                <div className="text-5xl mb-4">⚠️</div>
                <h3 className="text-base font-bold text-red-700 mb-1">Connection Failed</h3>
                <p className="text-red-500/70 text-sm max-w-sm mx-auto mb-4">
                  Could not connect to the SentinelAI backend. Ensure the server is running on port 8000.
                </p>
                <Button size="sm" variant="destructive" onClick={reconnect}>
                  Retry Connection
                </Button>
              </div>
            ) : events.length === 0 ? (
              <div className="text-center py-20 rounded-2xl border border-dashed border-slate-300 dark:border-slate-700 bg-white dark:bg-[#111827]">
                <div className="text-5xl mb-4">🛡️</div>
                <h3 className="text-base font-bold text-slate-700 dark:text-slate-200 mb-1">No alerts yet</h3>
                <p className="text-slate-400 text-sm max-w-xs mx-auto">
                  Click <strong>▶ Start Replay</strong> to stream benchmark traffic, or activate <strong>Live Sniffer</strong> to capture real network packets.
                </p>
              </div>
            ) : (
              <AnimatePresence initial={false}>
                {events.map((ev, i) => (
                  <motion.div
                    key={`live-${i}-${ev.event_id || ev.event_index}`}
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.22, ease: "easeOut" }}
                  >
                    <EventCard
                      event={ev}
                      onApprove={approveEvent}
                      onReject={rejectEvent}
                      onInvestigate={investigateEvent}
                      onFalsePositive={markFalsePositive}
                    />
                  </motion.div>
                ))}
              </AnimatePresence>
            )}
          </>
        ) : activeTab === "history" ? (
          <HistoryView onExportCsv={handleDownloadCsv} />
        ) : activeTab === "upload" ? (
          <DatasetUploadView onViewLiveFeed={() => setActiveTab("live")} />
        ) : (
          /* Comparative R&D Study tab */
          <div className="space-y-5">
            <div className="rounded-2xl border border-indigo-200 dark:border-indigo-900/50 bg-white dark:bg-[#111827] shadow-sm overflow-hidden">
              <div className="px-6 py-4 bg-gradient-to-r from-indigo-50 dark:from-indigo-950/40 to-white dark:to-[#111827] border-b border-indigo-100 dark:border-indigo-900/50">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-indigo-100 dark:bg-indigo-950/60 flex items-center justify-center text-xl">🔬</div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-md text-[0.6rem] font-bold uppercase tracking-widest bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800">Research</span>
                      <h2 className="text-base font-bold text-slate-900 dark:text-white">Comparative R&amp;D Study</h2>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Experimental detection methods explored during the research phase of SentinelAI.
                      These are <strong>not</strong> part of the production triage pipeline.
                    </p>
                  </div>
                </div>
              </div>
              <div className="p-6 space-y-4">
                <div className="p-5 rounded-xl bg-slate-50 dark:bg-[#1E293B] border border-slate-200 dark:border-slate-700">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">Quantum-Enhanced ML (Exploratory)</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                    A comparative study explored Variational Quantum Classifier (VQC) circuits
                    against the production XGBoost model on the NSL-KDD dataset. The quantum approach
                    used Qiskit&apos;s Aer simulator with ZZFeatureMap encoding and a RealAmplitudes ansatz.
                    Results showed the classical XGBoost model significantly outperforms the quantum
                    classifier in both accuracy and inference speed, validating the production choice.
                  </p>
                  <div className="mt-4 grid grid-cols-2 gap-3">
                    <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50">
                      <div className="text-xs text-emerald-700 dark:text-emerald-400 font-bold uppercase tracking-wider">XGBoost (Production)</div>
                      <div className="text-2xl font-black text-emerald-600 dark:text-emerald-400 mt-1">99.1%</div>
                      <div className="text-[0.65rem] text-slate-500 dark:text-slate-400 mt-0.5">Accuracy on KDDTest+</div>
                    </div>
                    <div className="p-4 rounded-xl bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-900/50">
                      <div className="text-xs text-indigo-700 dark:text-indigo-400 font-bold uppercase tracking-wider">Quantum VQC (Research)</div>
                      <div className="text-2xl font-black text-indigo-600 dark:text-indigo-400 mt-1">~65-70%</div>
                      <div className="text-[0.65rem] text-slate-500 dark:text-slate-400 mt-0.5">Accuracy (simulator)</div>
                    </div>
                  </div>
                </div>
                {researchMode && (
                  <div className="p-5 rounded-xl bg-fuchsia-50 dark:bg-fuchsia-950/30 border border-fuchsia-200 dark:border-fuchsia-900/50">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-2">🍯 Honeypot Intelligence (Research Mode)</h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                      The honeypot listener is available in Research Mode. It deploys a decoy
                      TCP listener on localhost to capture real adversarial probes and feed them
                      into the triage pipeline. Toggle it from the Live Feed controls.
                    </p>
                  </div>
                )}
                <p className="text-[0.65rem] text-slate-400 dark:text-slate-500 italic">
                  These experimental approaches informed architecture decisions but are not
                  included in the operational detection pipeline.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
