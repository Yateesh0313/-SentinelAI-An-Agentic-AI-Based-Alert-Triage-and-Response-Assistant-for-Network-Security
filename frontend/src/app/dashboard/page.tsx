"use client";

import { useSentinelWS, type SentinelEvent, type AttackTechnique, type IPEnrichment, type SignatureMatch, type HoneypotMeta, type SuricataMeta, type NetworkMeta } from "@/hooks/use-sentinel-ws";
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
import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import dynamic from "next/dynamic";
import Link from "next/link";

const DashboardBackground = dynamic(
  () => import("@/components/home/DashboardBackground"),
  { ssr: false }
);

const API_BASE = "http://localhost:8000";

/* ------------------------------------------------------------------ */
/* Severity badge                                                      */
/* ------------------------------------------------------------------ */

function SeverityBadge({ level }: { level: string | null | undefined }) {
  if (!level) return null;

  const colorMap: Record<string, string> = {
    Critical: "bg-red-600 text-white",
    High: "bg-orange-500 text-white",
    Medium: "bg-yellow-500 text-black",
    Low: "bg-zinc-500 text-white",
    UNKNOWN: "bg-zinc-700 text-zinc-300",
  };

  const cls = colorMap[level] || colorMap["UNKNOWN"];

  return (
    <Badge
      variant="outline"
      className={`rounded-full px-2.5 py-0.5 text-xs font-semibold border-transparent ${cls}`}
    >
      {level}
    </Badge>
  );
}

function PredictionBadge({ prediction }: { prediction: string }) {
  const isAnomaly = prediction === "anomaly";
  const isHoneypot = prediction === "honeypot";
  const isSuricata = prediction === "suricata_alert";
  return (
    <Badge
      variant={isAnomaly ? "destructive" : isHoneypot ? "default" : isSuricata ? "outline" : "secondary"}
      className={`text-[0.65rem] font-semibold uppercase tracking-wider ${
        isAnomaly
          ? "bg-red-500/15 text-red-400 border-red-500/20"
          : isHoneypot
          ? "bg-fuchsia-500/15 text-fuchsia-400 border-fuchsia-500/20"
          : isSuricata
          ? "bg-cyan-500/15 text-cyan-400 border-cyan-500/20"
          : "bg-emerald-500/10 text-emerald-400 border-emerald-500/10"
      }`}
    >
      {prediction === "suricata_alert" ? "suricata" : prediction}
    </Badge>
  );
}

function SourceBadge({ source }: { source?: string }) {
  if (!source) return null;
  const config: Record<string, { bg: string; text: string; label: string }> = {
    honeypot: { bg: "bg-fuchsia-500/15", text: "text-fuchsia-400", label: "Honeypot" },
    suricata: { bg: "bg-cyan-500/15", text: "text-cyan-400", label: "Suricata IDS" },
    replay: { bg: "bg-blue-500/10", text: "text-blue-400", label: "Replay" },
    live_capture: { bg: "bg-teal-500/10", text: "text-teal-400", label: "Live Capture" },
  };
  const c = config[source] || { bg: "bg-zinc-500/10", text: "text-zinc-400", label: source };
  return (
    <Badge
      variant="outline"
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.6rem] font-semibold uppercase tracking-wider border-current/20 ${c.bg} ${c.text}`}
    >
      <svg className="w-2 h-2" viewBox="0 0 8 8" fill="currentColor"><circle cx="4" cy="4" r="3" /></svg>
      {c.label}
    </Badge>
  );
}

function HoneypotProbePanel({ meta }: { meta?: HoneypotMeta | null }) {
  if (!meta) return null;
  return (
    <div className="mt-2 p-3 rounded-lg bg-gradient-to-r from-fuchsia-500/[0.04] to-purple-500/[0.04] border border-fuchsia-500/10">
      <div className="flex items-center gap-2 mb-2">
        <svg className="w-3.5 h-3.5 text-fuchsia-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <circle cx="12" cy="10" r="3" />
        </svg>
        <span className="text-xs font-semibold text-fuchsia-300">Honeypot Probe</span>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="space-y-1">
          <div className="text-muted-foreground">Source</div>
          <code className="text-[0.7rem] font-mono text-fuchsia-300 bg-white/5 px-1.5 py-0.5 rounded">
            {meta.src_ip}:{meta.src_port}
          </code>
        </div>
        <div className="space-y-1">
          <div className="text-muted-foreground">Target Port</div>
          <code className="text-[0.7rem] font-mono text-fuchsia-300 bg-white/5 px-1.5 py-0.5 rounded">
            :{meta.dst_port}
          </code>
        </div>
      </div>
      {meta.probe_text && (
        <div className="mt-2">
          <div className="text-[0.65rem] text-muted-foreground mb-1">Probe Data ({meta.probe_bytes_len} bytes)</div>
          <pre className="text-[0.65rem] font-mono text-fuchsia-200/80 bg-black/30 p-2 rounded overflow-x-auto max-h-16">{meta.probe_text}</pre>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* ATT&CK technique badges                                             */
/* ------------------------------------------------------------------ */

function AttackBadges({
  techniques,
}: {
  techniques?: AttackTechnique[] | null;
}) {
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
            className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.65rem] font-semibold bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/30 hover:bg-cyan-500/25 hover:ring-cyan-400/50 transition-all duration-150 cursor-pointer no-underline"
          >
            <svg
              className="w-2.5 h-2.5 opacity-60"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
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
      <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        Action executed (simulated)
      </span>
    );
  }

  if (status === "rejected") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-zinc-400">
        <span className="w-1.5 h-1.5 rounded-full bg-zinc-400" />
        Action declined
      </span>
    );
  }

  if (status === "investigating") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 animate-pulse">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
        Investigating…
      </span>
    );
  }

  if (status === "false_positive") {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-400">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
        False Positive
      </span>
    );
  }

  return null;
}

/* ------------------------------------------------------------------ */
/* Signature match badges                                              */
/* ------------------------------------------------------------------ */

function SignatureBadges({
  matches,
}: {
  matches?: SignatureMatch[] | null;
}) {
  if (!matches || matches.length === 0) return null;
  return (
    <>
      {matches.map((m) => {
        const severityColor =
          m.severity === "critical"
            ? "bg-rose-500/15 text-rose-400 ring-rose-500/20"
            : m.severity === "high"
            ? "bg-amber-500/15 text-amber-400 ring-amber-500/20"
            : "bg-amber-500/10 text-amber-300 ring-amber-500/15";
        return (
          <span
            key={m.rule}
            title={m.description}
            className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[0.6rem] font-medium ring-1 ${severityColor} cursor-help transition-colors`}
          >
            <svg
              className="w-2.5 h-2.5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            {m.rule.replace(/_/g, " ")}
          </span>
        );
      })}
    </>
  );
}

/* ------------------------------------------------------------------ */
/* IP Enrichment panel                                                 */
/* ------------------------------------------------------------------ */

function countryCodeToFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return "🌐";
  const offset = 0x1f1e6;
  return (
    String.fromCodePoint(code.charCodeAt(0) - 65 + offset) +
    String.fromCodePoint(code.charCodeAt(1) - 65 + offset)
  );
}

function EnrichmentPanel({
  enrichment,
}: {
  enrichment?: IPEnrichment | null;
}) {
  if (!enrichment) return null;

  const { ip, ip_type, reputation, geolocation } = enrichment;
  const hasGeo =
    geolocation &&
    geolocation.source !== "unavailable" &&
    geolocation.country;
  const hasRep =
    reputation &&
    reputation.source !== "unavailable" &&
    reputation.abuse_confidence_score !== null;

  if (!hasGeo && !hasRep) return null;

  const abuseScore = reputation?.abuse_confidence_score ?? 0;
  const abuseColor =
    abuseScore >= 75
      ? "text-red-400"
      : abuseScore >= 40
      ? "text-orange-400"
      : abuseScore >= 10
      ? "text-yellow-400"
      : "text-emerald-400";

  const countryCode =
    geolocation?.country_code || reputation?.country_code || null;
  const flag = countryCodeToFlag(countryCode);

  return (
    <div className="mt-2 p-3 rounded-lg bg-gradient-to-r from-violet-500/[0.04] to-blue-500/[0.04] border border-violet-500/10">
      <div className="flex items-center gap-2 mb-2">
        <svg
          className="w-3.5 h-3.5 text-violet-400"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="12" cy="12" r="10" />
          <path d="M2 12h20" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <span className="text-xs font-semibold text-violet-300">
          IP Enrichment
        </span>
        <code className="text-[0.65rem] font-mono text-muted-foreground bg-white/5 px-1.5 py-0.5 rounded">
          {ip}
        </code>
        {ip_type === "simulated" && (
          <span className="text-[0.6rem] text-amber-400/70 italic">
            (simulated IP — NSL-KDD)
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        {/* Geolocation column */}
        {hasGeo && (
          <div className="space-y-1">
            <div className="flex items-center gap-1.5">
              <span className="text-base leading-none">{flag}</span>
              <span className="text-muted-foreground">
                {geolocation.city && `${geolocation.city}, `}
                {geolocation.country}
              </span>
            </div>
            {geolocation.region && (
              <div className="text-muted-foreground/60 pl-6">
                {geolocation.region}
              </div>
            )}
            {geolocation.isp && (
              <div className="text-muted-foreground/60 pl-6 truncate" title={geolocation.isp}>
                ISP: {geolocation.isp}
              </div>
            )}
            {geolocation.lat !== null && geolocation.lon !== null && (
              <div className="text-muted-foreground/40 pl-6 font-mono text-[0.6rem]">
                {geolocation.lat.toFixed(2)}, {geolocation.lon.toFixed(2)}
              </div>
            )}
          </div>
        )}

        {/* Reputation column */}
        {hasRep && (
          <div className="space-y-1">
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground">Abuse Score:</span>
              <span className={`font-bold ${abuseColor}`}>
                {abuseScore}%
              </span>
            </div>
            <div className="text-muted-foreground/60">
              Reports: {reputation.total_reports ?? 0}
            </div>
            {reputation.isp && (
              <div className="text-muted-foreground/60 truncate" title={reputation.isp}>
                ISP: {reputation.isp}
              </div>
            )}
            {reputation.domain && (
              <div className="text-muted-foreground/60 truncate" title={reputation.domain}>
                Domain: {reputation.domain}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SuricataAlertPanel({ meta, network }: { meta?: SuricataMeta | null; network?: NetworkMeta | null }) {
  if (!meta) return null;
  const sevColors: Record<string, string> = {
    Critical: "text-red-400 bg-red-500/10",
    High: "text-orange-400 bg-orange-500/10",
    Medium: "text-yellow-400 bg-yellow-500/10",
    Low: "text-emerald-400 bg-emerald-500/10",
  };
  const sevClass = sevColors[meta.severity_label] ?? "text-zinc-400 bg-zinc-500/10";
  return (
    <div className="mt-2 p-3 rounded-lg bg-gradient-to-r from-cyan-500/[0.04] to-blue-500/[0.04] border border-cyan-500/10">
      <div className="flex items-center gap-2 mb-2">
        <svg className="w-3.5 h-3.5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span className="text-xs font-semibold text-cyan-300">Suricata IDS Alert</span>
        <span className={`text-[0.65rem] px-1.5 py-0.5 rounded font-medium ${sevClass}`}>
          {meta.severity_label}
        </span>
      </div>
      <div className="mb-1.5">
        <code className="text-[0.7rem] font-mono text-cyan-200 bg-white/5 px-1.5 py-0.5 rounded">
          SID:{meta.signature_id} — {meta.signature}
        </code>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="space-y-1">
          <div className="text-muted-foreground">Category</div>
          <span className="text-cyan-300/80">{meta.category}</span>
        </div>
        <div className="space-y-1">
          <div className="text-muted-foreground">Tactic</div>
          <span className="text-cyan-300/80">{meta.tactic}</span>
        </div>
        {network && (
          <>
            <div className="space-y-1">
              <div className="text-muted-foreground">Source</div>
              <code className="text-[0.7rem] font-mono text-cyan-300 bg-white/5 px-1.5 py-0.5 rounded">
                {network.src_ip}:{network.src_port}
              </code>
            </div>
            <div className="space-y-1">
              <div className="text-muted-foreground">Destination</div>
              <code className="text-[0.7rem] font-mono text-cyan-300 bg-white/5 px-1.5 py-0.5 rounded">
                {network.dst_ip}:{network.dst_port}
              </code>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Event card                                                          */
/* ------------------------------------------------------------------ */

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
  const isFalsePositive = event.status === "false_positive";

  const riskScore = event.risk_score ?? undefined;
  const riskClass = event.risk_classification ?? undefined;

  const riskColors: Record<string, string> = {
    CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
    HIGH:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
    MEDIUM:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    LOW:      "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };
  const riskBarColors: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH:     "bg-orange-500",
    MEDIUM:   "bg-yellow-500",
    LOW:      "bg-emerald-500",
  };

  const handleAction = (fn?: (id: string) => Promise<boolean>) => async () => {
    if (!event.event_id || actionInFlight || !fn) return;
    setActionInFlight(true);
    await fn(event.event_id);
    setActionInFlight(false);
  };

  const cardClass = isApproved
    ? "ring-emerald-500/40 bg-emerald-950/20"
    : isRejected
    ? "ring-zinc-600/30 bg-zinc-900/30 opacity-70"
    : isInvestigating
    ? "ring-blue-500/40 bg-blue-950/20"
    : isFalsePositive
    ? "ring-slate-500/30 bg-slate-900/20 opacity-60"
    : isHoneypot
    ? "ring-fuchsia-500/30 bg-fuchsia-950/20 hover:ring-fuchsia-500/50"
    : isSuricata
    ? "ring-cyan-500/30 bg-cyan-950/20 hover:ring-cyan-500/50"
    : isAnomaly
    ? "ring-red-500/30 bg-red-950/20 hover:ring-red-500/50"
    : hasSigMatch
    ? "ring-amber-500/30 bg-amber-950/20 hover:ring-amber-500/50"
    : "ring-emerald-500/10 hover:ring-emerald-500/20";

  return (
    <Card className={`mb-3 transition-all duration-200 ${cardClass}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-muted-foreground">
              #{event.event_index}
            </span>
            <CardTitle className="text-sm">
              <span className="font-semibold">
                {String(raw.protocol_type).toUpperCase()}
              </span>
              <span className="text-muted-foreground mx-1">/</span>
              <span>{String(raw.service)}</span>
              <span className="text-muted-foreground mx-1">/</span>
              <span className="text-muted-foreground">{String(raw.flag)}</span>
            </CardTitle>
            {event.event_id && (
              <span className="text-[0.6rem] font-mono text-muted-foreground/50">
                {event.event_id}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <PredictionBadge prediction={event.prediction} />
            <SourceBadge source={event.source} />
            <SeverityBadge level={event.severity} />
            <AttackBadges techniques={event.attack_techniques} />
            <SignatureBadges matches={event.signature_matches} />
            <span className="text-[0.65rem] text-muted-foreground ml-1">
              {(event.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </div>

        {/* ── Risk score comparison row (Phase 17) ── */}
        {riskScore !== undefined && riskClass && (
          <div className="mt-2 flex items-center gap-3">
            {/* LLM severity label */}
            <div className="flex items-center gap-1.5">
              <span className="text-[0.62rem] text-slate-500 uppercase tracking-wider">LLM</span>
              <SeverityBadge level={event.severity} />
            </div>
            <span className="text-slate-700">vs</span>
            {/* Formula risk score */}
            <div className="flex items-center gap-2">
              <span className="text-[0.62rem] text-slate-500 uppercase tracking-wider">Formula</span>
              <span
                className={`px-2 py-0.5 rounded-md text-[0.65rem] font-bold border
                  ${riskColors[riskClass] ?? "bg-slate-500/20 text-slate-400 border-slate-500/30"}`}
              >
                {riskScore} — {riskClass}
              </span>
              {/* Score bar */}
              <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700
                    ${riskBarColors[riskClass] ?? "bg-slate-500"}`}
                  style={{ width: `${riskScore}%` }}
                />
              </div>
              {/* Agreement indicator */}
              {event.severity && riskClass && (() => {
                const llmTier = ({
                  "Critical": 3, "High": 2, "Medium": 1, "Low": 0,
                } as Record<string, number>)[event.severity as string] ?? -1;
                const formulaTier = ({ "CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0 })[riskClass] ?? -1;
                const agree = llmTier === formulaTier;
                const diff = Math.abs(llmTier - formulaTier);
                return (
                  <span
                    className={`text-[0.58rem] font-semibold px-1.5 py-0.5 rounded
                      ${agree
                        ? "bg-emerald-500/10 text-emerald-400"
                        : diff > 1
                        ? "bg-red-500/10 text-red-400"
                        : "bg-amber-500/10 text-amber-400"}`}
                    title={agree ? "LLM and formula agree" : `${diff}-tier difference`}
                  >
                    {agree ? "✓ agree" : diff > 1 ? "⚠ disagree" : "~ close"}
                  </span>
                );
              })()}
            </div>
          </div>
        )}

        <div className="flex items-center justify-between mt-1">
          <div className="flex items-center gap-2">
            {isFlagged && event.recommended_action && (
              <CardDescription>
                <span className="text-xs text-muted-foreground">Action: </span>
                <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-orange-300">
                  {event.recommended_action}
                </code>
                {event.agent_latency_seconds !== undefined &&
                  event.agent_latency_seconds > 0 && (
                    <span className="text-[0.65rem] text-muted-foreground ml-2">
                      ({event.agent_latency_seconds}s)
                    </span>
                  )}
              </CardDescription>
            )}
            <StatusLabel status={event.status} />
          </div>

          {/* ── Action buttons (shadcn Button + Framer Motion) ── */}
          {showActions && event.event_id && (isPending || isInvestigating) && (
            <div className="flex items-center gap-1.5 flex-wrap justify-end">
              {isPending && (
                <Button
                  size="xs"
                  variant="investigate"
                  onClick={handleAction(onInvestigate)}
                  disabled={actionInFlight}
                  title="Mark as Investigating"
                >
                  🔍 Investigate
                </Button>
              )}
              <Button
                size="xs"
                variant="success"
                onClick={handleAction(onApprove)}
                disabled={actionInFlight}
              >
                {actionInFlight ? "…" : "✓ Approve"}
              </Button>
              <Button
                size="xs"
                variant="slate"
                onClick={handleAction(onFalsePositive)}
                disabled={actionInFlight}
                title="Mark as False Positive"
              >
                FP
              </Button>
              <Button
                size="xs"
                variant="zinc"
                onClick={handleAction(onReject)}
                disabled={actionInFlight}
              >
                {actionInFlight ? "…" : "✕ Reject"}
              </Button>
            </div>
          )}
        </div>
      </CardHeader>

      {event.triage && (
        <CardContent className="pt-0">
          <Collapsible open={expanded} onOpenChange={setExpanded}>
            <CollapsibleTrigger className="text-xs text-blue-400 hover:text-blue-300 transition-colors cursor-pointer flex items-center gap-1">
              <span>{expanded ? "− Hide triage details" : "+ Show triage details"}</span>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="mt-2 p-3 rounded-lg bg-white/[0.03] border border-white/[0.06] text-sm leading-relaxed space-y-2">
                <p>
                  <span className="font-medium text-blue-300">Triage: </span>
                  <span className="text-muted-foreground">{event.triage}</span>
                </p>
                {event.severity_justification && (
                  <p>
                    <span className="font-medium text-orange-300">
                      Justification:{" "}
                    </span>
                    <span className="text-muted-foreground">
                      {event.severity_justification}
                    </span>
                  </p>
                )}
                {event.attack_techniques && event.attack_techniques.length > 0 && (
                  <div>
                    <span className="font-medium text-cyan-300">ATT&CK Techniques: </span>
                    <span className="inline-flex flex-wrap gap-1.5 mt-1">
                      {event.attack_techniques.map((t) => (
                        <a
                          key={t.id}
                          href={`https://attack.mitre.org/techniques/${t.id}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors no-underline"
                        >
                          {t.id} — {t.name}
                        </a>
                      ))}
                    </span>
                  </div>
                )}
                <EnrichmentPanel enrichment={event.ip_enrichment} />
                <HoneypotProbePanel meta={event.honeypot_meta} />
                <SuricataAlertPanel meta={event.suricata_meta} network={event.network_meta} />
              </div>
            </CollapsibleContent>
          </Collapsible>
        </CardContent>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/* Stats bar                                                           */
/* ------------------------------------------------------------------ */

function StatsBar({ events }: { events: SentinelEvent[] }) {
  const anomalyCount = events.filter((e) => e.prediction === "anomaly").length;
  const normalCount = events.filter((e) => e.prediction === "normal").length;
  const pendingCount = events.filter(
    (e) => e.status === "pending_review"
  ).length;
  const approvedCount = events.filter((e) => e.status === "approved").length;
  const rejectedCount = events.filter((e) => e.status === "rejected").length;

  // Detection method comparison stats
  const mlOnly = events.filter(
    (e) => e.ml_flagged && !e.sig_flagged
  ).length;
  const sigOnly = events.filter(
    (e) => !e.ml_flagged && e.sig_flagged
  ).length;
  const bothFlagged = events.filter(
    (e) => e.ml_flagged && e.sig_flagged
  ).length;
  const neitherFlagged = events.filter(
    (e) => !e.ml_flagged && !e.sig_flagged
  ).length;

  const honeypotCount = events.filter((e) => e.prediction === "honeypot").length;
  const suricataCount = events.filter((e) => e.prediction === "suricata_alert").length;

  const stats = [
    { label: "Total", value: events.length, color: "text-foreground" },
    { label: "Anomalies", value: anomalyCount, color: "text-red-400" },
    { label: "Honeypot", value: honeypotCount, color: "text-fuchsia-400" },
    { label: "Suricata", value: suricataCount, color: "text-cyan-400" },
    { label: "Pending", value: pendingCount, color: "text-yellow-400" },
    { label: "Approved", value: approvedCount, color: "text-emerald-400" },
    { label: "Rejected", value: rejectedCount, color: "text-zinc-400" },
  ];

  const detectionStats = [
    { label: "ML Only", value: mlOnly, color: "text-red-400", desc: "ML anomaly, no sig match" },
    { label: "Sig Only", value: sigOnly, color: "text-amber-400", desc: "Signature match, ML normal" },
    { label: "Both", value: bothFlagged, color: "text-rose-400", desc: "ML + signature agree" },
    { label: "Neither", value: neitherFlagged, color: "text-emerald-400", desc: "Both say clean" },
  ];

  return (
    <div className="space-y-3 mb-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-3">
        {stats.map((stat) => (
          <Card key={stat.label} size="sm" className="text-center">
            <CardContent className="py-3">
              <div className={`text-2xl font-bold ${stat.color}`}>
                {stat.value}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {stat.label}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Detection method comparison */}
      {events.length > 0 && (mlOnly + sigOnly + bothFlagged) > 0 && (
        <Card size="sm">
          <CardContent className="py-3">
            <div className="flex items-center gap-2 mb-2">
              <svg
                className="w-3.5 h-3.5 text-violet-400"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span className="text-xs font-semibold text-violet-300">
                Detection Method Comparison
              </span>
            </div>
            <div className="grid grid-cols-4 gap-3">
              {detectionStats.map((ds) => (
                <div key={ds.label} className="text-center">
                  <div className={`text-lg font-bold ${ds.color}`}>
                    {ds.value}
                  </div>
                  <div className="text-[0.65rem] text-muted-foreground" title={ds.desc}>
                    {ds.label}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* MongoDB Stats Overview (Phase 17)                                   */
/* ------------------------------------------------------------------ */

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
      const res = await fetch(`${API_BASE}/stats/overview`);
      const data = await res.json();
      setStats(data);
    } catch { /* silent fail */ }
  }, []);

  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, 15000); // refresh every 15s
    return () => clearInterval(id);
  }, [fetchStats]);

  const openFilterModal = async (title: string, filter: Record<string, string>) => {
    setActiveModal({ title, filter });
    setModalLoading(true);
    try {
      const query = new URLSearchParams(filter).toString();
      const res = await fetch(`${API_BASE}/events/filter?${query}`);
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

  if (!stats || stats.total_events === 0) return null;

  const tiles: { label: string; value: number; color: string; icon: string; filter: Record<string, string> }[] = [
    { label: "Total Events",    value: stats.total_events,    color: "text-slate-300",   icon: "📁", filter: { status: "all" } },
    { label: "Pending Review",  value: stats.pending_review,  color: "text-yellow-400", icon: "⏳", filter: { status: "pending_review" } },
    { label: "Investigating",   value: stats.investigating,   color: "text-blue-400",   icon: "🔍", filter: { status: "investigating" } },
    { label: "LLM Critical",    value: stats.critical_severity, color: "text-red-400",  icon: "🚨", filter: { llm_severity: "Critical" } },
    { label: "Risk CRITICAL",   value: stats.risk_critical,   color: "text-orange-400", icon: "⚠", filter: { risk_classification: "CRITICAL" } },
    { label: "Honeypot Events", value: stats.honeypot_sourced, color: "text-fuchsia-400", icon: "🍯", filter: { source: "honeypot" } },
    { label: "Suricata Events", value: stats.suricata_sourced ?? stats.by_source?.["suricata"] ?? 0, color: "text-cyan-400", icon: "🛡️", filter: { source: "suricata" } },
    { label: "False Positives", value: stats.false_positives, color: "text-slate-400",  icon: "❌", filter: { status: "false_positive" } },
  ];

  return (
    <div className="mb-4 relative">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-[0.65rem] font-semibold uppercase tracking-widest text-slate-400">MongoDB Live Stats</span>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
        </div>
        <span className="text-[0.6rem] text-slate-500 italic">💡 Click any card or bar to inspect matching events</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2">
        {tiles.map((t) => (
          <button
            key={t.label}
            onClick={() => openFilterModal(t.label, t.filter)}
            className="rounded-xl border border-white/5 bg-white/[0.03] px-3 py-2.5 text-center
              hover:bg-cyan-500/10 hover:border-cyan-500/30 transition-all cursor-pointer group hover:scale-[1.02] active:scale-[0.98]"
          >
            <div className="text-base mb-0.5 group-hover:scale-110 transition-transform">{t.icon}</div>
            <div className={`text-xl font-black ${t.color}`}>{t.value}</div>
            <div className="text-[0.58rem] text-slate-500 group-hover:text-cyan-300 mt-0.5 leading-tight font-medium">{t.label}</div>
          </button>
        ))}
      </div>

      {/* LLM vs Formula severity distribution */}
      {Object.keys(stats.by_llm_severity).length > 0 && (
        <div className="mt-3 grid grid-cols-2 gap-3">
          {/* LLM distribution */}
          <div className="rounded-xl border border-white/5 bg-white/[0.02] p-3">
            <div className="text-[0.6rem] uppercase tracking-widest text-slate-500 mb-2">
              LLM Severity Distribution
            </div>
            <div className="space-y-1.5">
              {["Critical","High","Medium","Low"].map((sev) => {
                const count = stats.by_llm_severity[sev] ?? 0;
                const pct = stats.total_events > 0 ? Math.round((count/stats.total_events)*100) : 0;
                const col = { Critical:"bg-red-500", High:"bg-orange-500", Medium:"bg-yellow-500", Low:"bg-emerald-500" }[sev] ?? "bg-slate-500";
                return (
                  <button
                    key={sev}
                    onClick={() => openFilterModal(`LLM Severity: ${sev}`, { llm_severity: sev })}
                    className="w-full flex items-center gap-2 group p-1 rounded hover:bg-white/5 text-left transition-colors cursor-pointer"
                  >
                    <span className="text-[0.65rem] text-slate-400 group-hover:text-white w-12">{sev}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className={`h-full rounded-full ${col} group-hover:brightness-125 transition-all`} style={{ width:`${pct}%` }} />
                    </div>
                    <span className="text-[0.6rem] text-slate-500 group-hover:text-cyan-300 w-6 text-right font-mono">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
          {/* Formula risk distribution */}
          <div className="rounded-xl border border-white/5 bg-white/[0.02] p-3">
            <div className="text-[0.6rem] uppercase tracking-widest text-slate-500 mb-2">
              Formula Risk Distribution
            </div>
            <div className="space-y-1.5">
              {["CRITICAL","HIGH","MEDIUM","LOW"].map((cls) => {
                const count = stats.by_risk_class[cls] ?? 0;
                const pct = stats.total_events > 0 ? Math.round((count/stats.total_events)*100) : 0;
                const col = { CRITICAL:"bg-red-500", HIGH:"bg-orange-500", MEDIUM:"bg-yellow-500", LOW:"bg-emerald-500" }[cls] ?? "bg-slate-500";
                return (
                  <button
                    key={cls}
                    onClick={() => openFilterModal(`Formula Risk: ${cls}`, { risk_classification: cls })}
                    className="w-full flex items-center gap-2 group p-1 rounded hover:bg-white/5 text-left transition-colors cursor-pointer"
                  >
                    <span className="text-[0.65rem] text-slate-400 group-hover:text-white w-14">{cls}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className={`h-full rounded-full ${col} group-hover:brightness-125 transition-all`} style={{ width:`${pct}%` }} />
                    </div>
                    <span className="text-[0.6rem] text-slate-500 group-hover:text-cyan-300 w-6 text-right font-mono">{count}</span>
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
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              className="relative w-full max-w-4xl max-h-[85vh] flex flex-col rounded-2xl border border-cyan-500/30 bg-[#0b1021] shadow-2xl shadow-cyan-950/50 overflow-hidden"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-white/[0.02]">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                    🔍
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white tracking-tight">
                      {activeModal.title}
                    </h3>
                    <p className="text-xs text-slate-400">
                      Showing events matched from MongoDB ({modalEvents.length} results)
                    </p>
                  </div>
                </div>
                <Button
                  size="iconSm"
                  variant="ghost"
                  onClick={closeModal}
                  className="rounded-full border border-slate-700 hover:border-slate-500 bg-slate-800/50 hover:bg-slate-700 text-slate-300"
                >
                  ✕
                </Button>
              </div>

              {/* Modal Body */}
              <div className="p-6 overflow-y-auto space-y-3 flex-1 custom-scrollbar">
                {modalLoading ? (
                  <div className="py-16 text-center text-slate-400 text-sm animate-pulse">
                    Loading events from MongoDB…
                  </div>
                ) : modalEvents.length === 0 ? (
                  <div className="py-16 text-center text-slate-500 text-sm">
                    No stored events match this filter.
                  </div>
                ) : (
                  modalEvents.map((ev, i) => (
                    <EventCard
                      key={`${ev.event_id || i}`}
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

/* ------------------------------------------------------------------ */
/* History view                                                        */
/* ------------------------------------------------------------------ */

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

function HistoryView() {
  const [history, setHistory] = useState<HistoryEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/events/history?limit=50`);
      const data = await res.json();
      setHistory(data.events || []);
    } catch (err) {
      console.error("History fetch error:", err);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-muted-foreground">
          {history.length} resolved events (persisted in MongoDB)
        </p>
        <Button
          size="sm"
          variant="outline"
          onClick={fetchHistory}
          className="text-xs border-zinc-700 text-zinc-400 hover:bg-zinc-800"
        >
          Refresh
        </Button>
      </div>

      {loading ? (
        <Card className="text-center py-12">
          <CardContent>
            <p className="text-muted-foreground text-sm">Loading history...</p>
          </CardContent>
        </Card>
      ) : history.length === 0 ? (
        <Card className="text-center py-12">
          <CardContent>
            <p className="text-muted-foreground text-sm">
              No resolved events yet. Approve or reject some events from the
              Live Feed first.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div>
          {history.map((ev) => (
            <EventCard
              key={ev.event_id}
              event={ev as unknown as SentinelEvent}
              showActions={false}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main page                                                           */
/* ------------------------------------------------------------------ */

export default function Home() {
  const {
    events,
    connected,
    replaying,
    honeypotRunning,
    suricataRunning,
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
    clearEvents,
    approveEvent,
    rejectEvent,
    investigateEvent,
    markFalsePositive,
  } = useSentinelWS();

  const [activeTab, setActiveTab] = useState<"live" | "history" | "rnd">("live");

  return (
    <div className="min-h-screen bg-[#050812] relative">
      {/* Animated particle network background */}
      <DashboardBackground />

      {/* Auth error banner */}
      {authError && (
        <div className="fixed top-0 inset-x-0 z-50 flex items-center justify-between px-6 py-3
          bg-red-500/90 backdrop-blur text-white text-sm font-medium">
          <span>🔒 {authError}</span>
          <Link href="/login" className="underline font-bold hover:text-red-100">Sign In</Link>
        </div>
      )}

      <div className="relative z-10 max-w-4xl mx-auto px-4 py-8">
      {/* Dashboard Navbar */}
      <nav className="flex items-center justify-between mb-8 pb-4 border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center">
            <svg className="w-3.5 h-3.5 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clipRule="evenodd"/>
            </svg>
          </div>
          <span className="font-black text-base tracking-tight text-white">
            Sentinel<span className="text-cyan-400">AI</span>
          </span>
          <span className="ml-2 px-2 py-0.5 rounded text-[0.6rem] font-bold uppercase tracking-widest
            bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Dashboard</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500 hidden sm:block" id="dashboard-username">
            {typeof window !== "undefined" && localStorage.getItem("sentinel_user")
              ? `👤 ${localStorage.getItem("sentinel_user")}`
              : ""}
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
            className="text-slate-400 hover:text-white border-slate-700/60 hover:border-slate-500/60 hover:bg-slate-800/50"
          >
            Sign Out
          </Button>
        </div>
      </nav>
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
          SentinelAI Dashboard
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Agentic AI Alert Triage &amp; Response Assistant
        </p>
      </div>

      {/* Tab bar (shadcn Button + Framer Motion) */}
      <div className="flex items-center gap-1 mb-6 border-b border-zinc-800 pb-px">
        <Button
          size="sm"
          variant={activeTab === "live" ? "default" : "ghost"}
          onClick={() => setActiveTab("live")}
          className={`rounded-b-none border-b-2 ${
            activeTab === "live"
              ? "text-blue-400 border-blue-400 bg-blue-500/10 shadow-none"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Live Feed
        </Button>
        <Button
          size="sm"
          variant={activeTab === "history" ? "default" : "ghost"}
          onClick={() => setActiveTab("history")}
          className={`rounded-b-none border-b-2 ${
            activeTab === "history"
              ? "text-blue-400 border-blue-400 bg-blue-500/10 shadow-none"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          History
        </Button>
        <Button
          size="sm"
          variant={activeTab === "rnd" ? "default" : "ghost"}
          onClick={() => setActiveTab("rnd")}
          className={`rounded-b-none border-b-2 ${
            activeTab === "rnd"
              ? "text-violet-400 border-violet-400 bg-violet-500/10 shadow-none"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Comparative R&amp;D Study
        </Button>
      </div>

      {activeTab === "live" ? (
        <>
          {/* Controls */}
          <div className="flex items-center gap-3 mb-6 flex-wrap">
            <div className="flex items-center gap-2 mr-2">
              <span
                className={`w-2.5 h-2.5 rounded-full transition-all duration-500 ${
                  connected
                    ? "bg-emerald-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"
                    : wsStatus === "reconnecting"
                    ? "bg-yellow-400 shadow-[0_0_8px_rgba(250,204,21,0.5)] animate-pulse"
                    : wsStatus === "failed"
                    ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
                    : "bg-slate-600 animate-pulse"
                }`}
              />
              <span className="text-xs text-muted-foreground">
                {connected
                  ? "Live"
                  : wsStatus === "reconnecting"
                  ? "Reconnecting…"
                  : wsStatus === "failed"
                  ? "Offline"
                  : "Connecting…"}
              </span>
              {wsStatus === "failed" && (
                <Button
                  size="xs"
                  variant="slate"
                  onClick={reconnect}
                  className="ml-1 px-2 py-0.5 text-[0.65rem] font-semibold"
                >
                  Retry
                </Button>
              )}
            </div>

            {!replaying ? (
              <Button
                size="sm"
                variant="investigate"
                onClick={startReplay}
                disabled={!connected}
              >
                Start Replay
              </Button>
            ) : (
              <Button
                size="sm"
                variant="destructive"
                onClick={stopReplay}
              >
                Stop Replay
              </Button>
            )}

            {/* Honeypot toggle — only visible in Research Mode */}
            {researchMode && (
              <>
                {!honeypotRunning ? (
                  <Button
                    size="sm"
                    variant="honeypot"
                    onClick={startHoneypot}
                    disabled={!connected}
                  >
                    Start Honeypot
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={stopHoneypot}
                    className="bg-fuchsia-700 hover:bg-fuchsia-600 text-white ring-1 ring-fuchsia-400/30"
                  >
                    Stop Honeypot
                  </Button>
                )}
              </>
            )}

            {/* Suricata IDS toggle — only visible in Research Mode */}
            {researchMode && (
              <>
                {!suricataRunning ? (
                  <Button
                    size="sm"
                    variant="suricata"
                    onClick={startSuricata}
                    disabled={!connected}
                  >
                    Start Suricata
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={stopSuricata}
                    className="bg-cyan-700 hover:bg-cyan-600 text-white ring-1 ring-cyan-400/30"
                  >
                    Stop Suricata
                  </Button>
                )}
              </>
            )}

            <Button
              size="sm"
              variant="outline"
              onClick={clearEvents}
              className="border-zinc-700 text-zinc-400 hover:bg-zinc-800"
            >
              Clear
            </Button>

            {replaying && (
              <Badge
                variant="outline"
                className="ml-auto animate-pulse text-blue-400 border-blue-500/30"
              >
                LIVE
              </Badge>
            )}

            {honeypotRunning && (
              <Badge
                variant="outline"
                className={`${replaying ? '' : 'ml-auto'} animate-pulse text-fuchsia-400 border-fuchsia-500/30`}
              >
                HONEYPOT :8899
              </Badge>
            )}

            {suricataRunning && (
              <Badge
                variant="outline"
                className={`${replaying || honeypotRunning ? '' : 'ml-auto'} animate-pulse text-cyan-400 border-cyan-500/30`}
              >
                SURICATA IDS
              </Badge>
            )}
          </div>

          {/* Phase 17: MongoDB live stats overview */}
          <StatsOverview
            onApprove={approveEvent}
            onReject={rejectEvent}
            onInvestigate={investigateEvent}
            onFalsePositive={markFalsePositive}
          />

          {/* Session stats */}
          <StatsBar events={events} />

          {/* Event Feed */}
          {events.length === 0 ? (
            <Card className="text-center py-16">
              <CardContent>
                <p className="text-muted-foreground text-sm">
                  No events yet. Click &quot;Start Replay&quot; to begin
                  streaming network events.
                </p>
              </CardContent>
            </Card>
          ) : (
            <AnimatePresence initial={false}>
              {events.map((ev, i) => {
                const isHighSeverity =
                  ev.severity === "Critical" || ev.severity === "High";
                return (
                  <motion.div
                    layout
                    key={`${ev.event_index}-${ev.event_id || i}`}
                    initial={{ opacity: 0, y: -20, scale: 0.97 }}
                    animate={{
                      opacity: 1,
                      y: 0,
                      scale: 1,
                      ...(isHighSeverity && i === 0
                        ? {
                            boxShadow: [
                              "0 0 0px rgba(239,68,68,0)",
                              "0 0 20px rgba(239,68,68,0.3)",
                              "0 0 0px rgba(239,68,68,0)",
                            ],
                          }
                        : {}),
                    }}
                    transition={{
                      duration: 0.3,
                      ease: "easeOut",
                      ...(isHighSeverity && i === 0
                        ? {
                            boxShadow: {
                              duration: 1.5,
                              repeat: 2,
                              ease: "easeInOut",
                            },
                          }
                        : {}),
                    }}
                    className="rounded-xl"
                  >
                    <EventCard
                      event={ev}
                      onApprove={approveEvent}
                      onReject={rejectEvent}
                      onInvestigate={investigateEvent}
                      onFalsePositive={markFalsePositive}
                    />
                  </motion.div>
                );
              })}
            </AnimatePresence>
          )}
        </>
      ) : activeTab === "history" ? (
        <HistoryView />
      ) : (
        /* Comparative R&D Study tab */
        <div className="space-y-6">
          <Card className="border-violet-500/20 bg-violet-950/10">
            <CardHeader>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[0.6rem] font-bold uppercase tracking-widest
                  bg-violet-500/10 text-violet-400 border border-violet-500/20">Research</span>
                <CardTitle className="text-lg">Comparative R&amp;D Study</CardTitle>
              </div>
              <CardDescription>
                Experimental detection methods explored during the research phase of SentinelAI.
                These are <strong>not</strong> part of the production triage pipeline.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                <h3 className="text-sm font-bold text-white mb-2">Quantum-Enhanced ML (Exploratory)</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  A comparative study explored Variational Quantum Classifier (VQC) circuits
                  against the production XGBoost model on the NSL-KDD dataset. The quantum approach
                  used Qiskit&apos;s Aer simulator with ZZFeatureMap encoding and a RealAmplitudes ansatz.
                  Results showed the classical XGBoost model significantly outperforms the quantum
                  classifier in both accuracy and inference speed, validating the production choice.
                </p>
                <div className="mt-3 grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-md bg-emerald-500/5 border border-emerald-500/10">
                    <div className="text-xs text-emerald-400 font-semibold">XGBoost (Production)</div>
                    <div className="text-lg font-black text-emerald-400 mt-1">99.1%</div>
                    <div className="text-[0.65rem] text-slate-500">Accuracy on KDDTest+</div>
                  </div>
                  <div className="p-3 rounded-md bg-violet-500/5 border border-violet-500/10">
                    <div className="text-xs text-violet-400 font-semibold">Quantum VQC (Research)</div>
                    <div className="text-lg font-black text-violet-400 mt-1">~65-70%</div>
                    <div className="text-[0.65rem] text-slate-500">Accuracy (simulator)</div>
                  </div>
                </div>
              </div>
              {researchMode && (
                <div className="p-4 rounded-lg bg-white/[0.02] border border-white/5">
                  <h3 className="text-sm font-bold text-white mb-2">Honeypot Intelligence (Research Mode)</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    The honeypot listener is available in Research Mode. It deploys a decoy
                    TCP listener on localhost to capture real adversarial probes and feed them
                    into the triage pipeline. Toggle it from the Live Feed controls.
                  </p>
                </div>
              )}
              <p className="text-[0.65rem] text-slate-600 italic">
                These experimental approaches informed architecture decisions but are not
                included in the operational detection pipeline.
              </p>
            </CardContent>
          </Card>
        </div>
      )}
      </div>
    </div>
  );
}
