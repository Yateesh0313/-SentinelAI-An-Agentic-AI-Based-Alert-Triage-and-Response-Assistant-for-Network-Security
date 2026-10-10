"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export interface AttackTechnique {
  id: string;
  name: string;
}

export interface IPReputation {
  ip: string;
  abuse_confidence_score: number | null;
  total_reports: number | null;
  country_code: string | null;
  isp: string | null;
  domain?: string | null;
  usage_type?: string | null;
  is_whitelisted?: boolean | null;
  source: string;
  error?: string;
}

export interface GeoLocation {
  ip: string;
  country: string | null;
  country_code: string | null;
  city: string | null;
  region: string | null;
  lat: number | null;
  lon: number | null;
  isp: string | null;
  org?: string | null;
  timezone?: string | null;
  source: string;
  error?: string;
}

export interface IPEnrichment {
  ip: string;
  ip_type: "simulated" | "real";
  reputation: IPReputation;
  geolocation: GeoLocation;
}

export interface SignatureMatch {
  rule: string;
  severity: string;
  description: string;
}

export interface HoneypotMeta {
  src_ip: string;
  src_port: number;
  dst_port: number;
  probe_text: string;
  probe_bytes_len: number;
}

export interface SuricataMeta {
  signature: string;
  signature_id: number;
  category: string;
  severity: number;
  severity_label: string;
  tactic: string;
  action: string;
  gid: number;
  rev: number;
}

export interface NetworkInterface {
  name: string;
  ip: string;
  type: string;
  active: boolean;
  is_default: boolean;
}

export interface SuricataStatus {
  status: "running" | "stopped" | string;
  interface?: string | null;
  alerts: number;
  events_per_minute: number;
  uptime_seconds: number;
  eve_json?: string;
}

export interface NetworkMeta {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  timestamp: string;
  packets?: number;
}

export interface LiveCaptureStatus {
  status: "running" | "stopped" | "already_running" | "not_running" | "error" | string;
  running: boolean;
  interface?: string | null;
  uptime_seconds?: number;
  events_processed?: number;
  anomalies_detected?: number;
  active_connections?: number;
  total_connections?: number;
  total_packets?: number;
}

export interface LiveInterface {
  name: string;
  description: string;
  guid: string;
  mac: string;
  ip: string | null;
  is_up: boolean;
  type: "wifi" | "ethernet" | string;
}

export interface SentinelEvent {
  event_index: number;
  raw_event: Record<string, string | number>;
  prediction: string;
  confidence: number;
  actual?: string;
  source?: "replay" | "honeypot" | "suricata" | "live_capture" | "dataset_upload" | string;
  dataset_schema?: string;
  model_used?: string;
  honeypot_meta?: HoneypotMeta | null;
  suricata_meta?: SuricataMeta | null;
  network_meta?: NetworkMeta | null;
  triage?: string | null;
  severity?: string | null;
  severity_justification?: string | null;
  recommended_action?: string | null;
  attack_techniques?: AttackTechnique[] | null;
  signature_matches?: SignatureMatch[] | null;
  ip_enrichment?: IPEnrichment | null;
  ml_flagged?: boolean;
  sig_flagged?: boolean;
  agent_latency_seconds?: number;
  event_id?: string | null;
  status?: string | null;
  risk_score?: number | null;
  risk_classification?: string | null;
  risk_signals?: Record<string, unknown> | null;
}

interface StatusUpdate {
  type: "status_update";
  event_id: string;
  status: string;
  action_executed?: string;
  action_declined?: string;
}

const MAX_EVENTS = 50;
const WS_URL = "ws://localhost:8000/ws";
const API_BASE = "http://localhost:8000";
const RECONNECT_DELAY_MS = 3000;   // wait 3s before retry
const MAX_RECONNECT_ATTEMPTS = 10; // give up after 10 tries (~30s)

// ── Auth helpers ───────────────────────────────────────────────────────────────
function getToken(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("sentinel_token") ?? "";
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function authedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers ?? {}) },
  });
}

// ── Hook ───────────────────────────────────────────────────────────────────────
export function useSentinelWS() {
  const [events, setEvents]               = useState<SentinelEvent[]>([]);
  const [connected, setConnected]         = useState(false);
  const [replaying, setReplaying]         = useState(false);
  const [honeypotRunning, setHoneypotRunning] = useState(false);
  const [suricataRunning, setSuricataRunning] = useState(false);
  const [suricataStatus, setSuricataStatus]   = useState<SuricataStatus | null>(null);
  const [liveCaptureRunning, setLiveCaptureRunning] = useState(false);
  const [liveCaptureStatus, setLiveCaptureStatus]   = useState<LiveCaptureStatus | null>(null);
  const [liveInterfaces, setLiveInterfaces]         = useState<LiveInterface[]>([]);
  const [defaultLiveInterface, setDefaultLiveInterface] = useState<string>("Wi-Fi");
  const [liveCaptureLoading, setLiveCaptureLoading] = useState(false);
  const [interfaces, setInterfaces]           = useState<NetworkInterface[]>([]);
  const [defaultInterface, setDefaultInterface] = useState<string>("");
  const [authError, setAuthError]         = useState<string | null>(null);
  const [wsStatus, setWsStatus]           = useState<"connecting" | "connected" | "reconnecting" | "failed">("connecting");
  const [researchMode, setResearchMode]   = useState(false);
  const wsRef              = useRef<WebSocket | null>(null);
  const reconnectAttempts  = useRef(0);
  const reconnectTimer     = useRef<ReturnType<typeof setTimeout> | null>(null);
  const unmounted          = useRef(false);
  const scheduleReconnectRef = useRef<() => void>(() => {});

  // ── WebSocket connect (with auto-reconnect) ───────────────────────────────
  const connect = useCallback(() => {
    if (unmounted.current) return;
    if (wsRef.current && wsRef.current.readyState === WebSocket.CONNECTING) return;

    setWsStatus(reconnectAttempts.current > 0 ? "reconnecting" : "connecting");

    let ws: WebSocket;
    try {
      ws = new WebSocket(WS_URL);
    } catch {
      scheduleReconnectRef.current();
      return;
    }

    ws.onopen = () => {
      if (unmounted.current) { ws.close(); return; }
      console.log("[SentinelWS] Connected");
      reconnectAttempts.current = 0;
      setConnected(true);
      setWsStatus("connected");
    };

    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === "status_update") {
          const upd = data as StatusUpdate;
          setEvents((prev) =>
            prev.map((e) => (e.event_id === upd.event_id ? { ...e, status: upd.status } : e))
          );
          return;
        }
        setEvents((prev) => [data as SentinelEvent, ...prev].slice(0, MAX_EVENTS));
      } catch {
        /* ignore malformed frames */
      }
    };

    ws.onclose = () => {
      if (unmounted.current) return;
      console.log("[SentinelWS] Disconnected — will reconnect…");
      setConnected(false);
      scheduleReconnectRef.current();
    };

    ws.onerror = () => {
      // Browser fires a generic Event with no useful info — just log a clean message
      if (!unmounted.current) {
        console.warn(`[SentinelWS] Connection error (attempt ${reconnectAttempts.current + 1}/${MAX_RECONNECT_ATTEMPTS}) — backend may be starting up`);
      }
      // onclose fires right after onerror, which handles reconnect
    };

    wsRef.current = ws;
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const scheduleReconnect = useCallback(() => {
    if (unmounted.current) return;
    if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
      setWsStatus("failed");
      return;
    }
    reconnectAttempts.current += 1;
    setWsStatus("reconnecting");
    reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY_MS);
  }, [connect]);
  scheduleReconnectRef.current = scheduleReconnect;

  // ── Network interfaces fetch ─────────────────────────────────────────────
  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/interfaces`);
      if (res.ok) {
        const data = await res.json();
        setInterfaces(data.interfaces || []);
        if (data.default) {
          setDefaultInterface(data.default);
        }
      }
    } catch (err) {
      console.error("[SentinelWS] Fetch interfaces error:", err);
    }
  }, []);

  // ── Suricata status check ─────────────────────────────────────────────────
  const checkSuricataStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/suricata/status`);
      if (res.ok) {
        const data = await res.json();
        const isRunning = data.status === "running";
        setSuricataRunning(isRunning);
        setSuricataStatus(data);
      }
    } catch (err) {
      console.error("[SentinelWS] Check suricata status error:", err);
    }
  }, []);

  // ── Live Traffic Capture interfaces ───────────────────────────────────────
  const fetchLiveInterfaces = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/live/interfaces`);
      if (res.ok) {
        const data = await res.json();
        const ifaces: LiveInterface[] = data.interfaces || [];
        setLiveInterfaces(ifaces);
        if (data.default) {
          setDefaultLiveInterface(data.default);
        } else if (ifaces.length > 0) {
          const upIface = ifaces.find((i) => i.is_up && i.ip);
          if (upIface) setDefaultLiveInterface(upIface.name);
          else setDefaultLiveInterface(ifaces[0].name);
        }
        return ifaces;
      }
    } catch (err) {
      console.error("[SentinelWS] Fetch live interfaces error:", err);
    }
    return [];
  }, []);

  // ── Live Traffic Capture status check ─────────────────────────────────────
  const checkLiveCaptureStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/live/status`);
      if (res.ok) {
        const data: LiveCaptureStatus = await res.json();
        const isRunning = data.status === "running" || data.running === true;
        setLiveCaptureRunning(isRunning);
        setLiveCaptureStatus(data);
        return data;
      }
    } catch (err) {
      console.error("[SentinelWS] Check live capture status error:", err);
    }
    return null;
  }, []);

  useEffect(() => {
    unmounted.current = false;
    connect();
    // Fetch research mode config
    fetch(`${API_BASE}/config/mode`)
      .then((res) => res.json())
      .then((data) => {
        if (data.research_mode !== undefined) setResearchMode(data.research_mode);
      })
      .catch(() => { /* silent — default false */ });

    // Fetch initial pending events from DB so live feed is immediately populated
    fetch(`${API_BASE}/events/pending`)
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data.events) && data.events.length > 0) {
          setEvents((prev) => {
            const existingIds = new Set(prev.map((e) => e.event_id).filter(Boolean));
            const newPending = data.events.filter((e: SentinelEvent) => !existingIds.has(e.event_id));
            return [...prev, ...newPending].slice(0, MAX_EVENTS);
          });
        }
      })
      .catch(() => { /* backend may still be starting */ });

    // Fetch network interfaces and initial Suricata & Live Capture status
    const initNetworkStatus = async () => {
      await fetchInterfaces();
      await checkSuricataStatus();
      await fetchLiveInterfaces();
      await checkLiveCaptureStatus();
    };
    initNetworkStatus();

    return () => {
      unmounted.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  // ── Manual reconnect trigger ──────────────────────────────────────────────
  const reconnect = useCallback(() => {
    reconnectAttempts.current = 0;
    if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    wsRef.current?.close();
    connect();
  }, [connect]);

  // ── Start replay ──────────────────────────────────────────────────────────
  const startReplay = useCallback(async () => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/replay/start`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return; }
      const data = await res.json();
      if (data.status === "started" || data.status === "already_running") setReplaying(true);
    } catch (err) {
      console.error("[SentinelWS] Start replay error:", err);
    }
  }, []);

  // ── Stop replay ───────────────────────────────────────────────────────────
  const stopReplay = useCallback(async () => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/replay/stop`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return; }
      const data = await res.json();
      if (data.status === "stopped" || data.status === "not_running") setReplaying(false);
    } catch (err) {
      console.error("[SentinelWS] Stop replay error:", err);
    }
  }, []);

  // ── Approve event ─────────────────────────────────────────────────────────
  const approveEvent = useCallback(async (eventId: string) => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/events/${eventId}/approve`, { method: "POST" });
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return false; }
      if (res.ok) {
        setEvents((prev) => prev.map((e) => (e.event_id === eventId ? { ...e, status: "approved" } : e)));
      }
      return res.ok;
    } catch (err) {
      console.error("[SentinelWS] Approve error:", err);
      return false;
    }
  }, []);

  // ── Reject event ──────────────────────────────────────────────────────────
  const rejectEvent = useCallback(async (eventId: string) => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/events/${eventId}/reject`, { method: "POST" });
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return false; }
      if (res.ok) {
        setEvents((prev) => prev.map((e) => (e.event_id === eventId ? { ...e, status: "rejected" } : e)));
      }
      return res.ok;
    } catch (err) {
      console.error("[SentinelWS] Reject error:", err);
      return false;
    }
  }, []);

  // ── Investigate ───────────────────────────────────────────────────────────
  const investigateEvent = useCallback(async (eventId: string) => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/events/${eventId}/investigate`, { method: "POST" });
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return false; }
      if (res.ok) {
        setEvents((prev) => prev.map((e) => (e.event_id === eventId ? { ...e, status: "investigating" } : e)));
      }
      return res.ok;
    } catch (err) {
      console.error("[SentinelWS] Investigate error:", err);
      return false;
    }
  }, []);

  // ── False positive ────────────────────────────────────────────────────────
  const markFalsePositive = useCallback(async (eventId: string) => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/events/${eventId}/false_positive`, { method: "POST" });
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return false; }
      if (res.ok) {
        setEvents((prev) => prev.map((e) => (e.event_id === eventId ? { ...e, status: "false_positive" } : e)));
      }
      return res.ok;
    } catch (err) {
      console.error("[SentinelWS] FalsePositive error:", err);
      return false;
    }
  }, []);

  // ── Clear ─────────────────────────────────────────────────────────────────
  const clearEvents = useCallback(() => setEvents([]), []);

  // ── Honeypot start ────────────────────────────────────────────────────────
  const startHoneypot = useCallback(async () => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/honeypot/start`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return; }
      if (res.status === 403) {
        const data = await res.json();
        setAuthError(data.detail || "Research Mode is disabled.");
        return;
      }
      const data = await res.json();
      if (data.status === "started" || data.status === "already_running") setHoneypotRunning(true);
    } catch (err) {
      console.error("[SentinelWS] Start honeypot error:", err);
    }
  }, []);

  // ── Honeypot stop ─────────────────────────────────────────────────────────
  const stopHoneypot = useCallback(async () => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/honeypot/stop`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return; }
      if (res.status === 403) {
        const data = await res.json();
        setAuthError(data.detail || "Research Mode is disabled.");
        return;
      }
      const data = await res.json();
      if (data.status === "stopped" || data.status === "not_running") setHoneypotRunning(false);
    } catch (err) {
      console.error("[SentinelWS] Stop honeypot error:", err);
    }
  }, []);

  // ── Periodic polling for Suricata status when running ─────────────────────
  useEffect(() => {
    if (!suricataRunning) return;
    const interval = setInterval(() => {
      checkSuricataStatus();
    }, 4000);
    return () => clearInterval(interval);
  }, [suricataRunning, checkSuricataStatus]);

  // ── Suricata start ────────────────────────────────────────────────────────
  const startSuricata = useCallback(async (selectedInterface?: string) => {
    setAuthError(null);
    try {
      const url = selectedInterface
        ? `${API_BASE}/suricata/start?interface=${encodeURIComponent(selectedInterface)}`
        : `${API_BASE}/suricata/start`;
      const res = await authedFetch(url);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return; }
      if (res.status === 403) {
        const data = await res.json();
        setAuthError(data.detail || "Research Mode is disabled.");
        return;
      }
      const data = await res.json();
      if (data.status === "started" || data.status === "already_running") {
        setSuricataRunning(true);
        checkSuricataStatus();
      }
    } catch (err) {
      console.error("[SentinelWS] Start suricata error:", err);
    }
  }, [checkSuricataStatus]);

  // ── Suricata stop ─────────────────────────────────────────────────────────
  const stopSuricata = useCallback(async () => {
    setAuthError(null);
    try {
      const res = await authedFetch(`${API_BASE}/suricata/stop`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return; }
      if (res.status === 403) {
        const data = await res.json();
        setAuthError(data.detail || "Research Mode is disabled.");
        return;
      }
      const data = await res.json();
      if (data.status === "stopped" || data.status === "not_running") {
        setSuricataRunning(false);
        checkSuricataStatus();
      }
    } catch (err) {
      console.error("[SentinelWS] Stop suricata error:", err);
    }
  }, [checkSuricataStatus]);



  // ── Periodic polling for Live Traffic Capture status when running ─────────
  useEffect(() => {
    if (!liveCaptureRunning) return;
    const interval = setInterval(() => {
      checkLiveCaptureStatus();
    }, 2500);
    return () => clearInterval(interval);
  }, [liveCaptureRunning, checkLiveCaptureStatus]);

  // ── Live Traffic Capture start ───────────────────────────────────────────
  const startLiveCapture = useCallback(async (selectedInterface?: string, packetLimit = 0, timeLimit = 0) => {
    setAuthError(null);
    setLiveCaptureLoading(true);
    try {
      const params = new URLSearchParams();
      if (selectedInterface) params.set("interface", selectedInterface);
      if (packetLimit > 0) params.set("packet_limit", packetLimit.toString());
      if (timeLimit > 0) params.set("time_limit", timeLimit.toString());
      const query = params.toString() ? `?${params.toString()}` : "";

      const res = await authedFetch(`${API_BASE}/live/start${query}`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return false; }
      if (res.status === 403) {
        const data = await res.json().catch(() => ({}));
        setAuthError(data.detail || "Forbidden — insufficient permissions.");
        return false;
      }
      const data = await res.json();
      if (data.status === "started" || data.status === "already_running") {
        setLiveCaptureRunning(true);
        setLiveCaptureStatus(data);
        checkLiveCaptureStatus();
        return true;
      } else if (data.status === "error") {
        setAuthError(data.detail || "Failed to start live traffic capture");
        return false;
      }
      return false;
    } catch (err) {
      console.error("[SentinelWS] Start live capture error:", err);
      return false;
    } finally {
      setLiveCaptureLoading(false);
    }
  }, [checkLiveCaptureStatus]);

  // ── Live Traffic Capture stop ────────────────────────────────────────────
  const stopLiveCapture = useCallback(async () => {
    setAuthError(null);
    setLiveCaptureLoading(true);
    try {
      const res = await authedFetch(`${API_BASE}/live/stop`);
      if (res.status === 401) { setAuthError("Session expired — please sign in again."); return false; }
      const data = await res.json();
      if (data.status === "stopped" || data.status === "not_running") {
        setLiveCaptureRunning(false);
        setLiveCaptureStatus(data);
        checkLiveCaptureStatus();
        return true;
      }
      return false;
    } catch (err) {
      console.error("[SentinelWS] Stop live capture error:", err);
      return false;
    } finally {
      setLiveCaptureLoading(false);
    }
  }, [checkLiveCaptureStatus]);

  return {
    events,
    connected,
    replaying,
    honeypotRunning,
    suricataRunning,
    suricataStatus,
    liveCaptureRunning,
    liveCaptureStatus,
    liveInterfaces,
    defaultLiveInterface,
    liveCaptureLoading,
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
    startLiveCapture,
    stopLiveCapture,
    fetchInterfaces,
    fetchLiveInterfaces,
    checkSuricataStatus,
    checkLiveCaptureStatus,
    clearEvents,
    approveEvent,
    rejectEvent,
    investigateEvent,
    markFalsePositive,
  };
}
