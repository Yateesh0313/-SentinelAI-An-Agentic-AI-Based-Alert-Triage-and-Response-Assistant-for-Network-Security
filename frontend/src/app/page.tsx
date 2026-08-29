"use client";

import { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import Image from "next/image";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

// ─── Lazy-load 3D canvas (avoids SSR issues with WebGL) ───────────────────────
const NetworkHero = dynamic(() => import("@/components/home/NetworkHero"), {
  ssr: false,
  loading: () => <div className="w-full h-full bg-transparent" />,
});

if (typeof window !== "undefined") {
  gsap.registerPlugin(ScrollTrigger);
}

// ─── Types ────────────────────────────────────────────────────────────────────
interface StatItem { value: string; label: string; color: string }
interface Feature { icon: string; title: string; desc: string; accent: string }

const STATS: StatItem[] = [
  { value: "< 2s",  label: "Avg. Triage Time",    color: "text-cyan-400" },
  { value: "99.1%", label: "Detection Accuracy",  color: "text-violet-400" },
  { value: "24/7",  label: "Autonomous Coverage", color: "text-cyan-400" },
  { value: "0",     label: "False Positives*",    color: "text-emerald-400" },
];

const FEATURES: Feature[] = [
  {
    icon: "/images/feature-shield.svg",
    title: "Autonomous Triage",
    desc: "AI agents classify, score, and prioritize every alert in real-time — no analyst fatigue, no alert blindness.",
    accent: "cyan",
  },
  {
    icon: "/images/feature-radar.svg",
    title: "Live Threat Detection",
    desc: "KDDCup99 ML model + YARA signatures catch intrusions the moment they appear across all network layers.",
    accent: "red",
  },
  {
    icon: "/images/feature-brain.svg",
    title: "ATT&CK Mapping",
    desc: "Every event is automatically mapped to MITRE ATT&CK techniques and enriched with geolocation and abuse data.",
    accent: "violet",
  },
  {
    icon: "/images/feature-network.svg",
    title: "Honeypot Intelligence",
    desc: "Decoy listeners capture real adversarial probes and feed them into the triage pipeline automatically.",
    accent: "emerald",
  },
];

// ─── Animated Counter ─────────────────────────────────────────────────────────
function StatCounter({ stat }: { stat: StatItem }) {
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    gsap.fromTo(
      ref.current,
      { opacity: 0, y: 20 },
      {
        opacity: 1,
        y: 0,
        duration: 0.8,
        ease: "power3.out",
        scrollTrigger: { trigger: ref.current, start: "top 85%" },
      }
    );
  }, []);
  return (
    <div className="flex flex-col items-center gap-1">
      <span ref={ref} className={`text-4xl md:text-5xl font-black tracking-tight ${stat.color}`}>
        {stat.value}
      </span>
      <span className="text-sm text-slate-400 font-medium uppercase tracking-widest">
        {stat.label}
      </span>
    </div>
  );
}

// ─── Feature Card ─────────────────────────────────────────────────────────────
const accentMap: Record<string, string> = {
  cyan:    "border-cyan-500/30 hover:border-cyan-500/70 hover:shadow-cyan-500/10",
  red:     "border-red-500/30  hover:border-red-500/70  hover:shadow-red-500/10",
  violet:  "border-violet-500/30 hover:border-violet-500/70 hover:shadow-violet-500/10",
  emerald: "border-emerald-500/30 hover:border-emerald-500/70 hover:shadow-emerald-500/10",
};
const iconBgMap: Record<string, string> = {
  cyan:    "bg-cyan-500/10",
  red:     "bg-red-500/10",
  violet:  "bg-violet-500/10",
  emerald: "bg-emerald-500/10",
};

function FeatureCard({ feature, idx }: { feature: Feature; idx: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    gsap.fromTo(
      ref.current,
      { opacity: 0, y: 40 },
      {
        opacity: 1,
        y: 0,
        duration: 0.7,
        delay: idx * 0.12,
        ease: "power3.out",
        scrollTrigger: { trigger: ref.current, start: "top 88%" },
      }
    );
  }, [idx]);

  return (
    <div
      ref={ref}
      className={`group relative rounded-2xl border bg-slate-900/50 backdrop-blur-sm p-6 flex flex-col gap-4
        transition-all duration-300 hover:shadow-xl hover:-translate-y-1
        ${accentMap[feature.accent]}`}
    >
      {/* Subtle gradient shine on hover */}
      <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500
        bg-gradient-to-br from-white/[0.03] to-transparent pointer-events-none" />

      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${iconBgMap[feature.accent]}`}>
        <Image src={feature.icon} alt={feature.title} width={28} height={28} className="opacity-90" />
      </div>
      <h3 className="text-lg font-bold text-white">{feature.title}</h3>
      <p className="text-sm text-slate-400 leading-relaxed">{feature.desc}</p>
    </div>
  );
}

// ─── Typed terminal animation ─────────────────────────────────────────────────
const TERMINAL_LINES = [
  { text: "$ sentinel --monitor --live", color: "text-cyan-400" },
  { text: "[INFO] Connecting to threat pipeline...", color: "text-slate-400" },
  { text: "[ALERT] Intrusion detected: 185.220.101.47", color: "text-red-400" },
  { text: "[ML] Prediction: anomaly (confidence: 97.3%)", color: "text-yellow-400" },
  { text: "[ATT&CK] T1046 - Network Service Scanning", color: "text-violet-400" },
  { text: "[RESPONSE] Action: block_ip + alert_analyst", color: "text-emerald-400" },
  { text: "[DONE] Event triaged in 1.8s", color: "text-cyan-400" },
];

function TerminalWindow() {
  const [visibleLines, setVisibleLines] = useState(0);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const trigger = ScrollTrigger.create({
      trigger: ref.current,
      start: "top 80%",
      onEnter: () => {
        let i = 0;
        const interval = setInterval(() => {
          setVisibleLines((v) => v + 1);
          i++;
          if (i >= TERMINAL_LINES.length) clearInterval(interval);
        }, 320);
      },
      once: true,
    });
    return () => trigger.kill();
  }, []);

  return (
    <div
      ref={ref}
      className="rounded-2xl border border-slate-700/60 bg-slate-950/80 backdrop-blur overflow-hidden shadow-2xl shadow-black/40"
    >
      {/* Title bar */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700/60 bg-slate-900/60">
        <span className="w-3 h-3 rounded-full bg-red-500/80" />
        <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
        <span className="w-3 h-3 rounded-full bg-green-500/80" />
        <span className="ml-3 text-xs text-slate-500 font-mono">sentinel-ai — triage-pipeline</span>
      </div>
      {/* Content */}
      <div className="p-5 font-mono text-sm space-y-1.5 min-h-[200px]">
        {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
          <div key={i} className={`${line.color} leading-relaxed`}>
            {line.text}
            {i === visibleLines - 1 && (
              <span className="ml-0.5 inline-block w-2 h-4 bg-cyan-400 animate-pulse align-text-bottom" />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main Homepage ────────────────────────────────────────────────────────────
export default function HomePage() {
  const heroRef   = useRef<HTMLDivElement>(null);
  const headRef   = useRef<HTMLHeadingElement>(null);
  const subRef    = useRef<HTMLParagraphElement>(null);
  const ctaRef    = useRef<HTMLDivElement>(null);
  const navRef    = useRef<HTMLElement>(null);
  const badgeRef  = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Hero entrance animation
    const tl = gsap.timeline({ defaults: { ease: "power4.out" } });
    tl.fromTo(navRef.current, { y: -30, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7 })
      .fromTo(badgeRef.current, { scale: 0.8, opacity: 0 }, { scale: 1, opacity: 1, duration: 0.5 }, "-=0.3")
      .fromTo(headRef.current, { y: 60, opacity: 0 }, { y: 0, opacity: 1, duration: 0.9 }, "-=0.2")
      .fromTo(subRef.current, { y: 40, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7 }, "-=0.5")
      .fromTo(ctaRef.current, { y: 30, opacity: 0 }, { y: 0, opacity: 1, duration: 0.6 }, "-=0.4");

    return () => { tl.kill(); ScrollTrigger.getAll().forEach((t) => t.kill()); };
  }, []);

  return (
    <div className="min-h-screen bg-[#050812] text-white overflow-x-hidden">

      {/* ── Navbar ───────────────────────────────────────────────────────── */}
      <nav
        ref={navRef}
        className="fixed top-0 inset-x-0 z-50 flex items-center justify-between px-6 md:px-12 py-4
          bg-[#050812]/80 backdrop-blur-md border-b border-white/5"
      >
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center">
            <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clipRule="evenodd"/>
            </svg>
          </div>
          <span className="font-black text-lg tracking-tight">
            Sentinel<span className="text-cyan-400">AI</span>
          </span>
        </div>
        <div className="hidden md:flex items-center gap-8 text-sm text-slate-400 font-medium">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#how-it-works" className="hover:text-white transition-colors">How It Works</a>
          <a href="#stats" className="hover:text-white transition-colors">Metrics</a>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/login"
            className="px-4 py-1.5 text-sm font-semibold text-slate-300 hover:text-white transition-colors"
          >
            Sign In
          </Link>
          <Link
            href="/login"
            id="hero-cta-nav"
            className="px-4 py-1.5 text-sm font-semibold rounded-lg
              bg-gradient-to-r from-cyan-500 to-violet-600 text-white
              hover:shadow-lg hover:shadow-cyan-500/25 transition-all duration-200"
          >
            Launch Dashboard
          </Link>
        </div>
      </nav>

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section ref={heroRef} className="relative min-h-screen flex items-center justify-center overflow-hidden pt-20">

        {/* 3D canvas background */}
        <div className="absolute inset-0 z-0">
          <NetworkHero />
        </div>

        {/* Radial glow */}
        <div className="absolute inset-0 z-0 pointer-events-none">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2
            w-[700px] h-[500px] rounded-full
            bg-gradient-radial from-cyan-500/10 via-violet-600/5 to-transparent blur-3xl" />
        </div>

        {/* Hero text */}
        <div className="relative z-10 text-center px-6 max-w-5xl mx-auto">
          <div ref={badgeRef} className="inline-flex items-center gap-2 px-3 py-1 mb-6
            rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-xs font-semibold uppercase tracking-widest">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            Agentic AI — Threat Detection &amp; Response
          </div>

          <h1
            ref={headRef}
            className="text-5xl md:text-7xl lg:text-8xl font-black tracking-tight leading-[1.05] mb-6"
          >
            Stop Threats
            <br />
            <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-violet-500 bg-clip-text text-transparent">
              Before They Start
            </span>
          </h1>

          <p
            ref={subRef}
            className="text-lg md:text-xl text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            SentinelAI autonomously triages every security alert with a multi-agent pipeline —
            ML detection, ATT&amp;CK mapping, and analyst-in-the-loop approval in under 2 seconds.
          </p>

          <div ref={ctaRef} className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/login"
              id="hero-cta-primary"
              className="group flex items-center gap-2 px-8 py-3.5 rounded-xl font-bold text-base
                bg-gradient-to-r from-cyan-500 to-violet-600 text-white
                shadow-lg shadow-cyan-500/20
                hover:shadow-cyan-500/40 hover:scale-[1.03]
                transition-all duration-200"
            >
              Launch Dashboard
              <svg className="w-4 h-4 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </Link>
            <a
              href="#features"
              className="flex items-center gap-2 px-8 py-3.5 rounded-xl font-bold text-base
                border border-slate-600/60 text-slate-300 bg-slate-900/40 backdrop-blur
                hover:border-slate-400/60 hover:text-white hover:bg-slate-800/60
                transition-all duration-200"
            >
              Explore Features
            </a>
          </div>
        </div>

        {/* Scroll indicator */}
        <div className="absolute bottom-8 left-1/2 -translate-x-1/2 z-10 flex flex-col items-center gap-2 opacity-50">
          <span className="text-xs text-slate-500 uppercase tracking-widest">Scroll</span>
          <div className="w-px h-10 bg-gradient-to-b from-slate-500 to-transparent animate-pulse" />
        </div>
      </section>

      {/* ── Stats ─────────────────────────────────────────────────────────── */}
      <section id="stats" className="py-20 border-y border-white/5 bg-slate-900/30">
        <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-10">
          {STATS.map((s) => <StatCounter key={s.label} stat={s} />)}
        </div>
        <p className="text-center text-xs text-slate-600 mt-6">*On KDDTest+ benchmark with current model config</p>
      </section>

      {/* ── Features ─────────────────────────────────────────────────────── */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <div className="inline-block px-3 py-1 mb-4 rounded-full border border-violet-500/30
              bg-violet-500/10 text-violet-400 text-xs font-semibold uppercase tracking-widest">
              Capabilities
            </div>
            <h2 className="text-4xl md:text-5xl font-black tracking-tight mb-4">
              Everything you need to{" "}
              <span className="bg-gradient-to-r from-cyan-400 to-violet-500 bg-clip-text text-transparent">
                stay ahead
              </span>
            </h2>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto">
              A fully agentic pipeline — from raw packet to analyst decision — with no manual configuration.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {FEATURES.map((f, i) => <FeatureCard key={f.title} feature={f} idx={i} />)}
          </div>
        </div>
      </section>

      {/* ── How It Works ─────────────────────────────────────────────────── */}
      <section id="how-it-works" className="py-24 px-6 bg-slate-900/30">
        <div className="max-w-6xl mx-auto grid md:grid-cols-2 gap-16 items-center">
          <div>
            <div className="inline-block px-3 py-1 mb-4 rounded-full border border-cyan-500/30
              bg-cyan-500/10 text-cyan-400 text-xs font-semibold uppercase tracking-widest">
              How It Works
            </div>
            <h2 className="text-4xl md:text-5xl font-black tracking-tight mb-6">
              From packet to{" "}
              <span className="text-cyan-400">decision</span>
              {" "}in real time
            </h2>
            <div className="space-y-6">
              {[
                { step: "01", title: "Detect", desc: "ML model classifies network events. YARA signatures match patterns. Honeypot captures active probes.", color: "text-cyan-400 border-cyan-500/30" },
                { step: "02", title: "Triage", desc: "LLM agent maps to MITRE ATT&CK, assigns severity (Critical→Low), and drafts a recommended response.", color: "text-violet-400 border-violet-500/30" },
                { step: "03", title: "Respond", desc: "Analyst approves or rejects via dashboard. Executed actions are recorded with full audit trail.", color: "text-emerald-400 border-emerald-500/30" },
              ].map((item) => (
                <div key={item.step} className={`flex gap-4 p-4 rounded-xl border bg-slate-900/50 ${item.color.split(" ")[1]}`}>
                  <span className={`text-2xl font-black shrink-0 ${item.color.split(" ")[0]}`}>{item.step}</span>
                  <div>
                    <div className="font-bold text-white mb-1">{item.title}</div>
                    <div className="text-sm text-slate-400">{item.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div>
            <TerminalWindow />
          </div>
        </div>
      </section>

      {/* ── CTA Banner ───────────────────────────────────────────────────── */}
      <section className="py-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="relative rounded-3xl overflow-hidden border border-cyan-500/20 p-12
            bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950">
            {/* Glow effect */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-32
              bg-gradient-to-b from-cyan-500/20 to-transparent blur-2xl pointer-events-none" />
            <div className="relative z-10">
              <h2 className="text-4xl md:text-5xl font-black tracking-tight mb-4">
                Ready to eliminate{" "}
                <span className="bg-gradient-to-r from-cyan-400 to-violet-500 bg-clip-text text-transparent">
                  alert fatigue?
                </span>
              </h2>
              <p className="text-slate-400 text-lg mb-8 max-w-xl mx-auto">
                Sign in to your SentinelAI dashboard and let the agents work for you.
              </p>
              <Link
                href="/login"
                id="hero-cta-bottom"
                className="inline-flex items-center gap-2 px-10 py-4 rounded-xl font-bold text-base
                  bg-gradient-to-r from-cyan-500 to-violet-600 text-white
                  shadow-2xl shadow-cyan-500/30
                  hover:shadow-cyan-500/50 hover:scale-[1.03]
                  transition-all duration-200"
              >
                Get Started Now
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                </svg>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer className="border-t border-white/5 py-8 px-6 text-center">
        <div className="flex items-center justify-center gap-2 mb-3">
          <div className="w-5 h-5 rounded bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center">
            <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clipRule="evenodd"/>
            </svg>
          </div>
          <span className="font-bold text-sm">Sentinel<span className="text-cyan-400">AI</span></span>
        </div>
        <p className="text-xs text-slate-600">
          Agentic AI Alert Triage &amp; Response · Built with FastAPI, Next.js, React Three Fiber
        </p>
      </footer>
    </div>
  );
}
