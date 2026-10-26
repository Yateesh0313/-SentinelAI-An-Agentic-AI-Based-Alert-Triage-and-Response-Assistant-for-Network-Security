"use client";

import { useEffect, useRef, useState, Suspense } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Shield,
  Brain,
  Radar,
  Network,
  ArrowRight,
  CheckCircle2,
  Zap,
  Eye,
  Lock,
  ChevronDown,
} from "lucide-react";

// ─── Lazy-load 3D Globe ────────────────────────────────────────────────────────
const GlobeScene = dynamic(
  () => import("@/components/three/GlobeScene"),
  {
    ssr: false,
    loading: () => (
      <div className="w-full h-full flex items-center justify-center">
        <div className="w-64 h-64 rounded-full bg-gradient-to-br from-indigo-50 to-cyan-50 animate-pulse" />
      </div>
    ),
  }
);

// ─── Types ─────────────────────────────────────────────────────────────────────
interface StatItem { value: string; label: string; suffix?: string }
interface Feature { icon: React.ReactNode; title: string; desc: string; color: string }

// ─── Data ──────────────────────────────────────────────────────────────────────
const STATS: StatItem[] = [
  { value: "< 2", label: "Avg. Triage Time", suffix: "sec" },
  { value: "99.1", label: "Detection Accuracy", suffix: "%" },
  { value: "24/7", label: "Autonomous Coverage" },
  { value: "3", label: "AI Agent Pipeline", suffix: "nodes" },
];

const FEATURES: Feature[] = [
  {
    icon: <Radar className="w-6 h-6" />,
    title: "Live Threat Detection",
    desc: "ML model + YARA signatures detect intrusions the moment packets arrive. Suricata IDS and honeypot sensors feed real alerts into the pipeline.",
    color: "text-red-500 bg-red-50 border-red-100",
  },
  {
    icon: <Brain className="w-6 h-6" />,
    title: "AI-Powered Triage",
    desc: "Three LLM agents classify severity, map to MITRE ATT&CK techniques, and recommend response actions — all in under 2 seconds.",
    color: "text-indigo-500 bg-indigo-50 border-indigo-100",
  },
  {
    icon: <Eye className="w-6 h-6" />,
    title: "Plain-English Explanations",
    desc: "Every alert comes with What happened, Why it matters, and What we recommend — written for humans, not just security engineers.",
    color: "text-cyan-500 bg-cyan-50 border-cyan-100",
  },
  {
    icon: <Lock className="w-6 h-6" />,
    title: "Human-in-the-Loop Approval",
    desc: "No action executes without analyst approval. Approve, reject, investigate, or mark false-positive with full audit trail.",
    color: "text-emerald-500 bg-emerald-50 border-emerald-100",
  },
];

const PIPELINE_STEPS = [
  {
    step: "01",
    title: "Capture",
    desc: "Live network traffic from Suricata IDS, honeypot listeners, and Scapy packet capture flows into the detection engine.",
    color: "border-cyan-200 bg-cyan-50/50",
    textColor: "text-cyan-600",
  },
  {
    step: "02",
    title: "Detect",
    desc: "XGBoost ML model classifies each event. YARA rules scan for known-bad patterns. Both signals run in parallel.",
    color: "border-indigo-200 bg-indigo-50/50",
    textColor: "text-indigo-600",
  },
  {
    step: "03",
    title: "Triage",
    desc: "LangGraph multi-agent pipeline: Triage → Severity → Response. Each node produces structured JSON with ATT&CK mappings.",
    color: "border-violet-200 bg-violet-50/50",
    textColor: "text-violet-600",
  },
  {
    step: "04",
    title: "Respond",
    desc: "Human analyst reviews the recommendation on the dashboard. One click to approve, reject, or investigate further.",
    color: "border-emerald-200 bg-emerald-50/50",
    textColor: "text-emerald-600",
  },
];

// ─── Animation variants ───────────────────────────────────────────────────────
const fadeUp = {
  hidden: { opacity: 0, y: 30 },
  visible: (i: number = 0) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.1, duration: 0.6, ease: [0.33, 1, 0.68, 1] as [number, number, number, number] },
  }),
};

const stagger = {
  visible: { transition: { staggerChildren: 0.12 } },
};

// ─── Stat Counter with count-up ───────────────────────────────────────────────
function StatCounter({ stat, index }: { stat: StatItem; index: number }) {
  return (
    <motion.div
      variants={fadeUp}
      custom={index}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-50px" }}
      className="flex flex-col items-center gap-1 p-6"
    >
      <div className="flex items-baseline gap-1">
        <span className="text-4xl md:text-5xl font-black tracking-tight text-foreground">
          {stat.value}
        </span>
        {stat.suffix && (
          <span className="text-lg font-semibold text-muted-foreground">
            {stat.suffix}
          </span>
        )}
      </div>
      <span className="text-sm text-muted-foreground font-medium uppercase tracking-widest mt-1">
        {stat.label}
      </span>
    </motion.div>
  );
}

// ─── Feature Card ─────────────────────────────────────────────────────────────
function FeatureCard({ feature, index }: { feature: Feature; index: number }) {
  const colorParts = feature.color.split(" ");

  return (
    <motion.div
      variants={fadeUp}
      custom={index}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-50px" }}
      className="group relative rounded-2xl border border-border bg-white p-6 flex flex-col gap-4
        shadow-sm hover:shadow-lg hover:-translate-y-1 transition-all duration-300"
    >
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center border ${colorParts.slice(1).join(" ")}`}>
        <div className={colorParts[0]}>{feature.icon}</div>
      </div>
      <h3 className="text-lg font-bold text-foreground">{feature.title}</h3>
      <p className="text-sm text-muted-foreground leading-relaxed">{feature.desc}</p>
    </motion.div>
  );
}

// ─── Main Landing Page ────────────────────────────────────────────────────────
export default function HomePage() {
  return (
    <div className="min-h-screen gradient-mesh-bg overflow-x-hidden">

      {/* ── Navbar ───────────────────────────────────────────────────────── */}
      <motion.nav
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="fixed top-0 inset-x-0 z-50 flex items-center justify-between px-6 md:px-12 py-4
          bg-white/70 backdrop-blur-xl border-b border-border/50"
      >
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-black text-lg tracking-tight text-foreground">
            Sentinel<span className="gradient-text">AI</span>
          </span>
        </div>

        <div className="hidden md:flex items-center gap-8 text-sm text-muted-foreground font-medium">
          <a href="#features" className="hover:text-foreground transition-colors">Features</a>
          <a href="#pipeline" className="hover:text-foreground transition-colors">Architecture</a>
          <a href="#stats" className="hover:text-foreground transition-colors">Metrics</a>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/login"
            className="px-4 py-2 text-sm font-semibold text-muted-foreground hover:text-foreground transition-colors"
          >
            Sign In
          </Link>
          <Link
            href="/login"
            id="hero-cta-nav"
            className="btn-gradient px-5 py-2 text-sm font-bold rounded-xl"
          >
            Launch Dashboard
          </Link>
        </div>
      </motion.nav>

      {/* ── Hero Section with 3D Globe ───────────────────────────────────── */}
      <section className="relative min-h-screen flex items-center overflow-hidden pt-20">
        <div className="max-w-7xl mx-auto px-6 w-full grid lg:grid-cols-2 gap-12 items-center">
          {/* Left: Text content */}
          <div className="relative z-10">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2, duration: 0.5 }}
              className="inline-flex items-center gap-2 px-4 py-1.5 mb-6
                rounded-full border border-indigo-200 bg-indigo-50 text-indigo-600
                text-xs font-semibold uppercase tracking-widest"
            >
              <Zap className="w-3 h-3" />
              Agentic AI — Threat Detection & Response
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.35, duration: 0.7, ease: [0.33, 1, 0.68, 1] }}
              className="text-5xl md:text-6xl lg:text-7xl font-black tracking-tight leading-[1.05] mb-6 text-foreground"
            >
              Stop Threats
              <br />
              <span className="gradient-text">Before They Start</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5, duration: 0.6 }}
              className="text-lg md:text-xl text-muted-foreground max-w-lg mb-10 leading-relaxed"
            >
              SentinelAI autonomously triages every security alert with a
              multi-agent pipeline — ML detection, ATT&CK mapping, and
              analyst-in-the-loop approval in under 2 seconds.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.65, duration: 0.5 }}
              className="flex flex-col sm:flex-row items-start gap-4"
            >
              <Link
                href="/login"
                id="hero-cta-primary"
                className="group flex items-center gap-2 btn-gradient px-8 py-3.5 rounded-xl font-bold text-base"
              >
                Launch Dashboard
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </Link>
              <a
                href="#features"
                className="flex items-center gap-2 px-8 py-3.5 rounded-xl font-bold text-base
                  border border-border text-foreground bg-white/60 backdrop-blur
                  hover:bg-white hover:shadow-md transition-all duration-200"
              >
                Explore Features
                <ChevronDown className="w-4 h-4" />
              </a>
            </motion.div>
          </div>

          {/* Right: 3D Globe */}
          <motion.div
            initial={{ opacity: 0, scale: 0.85 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.4, duration: 0.8, ease: [0.33, 1, 0.68, 1] }}
            className="relative h-[400px] md:h-[500px] lg:h-[560px]"
          >
            <Suspense
              fallback={
                <div className="w-full h-full flex items-center justify-center">
                  <div className="w-64 h-64 rounded-full bg-gradient-to-br from-indigo-50 to-cyan-50 animate-pulse" />
                </div>
              }
            >
              <GlobeScene className="w-full h-full" />
            </Suspense>

            {/* Floating stat badges around globe */}
            <div className="absolute top-8 left-4 glass-card rounded-xl px-4 py-2.5 animate-[float_4s_ease-in-out_infinite]">
              <div className="text-xs font-bold text-red-500 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-red-500 status-dot-live" />
                Critical Alert
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">T1046 — Network Scan</div>
            </div>

            <div className="absolute bottom-12 right-4 glass-card rounded-xl px-4 py-2.5 animate-[float_5s_ease-in-out_infinite_0.5s]">
              <div className="text-xs font-bold text-emerald-500 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Threat Blocked
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">Response time: 1.8s</div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── Stats Bar ──────────────────────────────────────────────────── */}
      <section id="stats" className="py-16 border-y border-border/50 bg-white/40 backdrop-blur-sm">
        <motion.div
          variants={stagger}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-6"
        >
          {STATS.map((s, i) => <StatCounter key={s.label} stat={s} index={i} />)}
        </motion.div>
        <p className="text-center text-xs text-muted-foreground mt-4">
          *Benchmarked on KDDTest+ dataset with current model configuration
        </p>
      </section>

      {/* ── Features Grid ──────────────────────────────────────────────── */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <div className="inline-block px-4 py-1.5 mb-4 rounded-full border border-violet-200
              bg-violet-50 text-violet-600 text-xs font-semibold uppercase tracking-widest">
              Capabilities
            </div>
            <h2 className="text-4xl md:text-5xl font-black tracking-tight mb-4 text-foreground">
              Everything you need to{" "}
              <span className="gradient-text">stay ahead</span>
            </h2>
            <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
              A fully agentic pipeline — from raw packet to analyst decision — with no manual configuration.
            </p>
          </motion.div>

          <motion.div
            variants={stagger}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5"
          >
            {FEATURES.map((f, i) => <FeatureCard key={f.title} feature={f} index={i} />)}
          </motion.div>
        </div>
      </section>

      {/* ── Architecture Pipeline ──────────────────────────────────────── */}
      <section id="pipeline" className="py-24 px-6 bg-white/30 backdrop-blur-sm border-y border-border/50">
        <div className="max-w-6xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <div className="inline-block px-4 py-1.5 mb-4 rounded-full border border-cyan-200
              bg-cyan-50 text-cyan-600 text-xs font-semibold uppercase tracking-widest">
              Architecture
            </div>
            <h2 className="text-4xl md:text-5xl font-black tracking-tight mb-4 text-foreground">
              From packet to{" "}
              <span className="gradient-text">decision</span>
              {" "}in real time
            </h2>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-5">
            {PIPELINE_STEPS.map((item, i) => (
              <motion.div
                key={item.step}
                variants={fadeUp}
                custom={i}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true }}
                className={`rounded-2xl border p-6 ${item.color} hover:shadow-lg hover:-translate-y-1 transition-all duration-300`}
              >
                <span className={`text-3xl font-black ${item.textColor} opacity-60`}>{item.step}</span>
                <h3 className="text-lg font-bold text-foreground mt-3 mb-2">{item.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{item.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA Banner ─────────────────────────────────────────────────── */}
      <section className="py-24 px-6">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.7 }}
          className="max-w-4xl mx-auto"
        >
          <div className="relative rounded-3xl overflow-hidden border border-indigo-100 p-12 md:p-16
            bg-gradient-to-br from-white via-indigo-50/50 to-cyan-50/30 shadow-xl shadow-indigo-500/5">
            {/* Subtle glow */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-32
              bg-gradient-to-b from-indigo-200/30 to-transparent blur-3xl pointer-events-none" />

            <div className="relative z-10 text-center">
              <h2 className="text-4xl md:text-5xl font-black tracking-tight mb-4 text-foreground">
                Ready to eliminate{" "}
                <span className="gradient-text">alert fatigue?</span>
              </h2>
              <p className="text-muted-foreground text-lg mb-8 max-w-xl mx-auto">
                Sign in to your SentinelAI dashboard and let the AI agents work for you.
              </p>
              <Link
                href="/login"
                id="hero-cta-bottom"
                className="group inline-flex items-center gap-2 btn-gradient px-10 py-4 rounded-xl font-bold text-base"
              >
                Get Started Now
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </Link>
            </div>
          </div>
        </motion.div>
      </section>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <footer className="border-t border-border/50 py-10 px-6 bg-white/30 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-lg bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center">
              <Shield className="w-3 h-3 text-white" />
            </div>
            <span className="font-bold text-sm text-foreground">
              Sentinel<span className="gradient-text">AI</span>
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            Agentic AI Alert Triage & Response · Built with FastAPI, LangGraph & Next.js
          </p>
        </div>
      </footer>
    </div>
  );
}
