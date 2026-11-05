"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import { Shield, Eye, EyeOff, ArrowRight, AlertCircle, Lock, Fingerprint, Cpu, ArrowLeft } from "lucide-react";
import dynamic from "next/dynamic";
import { SentinelLogo } from "@/components/ui/sentinel-logo";
import { ThemeToggle } from "@/components/ui/theme-toggle";

const CyberBackground = dynamic(
  () => import("@/components/three/CyberBackground"),
  { ssr: false }
);

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ── Auth helpers ─────────────────────────────────────────────────────────────
function saveToken(token: string, username: string) {
  localStorage.setItem("sentinel_token", token);
  localStorage.setItem("sentinel_user", username);
}

// ── Floating Security Badge ──────────────────────────────────────────────────
function SecurityBadge({
  icon,
  label,
  delay,
  className,
}: {
  icon: React.ReactNode;
  label: string;
  delay: number;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.6 }}
      className={`floating-badge-dark flex items-center gap-2 text-xs font-medium text-gray-300 ${className ?? ""}`}
    >
      {icon}
      {label}
    </motion.div>
  );
}

// ── Login Page ───────────────────────────────────────────────────────────────
export default function LoginPage() {
  const router = useRouter();

  // Registration is admin-only (via API). Login page is sign-in only.
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [shaking, setShaking] = useState(false);

  // Shake card on error
  useEffect(() => {
    if (!error) return;
    setShaking(true);
    const timer = setTimeout(() => setShaking(false), 500);
    return () => clearTimeout(timer);
  }, [error]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!username.trim() || !password.trim()) {
      setError("Username and password are required.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || "Invalid username or password.");
        return;
      }

      saveToken(data.access_token, data.username);
      router.push("/dashboard");
    } catch {
      setError("Cannot reach the server. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center p-6 overflow-hidden">
      {/* ── 3D Cyber Background ────────────────────────────────────────── */}
      <CyberBackground className="absolute inset-0 z-0" />

      {/* Dark overlay for readability */}
      <div className="absolute inset-0 z-[1] bg-black/20 pointer-events-none" />

      {/* Top bar with back to home and theme toggle */}
      <div className="absolute top-6 left-6 right-6 z-20 flex items-center justify-between">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-300 hover:text-white px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 backdrop-blur-sm border border-white/10 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Home
        </Link>
        <ThemeToggle />
      </div>

      {/* ── Login Card ─────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5 }}
        className="relative z-10 w-full max-w-md"
      >
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <SentinelLogo href="/" size="lg" textClassName="text-white" showBadge badgeText="SECURE" />
        </div>

        {/* Card */}
        <div
          className={`glass-card-dark rounded-2xl p-8 shadow-2xl
            ${shaking ? "animate-[shakeX_0.4s_ease]" : ""}`}
        >
          <div className="text-center mb-6">
            <h1 className="text-2xl font-black text-white mb-1">
              Welcome back
            </h1>
            <p className="text-sm text-gray-400">
              Sign in to access your security dashboard
            </p>
          </div>

          {/* Error messages */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-2 px-4 py-3 mb-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm"
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </motion.div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-gray-300 mb-1.5">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst"
                autoComplete="username"
                className="w-full px-4 py-3 rounded-xl input-dark text-sm"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-300 mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  className="w-full px-4 py-3 pr-12 rounded-xl input-dark text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-gradient py-3 rounded-xl font-bold text-sm
                disabled:opacity-50 disabled:cursor-not-allowed
                flex items-center justify-center gap-2"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  Sign In
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        </div>

        {/* Back to landing */}
        <div className="text-center mt-6">
          <Link
            href="/"
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            &larr; Back to SentinelAI
          </Link>
        </div>
      </motion.div>

      {/* ── Floating Security Badges ───────────────────────────────────── */}
      <div className="hidden md:block">
        <SecurityBadge
          icon={<Lock className="w-3.5 h-3.5 text-emerald-400" />}
          label="AES-256 Encrypted"
          delay={1.0}
          className="absolute bottom-12 left-12 z-10"
        />
        <SecurityBadge
          icon={<Cpu className="w-3.5 h-3.5 text-cyan-400" />}
          label="Multi-Agent AI Pipeline"
          delay={1.2}
          className="absolute top-24 right-12 z-10"
        />
        <SecurityBadge
          icon={<Fingerprint className="w-3.5 h-3.5 text-violet-400" />}
          label="99.1% Detection Accuracy"
          delay={1.4}
          className="absolute bottom-24 right-16 z-10"
        />
        <SecurityBadge
          icon={<Shield className="w-3.5 h-3.5 text-indigo-400" />}
          label="MITRE ATT&CK Mapped"
          delay={1.6}
          className="absolute top-32 left-16 z-10"
        />
      </div>
    </div>
  );
}
