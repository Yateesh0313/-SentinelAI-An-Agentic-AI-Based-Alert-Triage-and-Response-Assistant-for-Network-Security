"use client";

import { useRef, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import dynamic from "next/dynamic";
import { gsap } from "gsap";

const NetworkHero = dynamic(() => import("@/components/home/NetworkHero"), { ssr: false });

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function saveToken(token: string, username: string) {
  localStorage.setItem("sentinel_token", token);
  localStorage.setItem("sentinel_user", username);
}

// ─── Login Page ───────────────────────────────────────────────────────────────
export default function LoginPage() {
  const router = useRouter();
  const cardRef = useRef<HTMLDivElement>(null);
  const logoRef = useRef<HTMLDivElement>(null);

  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Entrance animation
  useEffect(() => {
    const tl = gsap.timeline({ defaults: { ease: "power4.out" } });
    tl.fromTo(logoRef.current, { y: -20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.6 })
      .fromTo(cardRef.current,  { y: 40,  opacity: 0, scale: 0.97 }, { y: 0, opacity: 1, scale: 1, duration: 0.7 }, "-=0.3");
  }, []);

  // Shake card on error
  useEffect(() => {
    if (!error || !cardRef.current) return;
    gsap.fromTo(
      cardRef.current,
      { x: -8 },
      { x: 0, duration: 0.4, ease: "elastic.out(1, 0.4)" }
    );
  }, [error]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    if (!username.trim() || !password.trim()) {
      setError("Username and password are required.");
      return;
    }

    setLoading(true);
    try {
      const endpoint = mode === "login" ? "/auth/login" : "/auth/register";
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data?.detail ?? `Request failed (${res.status})`);
        return;
      }

      if (mode === "register") {
        setSuccess("Account created! Signing you in…");
        // Auto-login after register
        const loginRes = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username.trim(), password }),
        });
        const loginData = await loginRes.json();
        if (loginRes.ok) {
          saveToken(loginData.access_token, loginData.username);
          setTimeout(() => router.push("/dashboard"), 800);
        }
      } else {
        saveToken(data.access_token, data.username);
        // Slide out and navigate
        await gsap.to(cardRef.current, { y: -20, opacity: 0, duration: 0.4, ease: "power3.in" });
        router.push("/dashboard");
      }
    } catch (err) {
      setError("Could not reach the backend. Is the server running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen bg-[#050812] flex items-center justify-center overflow-hidden p-4">

      {/* Background 3D network (muted) */}
      <div className="absolute inset-0 z-0 opacity-40">
        <NetworkHero />
      </div>

      {/* Radial glow */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2
          w-[600px] h-[600px] rounded-full
          bg-gradient-radial from-cyan-500/8 via-violet-600/4 to-transparent blur-3xl" />
      </div>

      <div className="relative z-10 w-full max-w-md">

        {/* Logo */}
        <div ref={logoRef} className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-violet-600
            flex items-center justify-center mb-4 shadow-2xl shadow-cyan-500/30">
            <svg className="w-7 h-7 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clipRule="evenodd"/>
            </svg>
          </div>
          <h1 className="text-2xl font-black tracking-tight text-white">
            Sentinel<span className="text-cyan-400">AI</span>
          </h1>
          <p className="text-slate-500 text-sm mt-1">Agentic Threat Intelligence Platform</p>
        </div>

        {/* Card */}
        <div
          ref={cardRef}
          className="rounded-2xl border border-white/10 bg-slate-900/80 backdrop-blur-xl
            shadow-2xl shadow-black/40 p-8"
        >
          {/* Mode tabs */}
          <div className="flex rounded-xl overflow-hidden border border-slate-700/60 mb-6 bg-slate-950/50">
            {(["login", "register"] as const).map((m) => (
              <button
                key={m}
                id={`tab-${m}`}
                onClick={() => { setMode(m); setError(""); setSuccess(""); }}
                className={`flex-1 py-2.5 text-sm font-semibold capitalize transition-all duration-200
                  ${mode === m
                    ? "bg-gradient-to-r from-cyan-500 to-violet-600 text-white"
                    : "text-slate-500 hover:text-slate-300"}`}
              >
                {m === "login" ? "Sign In" : "Register"}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            {/* Username */}
            <div>
              <label htmlFor="login-username" className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">
                Username
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst@sentinelai"
                className="w-full px-4 py-3 rounded-xl bg-slate-800/60 border border-slate-700/60 text-white
                  placeholder-slate-600 text-sm
                  focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30
                  transition-all duration-200"
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="login-password" className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">
                Password
              </label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-4 py-3 rounded-xl bg-slate-800/60 border border-slate-700/60 text-white
                  placeholder-slate-600 text-sm
                  focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30
                  transition-all duration-200"
              />
              {mode === "register" && (
                <p className="text-xs text-slate-600 mt-1.5">Minimum 6 characters</p>
              )}
            </div>

            {/* Error / Success */}
            {error && (
              <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                <svg className="w-4 h-4 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd"/>
                </svg>
                {error}
              </div>
            )}
            {success && (
              <div className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm">
                <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/>
                </svg>
                {success}
              </div>
            )}

            {/* Submit */}
            <button
              id="login-submit"
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl font-bold text-sm text-white
                bg-gradient-to-r from-cyan-500 to-violet-600
                shadow-lg shadow-cyan-500/20
                hover:shadow-cyan-500/40 hover:scale-[1.01]
                disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100
                transition-all duration-200 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>
                  {mode === "login" ? "Signing in…" : "Creating account…"}
                </>
              ) : (
                mode === "login" ? "Sign In to Dashboard" : "Create Account"
              )}
            </button>
          </form>

          {/* Security note */}
          <div className="flex items-center justify-center gap-1.5 mt-6 text-xs text-slate-600">
            <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd"/>
            </svg>
            Secured with JWT · bcrypt · HTTPS-ready
          </div>
        </div>

        {/* Back link */}
        <div className="text-center mt-6">
          <a href="/" className="text-sm text-slate-600 hover:text-slate-400 transition-colors">
            ← Back to homepage
          </a>
        </div>
      </div>
    </div>
  );
}
