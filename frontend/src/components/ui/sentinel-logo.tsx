"use client";

import Link from "next/link";
import React from "react";

interface SentinelLogoProps {
  href?: string;
  size?: "sm" | "md" | "lg";
  showBadge?: boolean;
  badgeText?: string;
  className?: string;
  textClassName?: string;
}

export function SentinelLogo({
  href = "/",
  size = "md",
  showBadge = false,
  badgeText = "v2.0",
  className = "",
  textClassName = "",
}: SentinelLogoProps) {
  const iconSize = size === "sm" ? "w-7 h-7" : size === "lg" ? "w-11 h-11" : "w-9 h-9";
  const shieldSize = size === "sm" ? "w-3.5 h-3.5" : size === "lg" ? "w-5 h-5" : "w-4 h-4";
  const textSize = size === "sm" ? "text-base" : size === "lg" ? "text-2xl" : "text-lg";

  return (
    <Link
      href={href}
      className={`group inline-flex items-center gap-2.5 no-underline transition-transform duration-200 hover:scale-[1.02] active:scale-[0.98] ${className}`}
      title="SentinelAI — Back to Home"
    >
      {/* Attractive Shield + AI Core Icon */}
      <div
        className={`relative ${iconSize} rounded-xl bg-gradient-to-br from-indigo-500 via-indigo-600 to-violet-600 flex items-center justify-center shadow-md shadow-indigo-500/25 group-hover:shadow-indigo-500/40 group-hover:from-indigo-400 group-hover:to-cyan-500 transition-all duration-300 ring-1 ring-white/20`}
      >
        {/* Ambient glow behind icon */}
        <div className="absolute inset-0 rounded-xl bg-gradient-to-tr from-cyan-400 to-violet-500 opacity-0 group-hover:opacity-40 blur-sm transition-opacity duration-300" />

        {/* Shield outline */}
        <svg
          className={`${shieldSize} text-white relative z-10 drop-shadow-[0_1px_2px_rgba(0,0,0,0.3)]`}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          {/* AI Neural / Radar Core */}
          <circle cx="12" cy="11" r="2.5" fill="currentColor" opacity="0.9" />
          <path d="M12 8.5v-1.5" stroke="currentColor" strokeWidth="1.5" />
          <path d="M12 15v-1.5" stroke="currentColor" strokeWidth="1.5" />
          <path d="M9.5 11h-1.5" stroke="currentColor" strokeWidth="1.5" />
          <path d="M16 11h-1.5" stroke="currentColor" strokeWidth="1.5" />
        </svg>

        {/* Active Pulse Dot on top right */}
        <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400 ring-1 ring-white/60" />
        </span>
      </div>

      {/* Brand Text */}
      <div className="flex items-center">
        <span
          className={`font-black tracking-tight ${textSize} ${
            textClassName || "text-slate-900 dark:text-white"
          }`}
        >
          Sentinel
          <span className="bg-gradient-to-r from-indigo-500 via-violet-500 to-cyan-400 bg-clip-text text-transparent group-hover:from-cyan-400 group-hover:to-indigo-500 transition-all duration-300">
            AI
          </span>
        </span>

        {showBadge && (
          <span className="ml-2 px-1.5 py-0.5 rounded text-[0.58rem] font-bold tracking-widest uppercase bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800">
            {badgeText}
          </span>
        )}
      </div>
    </Link>
  );
}

