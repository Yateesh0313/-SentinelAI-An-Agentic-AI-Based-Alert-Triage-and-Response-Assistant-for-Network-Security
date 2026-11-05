"use client";

import { useTheme } from "@/context/ThemeContext";
import { Sun, Moon } from "lucide-react";

export function ThemeToggle({ className }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      type="button"
      onClick={toggleTheme}
      title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
      className={`relative inline-flex items-center justify-center w-9 h-9 rounded-xl border
        transition-all duration-300 hover:scale-105 active:scale-95
        ${
          theme === "dark"
            ? "bg-slate-800 border-slate-600 text-amber-400 hover:bg-slate-700 shadow-lg shadow-slate-900/30"
            : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50 shadow-sm"
        }
        ${className ?? ""}`}
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
    >
      {theme === "dark" ? (
        <Sun className="w-4 h-4" />
      ) : (
        <Moon className="w-4 h-4" />
      )}
    </button>
  );
}

