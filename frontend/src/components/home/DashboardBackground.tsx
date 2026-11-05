"use client";

import { useEffect, useRef, useState } from "react";

interface Particle {
  x: number; y: number;
  vx: number; vy: number;
  r: number;
  alpha: number;
  color: string;
  isThreat: boolean;
}

const COLORS = [
  "rgba(6,182,212,",    // cyan
  "rgba(79,70,229,",    // indigo (more on-brand)
  "rgba(124,58,237,",   // violet
  "rgba(16,185,129,",   // emerald
  "rgba(239,68,68,",    // red (threat)
];

const PARTICLE_COUNT = 40;
const CONNECTION_DIST = 130;

export default function DashboardBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const frameRef = useRef<number>(0);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  useEffect(() => {
    if (reducedMotion) return;
    
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    // Init particles
    const particles: Particle[] = Array.from({ length: PARTICLE_COUNT }, (_, i) => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r: Math.random() * 1.5 + 0.6,
      alpha: Math.random() * 0.4 + 0.15,
      isThreat: i < 3,
      color: i < 3 ? COLORS[4] : COLORS[Math.floor(Math.random() * 3)],
    }));

    let scanY = 0;
    let scanDir = 1;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Scan line
      scanY += scanDir * 0.3;
      if (scanY > canvas.height || scanY < 0) scanDir *= -1;
      
      const scanGrad = ctx.createLinearGradient(0, scanY - 20, 0, scanY + 20);
      scanGrad.addColorStop(0, "rgba(6,182,212,0)");
      scanGrad.addColorStop(0.5, "rgba(6,182,212,0.03)");
      scanGrad.addColorStop(1, "rgba(6,182,212,0)");
      ctx.fillStyle = scanGrad;
      ctx.fillRect(0, scanY - 20, canvas.width, 40);

      // Update positions
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      }

      // Draw connections
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < CONNECTION_DIST) {
            const lineAlpha = (1 - dist / CONNECTION_DIST) * 0.08;
            const isThreat = particles[i].isThreat || particles[j].isThreat;
            ctx.beginPath();
            ctx.strokeStyle = isThreat
              ? `rgba(239,68,68,${lineAlpha})`
              : `rgba(79,70,229,${lineAlpha})`;
            ctx.lineWidth = 0.5;
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      for (const p of particles) {
        // Outer glow
        const grd = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r * 5);
        grd.addColorStop(0, `${p.color}${p.alpha * 0.3})`);
        grd.addColorStop(1, `${p.color}0)`);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * 5, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `${p.color}${p.alpha})`;
        ctx.fill();
      }

      frameRef.current = requestAnimationFrame(draw);
    };

    frameRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(frameRef.current);
      ro.disconnect();
    };
  }, [reducedMotion]);

  if (reducedMotion) {
    return (
      <div className="fixed inset-0 pointer-events-none z-0 dashboard-bg-pattern" aria-hidden="true" />
    );
  }

  return (
    <>
      {/* Subtle grid pattern layer */}
      <div className="fixed inset-0 pointer-events-none z-0 dashboard-grid-bg" aria-hidden="true" />
      
      {/* Particle canvas */}
      <canvas
        ref={canvasRef}
        className="fixed inset-0 w-full h-full pointer-events-none z-0"
        style={{ opacity: 0.3 }}
        aria-hidden="true"
      />
    </>
  );
}
