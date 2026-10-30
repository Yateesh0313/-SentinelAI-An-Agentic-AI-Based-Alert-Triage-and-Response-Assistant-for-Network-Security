"use client";

import { useRef, useMemo, useEffect, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls, Sphere, Line } from "@react-three/drei";
import * as THREE from "three";

/* ═══════════════════════════════════════════════════════════════════════════
   3D Globe with Attack Arcs — Light Theme
   
   Shows a semi-transparent globe with latitude/longitude wireframe lines
   and animated arcs representing attack sources hitting a central
   protected network node.
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Generate lat/long wireframe points ─────────────────────────────────────
function generateGlobeLines(radius: number, segments: number = 24) {
  const lines: [number, number, number][][] = [];

  // Latitude lines
  for (let i = 1; i < segments; i++) {
    const phi = (Math.PI * i) / segments;
    const points: [number, number, number][] = [];
    for (let j = 0; j <= segments * 2; j++) {
      const theta = (Math.PI * 2 * j) / (segments * 2);
      points.push([
        radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta),
      ]);
    }
    lines.push(points);
  }

  // Longitude lines
  for (let i = 0; i < segments; i++) {
    const theta = (Math.PI * 2 * i) / segments;
    const points: [number, number, number][] = [];
    for (let j = 0; j <= segments; j++) {
      const phi = (Math.PI * j) / segments;
      points.push([
        radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta),
      ]);
    }
    lines.push(points);
  }

  return lines;
}

// ── Attack source locations (lat, lng in radians) ─────────────────────────
const ATTACK_SOURCES = [
  { lat: 0.92, lng: 0.65, label: "Eastern Europe" },
  { lat: 0.63, lng: 2.10, label: "East Asia" },
  { lat: 0.52, lng: -0.18, label: "West Africa" },
  { lat: 0.78, lng: -1.40, label: "South America" },
  { lat: 1.05, lng: 1.80, label: "Southeast Asia" },
  { lat: 0.85, lng: -2.10, label: "North America" },
];

const TARGET = { lat: 0.88, lng: -0.10 }; // Western Europe / our network

function latLngToVec3(lat: number, lng: number, radius: number): THREE.Vector3 {
  return new THREE.Vector3(
    radius * Math.sin(lat) * Math.cos(lng),
    radius * Math.cos(lat),
    radius * Math.sin(lat) * Math.sin(lng)
  );
}

// ── Animated arc between two points on the globe ──────────────────────────
function AttackArc({
  from,
  to,
  radius,
  color,
  delay,
}: {
  from: { lat: number; lng: number };
  to: { lat: number; lng: number };
  radius: number;
  color: string;
  delay: number;
}) {
  const meshRef = useRef<THREE.Group>(null);
  const progressRef = useRef(0);
  const startTime = useRef(delay);

  const curve = useMemo(() => {
    const start = latLngToVec3(from.lat, from.lng, radius);
    const end = latLngToVec3(to.lat, to.lng, radius);
    const mid = start.clone().add(end).multiplyScalar(0.5);
    const dist = start.distanceTo(end);
    mid.normalize().multiplyScalar(radius + dist * 0.35);

    return new THREE.QuadraticBezierCurve3(start, mid, end);
  }, [from, to, radius]);

  const points = useMemo(() => curve.getPoints(48), [curve]);

  useFrame((_, delta) => {
    startTime.current -= delta;
    if (startTime.current > 0) return;

    progressRef.current += delta * 0.3;
    if (progressRef.current > 1.4) progressRef.current = 0;
  });

  // Render the arc as a line with animated opacity
  const linePoints = useMemo(
    () => points.map((p) => [p.x, p.y, p.z] as [number, number, number]),
    [points]
  );

  return (
    <group ref={meshRef}>
      <Line
        points={linePoints}
        color={color}
        lineWidth={1.5}
        transparent
        opacity={0.5}
      />
      {/* Glowing source dot */}
      <mesh position={[linePoints[0][0], linePoints[0][1], linePoints[0][2]]}>
        <sphereGeometry args={[0.025, 8, 8]} />
        <meshBasicMaterial color={color} transparent opacity={0.8} />
      </mesh>
    </group>
  );
}

// ── Globe wireframe mesh ──────────────────────────────────────────────────
function GlobeWireframe({ radius }: { radius: number }) {
  const lines = useMemo(() => generateGlobeLines(radius, 20), [radius]);

  return (
    <group>
      {lines.map((points, i) => (
        <Line
          key={i}
          points={points}
          color="#CBD5E1"
          lineWidth={0.4}
          transparent
          opacity={0.3}
        />
      ))}
    </group>
  );
}

// ── Rotating globe group ──────────────────────────────────────────────────
function RotatingGlobe({ alertSources }: { alertSources?: { lat: number; lng: number; label: string; color?: string }[] }) {
  const groupRef = useRef<THREE.Group>(null);
  const { viewport } = useThree();

  useFrame((_, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * 0.08;
    }
  });

  const radius = Math.min(viewport.width, viewport.height) * 0.22;
  const clampedRadius = Math.max(1.2, Math.min(radius, 2.0));

  return (
    <group ref={groupRef} rotation={[0.3, 0, 0.1]}>
      {/* Semi-transparent globe surface */}
      <Sphere args={[clampedRadius, 48, 48]}>
        <meshPhysicalMaterial
          color="#EEF2FF"
          transparent
          opacity={0.15}
          roughness={0.8}
          metalness={0.1}
          side={THREE.DoubleSide}
        />
      </Sphere>

      {/* Wireframe */}
      <GlobeWireframe radius={clampedRadius + 0.005} />

      {/* Inner glow sphere */}
      <Sphere args={[clampedRadius * 0.98, 32, 32]}>
        <meshBasicMaterial
          color="#4F46E5"
          transparent
          opacity={0.03}
        />
      </Sphere>

      {/* Attack arcs */}
      {ATTACK_SOURCES.map((src, i) => (
        <AttackArc
          key={i}
          from={src}
          to={TARGET}
          radius={clampedRadius + 0.01}
          color={i % 2 === 0 ? "#EF4444" : "#F97316"}
          delay={i * 0.8}
        />
      ))}

      {/* Real alert arcs from GeoIP */}
      {alertSources?.map((src, i) => (
        <AttackArc
          key={`real-${i}`}
          from={src}
          to={TARGET}
          radius={clampedRadius + 0.01}
          color={src.color || "#EF4444"}
          delay={0}
        />
      ))}

      {/* Protected node (target) */}
      <mesh position={latLngToVec3(TARGET.lat, TARGET.lng, clampedRadius + 0.02).toArray()}>
        <sphereGeometry args={[0.04, 16, 16]} />
        <meshBasicMaterial color="#10B981" />
      </mesh>
    </group>
  );
}

// ── Exported Globe Scene ──────────────────────────────────────────────────
export interface GlobeAlert {
  lat: number;
  lon: number;
  label: string;
  severity?: "Critical" | "High" | "Medium" | "Low";
}

export default function GlobeScene({ className, alerts }: { className?: string; alerts?: GlobeAlert[] }) {
  const [visible, setVisible] = useState(true);

  // Pause when tab is hidden
  useEffect(() => {
    const handler = () => setVisible(!document.hidden);
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, []);

  // Respect prefers-reduced-motion
  const [reducedMotion, setReducedMotion] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // Low-power device fallback
  const [isLowPower, setIsLowPower] = useState(false);
  useEffect(() => {
    if (typeof navigator !== "undefined") {
      const cores = navigator.hardwareConcurrency;
      const mem = (navigator as unknown as { deviceMemory?: number }).deviceMemory;
      if ((cores && cores <= 4) || (mem && mem <= 4)) {
        setIsLowPower(true);
      }
    }
  }, []);

  if (reducedMotion || isLowPower) {
    return (
      <div className={`${className ?? ""} flex items-center justify-center`}>
        <div className="w-64 h-64 rounded-full bg-gradient-to-br from-indigo-100 to-cyan-50 border border-indigo-200/50 flex flex-col items-center justify-center p-4 text-center">
          <div className="text-2xl mb-1">🌐</div>
          <div className="text-indigo-600 text-sm font-bold">Global Threat Map</div>
          <div className="text-slate-400 text-xs mt-1">
            {alerts && alerts.length > 0 ? `${alerts.length} active threat sources` : "Monitoring global ingress"}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={className}>
      <Canvas
        dpr={typeof window !== "undefined" ? Math.min(window.devicePixelRatio || 1, 2) : 1}
        camera={{ position: [0, 0, 4.5], fov: 45 }}
        frameloop={visible ? "always" : "never"}
        style={{ background: "transparent" }}
      >
        <ambientLight intensity={0.6} />
        <directionalLight position={[5, 5, 5]} intensity={0.4} />
        <pointLight position={[-3, 2, 4]} intensity={0.3} color="#06B6D4" />

        <RotatingGlobe alertSources={alerts?.map(a => ({
          lat: ((90 - a.lat) * Math.PI) / 180,
          lng: (a.lon * Math.PI) / 180,
          label: a.label,
          color: a.severity === "Critical" ? "#EF4444" : a.severity === "High" ? "#F97316" : a.severity === "Medium" ? "#F59E0B" : "#06B6D4",
        }))} />

        <OrbitControls
          enableZoom={false}
          enablePan={false}
          autoRotate={false}
          maxPolarAngle={Math.PI * 0.75}
          minPolarAngle={Math.PI * 0.25}
        />
      </Canvas>
    </div>
  );
}
