"use client";

import { useRef, useMemo, useCallback } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

// ─── Particle Network ────────────────────────────────────────────────────────

const NODE_COUNT = 80;
const CONNECTION_DISTANCE = 3.2;
const THREAT_NODES = 6;

function ParticleNetwork() {
  const meshRef = useRef<THREE.Points>(null);
  const linesRef = useRef<THREE.LineSegments>(null);
  const { size } = useThree();

  // Generate node positions
  const { positions, velocities, types } = useMemo(() => {
    const positions = new Float32Array(NODE_COUNT * 3);
    const velocities = new Float32Array(NODE_COUNT * 3);
    const types = new Float32Array(NODE_COUNT); // 0=normal, 1=threat, 2=hub

    const spread = size.width < 768 ? 7 : 10;

    for (let i = 0; i < NODE_COUNT; i++) {
      positions[i * 3] = (Math.random() - 0.5) * spread;
      positions[i * 3 + 1] = (Math.random() - 0.5) * (spread * 0.6);
      positions[i * 3 + 2] = (Math.random() - 0.5) * 4;

      velocities[i * 3] = (Math.random() - 0.5) * 0.004;
      velocities[i * 3 + 1] = (Math.random() - 0.5) * 0.003;
      velocities[i * 3 + 2] = (Math.random() - 0.5) * 0.002;

      types[i] = i < THREAT_NODES ? 1 : i < THREAT_NODES + 8 ? 2 : 0;
    }
    return { positions, velocities, types };
  }, [size.width]);

  // Particle colors per type
  const colors = useMemo(() => {
    const c = new Float32Array(NODE_COUNT * 3);
    for (let i = 0; i < NODE_COUNT; i++) {
      if (types[i] === 1) {
        // Threat node: red
        c[i * 3] = 0.95; c[i * 3 + 1] = 0.15; c[i * 3 + 2] = 0.15;
      } else if (types[i] === 2) {
        // Hub node: bright cyan
        c[i * 3] = 0.02; c[i * 3 + 1] = 0.85; c[i * 3 + 2] = 0.95;
      } else {
        // Normal node: cyan/blue
        c[i * 3] = 0.15; c[i * 3 + 1] = 0.55; c[i * 3 + 2] = 0.95;
      }
    }
    return c;
  }, [types]);

  // Pre-allocate line geometry buffer (max connections)
  const maxLines = NODE_COUNT * 4;
  const linePositions = useMemo(() => new Float32Array(maxLines * 6), [maxLines]);
  const lineColors = useMemo(() => new Float32Array(maxLines * 6), [maxLines]);

  const geo = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(positions.slice(), 3));
    g.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    return g;
  }, [positions, colors]);

  const lineGeo = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(linePositions, 3).setUsage(THREE.DynamicDrawUsage));
    g.setAttribute("color", new THREE.BufferAttribute(lineColors, 3).setUsage(THREE.DynamicDrawUsage));
    return g;
  }, [linePositions, lineColors]);

  const posRef = useRef(positions.slice());

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime();
    const pos = posRef.current;

    // Update node positions with gentle drift + sine bob
    for (let i = 0; i < NODE_COUNT; i++) {
      pos[i * 3] += velocities[i * 3];
      pos[i * 3 + 1] += velocities[i * 3 + 1] + Math.sin(t * 0.4 + i) * 0.0005;
      pos[i * 3 + 2] += velocities[i * 3 + 2];

      // Soft boundary bounce
      for (let ax = 0; ax < 3; ax++) {
        const lim = ax === 1 ? 3.5 : ax === 2 ? 2.5 : 5.5;
        if (Math.abs(pos[i * 3 + ax]) > lim) velocities[i * 3 + ax] *= -1;
      }
    }

    // Update particle geometry
    if (meshRef.current) {
      const posAttr = meshRef.current.geometry.getAttribute("position") as THREE.BufferAttribute;
      posAttr.array.set(pos);
      posAttr.needsUpdate = true;
    }

    // Rebuild connection lines
    let lineIdx = 0;
    for (let i = 0; i < NODE_COUNT && lineIdx < maxLines; i++) {
      for (let j = i + 1; j < NODE_COUNT && lineIdx < maxLines; j++) {
        const dx = pos[i * 3] - pos[j * 3];
        const dy = pos[i * 3 + 1] - pos[j * 3 + 1];
        const dz = pos[i * 3 + 2] - pos[j * 3 + 2];
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (dist < CONNECTION_DISTANCE) {
          const alpha = 1 - dist / CONNECTION_DISTANCE;
          const isThreat = types[i] === 1 || types[j] === 1;
          const r = isThreat ? 0.9 * alpha : 0.1 * alpha;
          const g = isThreat ? 0.1 * alpha : 0.6 * alpha;
          const b = isThreat ? 0.1 * alpha : 1.0 * alpha;

          // Start point
          linePositions[lineIdx * 6] = pos[i * 3];
          linePositions[lineIdx * 6 + 1] = pos[i * 3 + 1];
          linePositions[lineIdx * 6 + 2] = pos[i * 3 + 2];
          lineColors[lineIdx * 6] = r; lineColors[lineIdx * 6 + 1] = g; lineColors[lineIdx * 6 + 2] = b;
          // End point
          linePositions[lineIdx * 6 + 3] = pos[j * 3];
          linePositions[lineIdx * 6 + 4] = pos[j * 3 + 1];
          linePositions[lineIdx * 6 + 5] = pos[j * 3 + 2];
          lineColors[lineIdx * 6 + 3] = r; lineColors[lineIdx * 6 + 4] = g; lineColors[lineIdx * 6 + 5] = b;

          lineIdx++;
        }
      }
    }

    if (linesRef.current) {
      const lp = linesRef.current.geometry.getAttribute("position") as THREE.BufferAttribute;
      const lc = linesRef.current.geometry.getAttribute("color") as THREE.BufferAttribute;
      lp.array.set(linePositions);
      lc.array.set(lineColors);
      lp.needsUpdate = true;
      lc.needsUpdate = true;
      linesRef.current.geometry.setDrawRange(0, lineIdx * 2);
    }

    // Slowly rotate scene
    if (meshRef.current) meshRef.current.rotation.y = t * 0.04;
    if (linesRef.current) linesRef.current.rotation.y = t * 0.04;
  });

  return (
    <>
      <points ref={meshRef} geometry={geo}>
        <pointsMaterial
          size={0.12}
          vertexColors
          transparent
          opacity={0.9}
          sizeAttenuation
          depthWrite={false}
        />
      </points>
      <lineSegments ref={linesRef} geometry={lineGeo}>
        <lineBasicMaterial
          vertexColors
          transparent
          opacity={0.35}
          depthWrite={false}
        />
      </lineSegments>
    </>
  );
}

// ─── Public export ────────────────────────────────────────────────────────────

export default function NetworkHero() {
  return (
    <Canvas
      camera={{ position: [0, 0, 8], fov: 60 }}
      style={{ width: "100%", height: "100%" }}
      gl={{ antialias: true, alpha: true }}
      dpr={[1, 1.5]}
    >
      <ambientLight intensity={0.2} />
      <ParticleNetwork />
    </Canvas>
  );
}
