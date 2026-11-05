"use client";

import { useRef, useMemo, useEffect, useState, useCallback } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";

// ── Palette ────────────────────────────────────────────────────────────────────
const COLORS = {
  cyan: new THREE.Color("#06B6D4"),
  indigo: new THREE.Color("#4F46E5"),
  violet: new THREE.Color("#7C3AED"),
  emerald: new THREE.Color("#10B981"),
  red: new THREE.Color("#EF4444"),
  white: new THREE.Color("#ffffff"),
};

const NODE_PALETTE = [COLORS.cyan, COLORS.indigo, COLORS.violet];
const THREAT_RATIO = 0.08; // 8% of nodes are "threats"

// ── Helpers ────────────────────────────────────────────────────────────────────
function randomInSphere(radius: number): [number, number, number] {
  const u = Math.random();
  const v = Math.random();
  const theta = 2 * Math.PI * u;
  const phi = Math.acos(2 * v - 1);
  const r = radius * Math.cbrt(Math.random());
  return [
    r * Math.sin(phi) * Math.cos(theta),
    r * Math.sin(phi) * Math.sin(theta),
    r * Math.cos(phi),
  ];
}

// ── NetworkNodes (InstancedMesh) ───────────────────────────────────────────────
interface NodeData {
  positions: Float32Array;
  colors: Float32Array;
  baseColors: THREE.Color[];
  isThreat: boolean[];
  count: number;
}

function useNodeData(count: number, spread: number): NodeData {
  return useMemo(() => {
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const baseColors: THREE.Color[] = [];
    const isThreat: boolean[] = [];

    for (let i = 0; i < count; i++) {
      const [x, y, z] = randomInSphere(spread);
      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      const threat = Math.random() < THREAT_RATIO;
      isThreat.push(threat);
      const color = threat
        ? COLORS.red
        : NODE_PALETTE[Math.floor(Math.random() * NODE_PALETTE.length)];
      baseColors.push(color.clone());
      colors[i * 3] = color.r;
      colors[i * 3 + 1] = color.g;
      colors[i * 3 + 2] = color.b;
    }

    return { positions, colors, baseColors, isThreat, count };
  }, [count, spread]);
}

const _tempObj = new THREE.Object3D();
const _tempColor = new THREE.Color();

function NetworkNodes({
  nodeData,
  variant,
}: {
  nodeData: NodeData;
  variant: "full" | "subtle";
}) {
  const meshRef = useRef<THREE.InstancedMesh>(null!);
  const { positions, baseColors, count } = nodeData;

  // Set initial transforms
  useEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    for (let i = 0; i < count; i++) {
      _tempObj.position.set(
        positions[i * 3],
        positions[i * 3 + 1],
        positions[i * 3 + 2]
      );
      _tempObj.scale.setScalar(1);
      _tempObj.updateMatrix();
      mesh.setMatrixAt(i, _tempObj.matrix);
      _tempColor.copy(baseColors[i]);
      mesh.setColorAt(i, _tempColor);
    }
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  }, [positions, baseColors, count]);

  // Animate: gentle floating + glow pulse
  useFrame(({ clock }) => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const t = clock.getElapsedTime();

    for (let i = 0; i < count; i++) {
      const bx = positions[i * 3];
      const by = positions[i * 3 + 1];
      const bz = positions[i * 3 + 2];

      // Gentle floating
      const drift = Math.sin(t * 0.3 + i * 0.7) * 0.08;
      _tempObj.position.set(bx, by + drift, bz);

      // Pulse scale
      const pulse = 1 + Math.sin(t * 1.5 + i * 1.2) * 0.15;
      _tempObj.scale.setScalar(pulse);
      _tempObj.updateMatrix();
      mesh.setMatrixAt(i, _tempObj.matrix);

      // Gentle color brightness pulse
      const brightness = 0.85 + Math.sin(t * 2 + i) * 0.15;
      _tempColor.copy(baseColors[i]).multiplyScalar(brightness);
      mesh.setColorAt(i, _tempColor);
    }

    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  });

  const nodeSize = variant === "full" ? 0.06 : 0.05;

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, count]}>
      <sphereGeometry args={[nodeSize, 12, 12]} />
      <meshBasicMaterial toneMapped={false} transparent opacity={variant === "full" ? 0.9 : 0.55} />
    </instancedMesh>
  );
}

// ── ConnectionLines ────────────────────────────────────────────────────────────
function ConnectionLines({
  nodeData,
  variant,
}: {
  nodeData: NodeData;
  variant: "full" | "subtle";
}) {
  const lineRef = useRef<THREE.LineSegments>(null!);
  const threshold = variant === "full" ? 2.2 : 2.6;

  const geometry = useMemo(() => {
    const { positions, baseColors, count } = nodeData;
    const verts: number[] = [];
    const cols: number[] = [];

    for (let i = 0; i < count; i++) {
      for (let j = i + 1; j < count; j++) {
        const dx = positions[i * 3] - positions[j * 3];
        const dy = positions[i * 3 + 1] - positions[j * 3 + 1];
        const dz = positions[i * 3 + 2] - positions[j * 3 + 2];
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);

        if (dist < threshold) {
          verts.push(
            positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2],
            positions[j * 3], positions[j * 3 + 1], positions[j * 3 + 2]
          );

          // If either node is a threat, use red; else blend colors
          const isThreatEdge = nodeData.isThreat[i] || nodeData.isThreat[j];
          const edgeColor = isThreatEdge ? COLORS.red : baseColors[i];
          cols.push(edgeColor.r, edgeColor.g, edgeColor.b);
          cols.push(edgeColor.r, edgeColor.g, edgeColor.b);
        }
      }
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.Float32BufferAttribute(verts, 3));
    geo.setAttribute("color", new THREE.Float32BufferAttribute(cols, 3));
    return geo;
  }, [nodeData, threshold]);

  return (
    <lineSegments ref={lineRef} geometry={geometry}>
      <lineBasicMaterial
        vertexColors
        transparent
        opacity={variant === "full" ? 0.18 : 0.08}
        depthWrite={false}
      />
    </lineSegments>
  );
}

// ── RadarSweep ─────────────────────────────────────────────────────────────────
function RadarSweep() {
  const meshRef = useRef<THREE.Mesh>(null!);

  useFrame(({ clock }) => {
    if (meshRef.current) {
      meshRef.current.rotation.y = clock.getElapsedTime() * 0.4;
    }
  });

  const geometry = useMemo(() => {
    // Create a thin cone shape for the radar sweep
    const geo = new THREE.ConeGeometry(4, 0.02, 32, 1, true, 0, Math.PI / 3);
    geo.rotateX(Math.PI / 2);
    return geo;
  }, []);

  return (
    <mesh ref={meshRef} geometry={geometry} position={[0, 0, 0]}>
      <meshBasicMaterial
        color="#06B6D4"
        transparent
        opacity={0.06}
        side={THREE.DoubleSide}
        depthWrite={false}
      />
    </mesh>
  );
}

// ── PulseRings ─────────────────────────────────────────────────────────────────
function PulseRings({ variant }: { variant: "full" | "subtle" }) {
  const ringsCount = variant === "full" ? 3 : 1;
  const groupRef = useRef<THREE.Group>(null!);
  const ringRefs = useRef<THREE.Mesh[]>([]);

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime();
    for (let i = 0; i < ringsCount; i++) {
      const ring = ringRefs.current[i];
      if (!ring) continue;
      const phase = (t * 0.3 + (i / ringsCount) * Math.PI * 2) % (Math.PI * 2);
      const progress = phase / (Math.PI * 2);
      const scale = 0.5 + progress * 5;
      ring.scale.set(scale, scale, scale);
      (ring.material as THREE.MeshBasicMaterial).opacity =
        (1 - progress) * (variant === "full" ? 0.12 : 0.05);
    }
  });

  return (
    <group ref={groupRef}>
      {Array.from({ length: ringsCount }).map((_, i) => (
        <mesh
          key={i}
          ref={(el) => {
            if (el) ringRefs.current[i] = el;
          }}
          rotation={[-Math.PI / 2, 0, 0]}
        >
          <ringGeometry args={[0.95, 1, 64]} />
          <meshBasicMaterial
            color="#4F46E5"
            transparent
            opacity={0.1}
            side={THREE.DoubleSide}
            depthWrite={false}
          />
        </mesh>
      ))}
    </group>
  );
}

// ── HexGrid ────────────────────────────────────────────────────────────────────
function HexGrid({ variant }: { variant: "full" | "subtle" }) {
  const gridRef = useRef<THREE.LineSegments>(null!);

  const geometry = useMemo(() => {
    const verts: number[] = [];
    const size = 0.4;
    const cols = variant === "full" ? 20 : 12;
    const rows = variant === "full" ? 20 : 12;
    const offsetX = (cols * size * 1.5) / 2;
    const offsetZ = (rows * size * Math.sqrt(3)) / 2;

    for (let col = 0; col < cols; col++) {
      for (let row = 0; row < rows; row++) {
        const cx = col * size * 1.5 - offsetX;
        const cz = row * size * Math.sqrt(3) + (col % 2 === 0 ? 0 : size * Math.sqrt(3) * 0.5) - offsetZ;

        // Draw hexagon edges
        for (let k = 0; k < 6; k++) {
          const angle1 = (Math.PI / 3) * k;
          const angle2 = (Math.PI / 3) * (k + 1);
          verts.push(
            cx + size * Math.cos(angle1), 0, cz + size * Math.sin(angle1),
            cx + size * Math.cos(angle2), 0, cz + size * Math.sin(angle2)
          );
        }
      }
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.Float32BufferAttribute(verts, 3));
    return geo;
  }, [variant]);

  return (
    <lineSegments
      ref={gridRef}
      geometry={geometry}
      position={[0, -3.5, 0]}
      rotation={[0, 0, 0]}
    >
      <lineBasicMaterial
        color="#06B6D4"
        transparent
        opacity={variant === "full" ? 0.045 : 0.02}
        depthWrite={false}
      />
    </lineSegments>
  );
}

// ── DataFlowParticles ──────────────────────────────────────────────────────────
function DataFlowParticles({
  nodeData,
  variant,
}: {
  nodeData: NodeData;
  variant: "full" | "subtle";
}) {
  const pointsRef = useRef<THREE.Points>(null!);
  const particleCount = variant === "full" ? 120 : 30;
  const threshold = variant === "full" ? 2.2 : 2.6;

  // Build edges list and create particles that travel along them
  const { edges, particleData } = useMemo(() => {
    const { positions, count } = nodeData;
    const edgeList: [number, number][] = [];

    for (let i = 0; i < count; i++) {
      for (let j = i + 1; j < count; j++) {
        const dx = positions[i * 3] - positions[j * 3];
        const dy = positions[i * 3 + 1] - positions[j * 3 + 1];
        const dz = positions[i * 3 + 2] - positions[j * 3 + 2];
        if (Math.sqrt(dx * dx + dy * dy + dz * dz) < threshold) {
          edgeList.push([i, j]);
        }
      }
    }

    // Assign each particle to a random edge
    const data = Array.from({ length: particleCount }).map(() => ({
      edgeIdx: Math.floor(Math.random() * Math.max(edgeList.length, 1)),
      t: Math.random(),
      speed: 0.2 + Math.random() * 0.5,
      direction: Math.random() > 0.5 ? 1 : -1,
    }));

    return { edges: edgeList, particleData: data };
  }, [nodeData, particleCount, threshold]);

  const positionsAttr = useMemo(
    () => new Float32Array(particleCount * 3),
    [particleCount]
  );

  useFrame(({ clock }) => {
    const points = pointsRef.current;
    if (!points || edges.length === 0) return;
    const dt = clock.getDelta();
    const { positions } = nodeData;

    for (let p = 0; p < particleCount; p++) {
      const pd = particleData[p];
      pd.t += dt * pd.speed * pd.direction;

      // Wrap
      if (pd.t > 1) { pd.t = 0; pd.edgeIdx = Math.floor(Math.random() * edges.length); }
      if (pd.t < 0) { pd.t = 1; pd.edgeIdx = Math.floor(Math.random() * edges.length); }

      const [a, b] = edges[pd.edgeIdx % edges.length];
      const t = pd.t;
      positionsAttr[p * 3] = positions[a * 3] * (1 - t) + positions[b * 3] * t;
      positionsAttr[p * 3 + 1] = positions[a * 3 + 1] * (1 - t) + positions[b * 3 + 1] * t;
      positionsAttr[p * 3 + 2] = positions[a * 3 + 2] * (1 - t) + positions[b * 3 + 2] * t;
    }

    const geo = points.geometry as THREE.BufferGeometry;
    geo.setAttribute("position", new THREE.Float32BufferAttribute(positionsAttr, 3));
    geo.attributes.position.needsUpdate = true;
  });

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[positionsAttr, 3]}
        />
      </bufferGeometry>
      <pointsMaterial
        color="#06B6D4"
        size={0.025}
        transparent
        opacity={variant === "full" ? 0.7 : 0.35}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  );
}

// ── CyberScene ─────────────────────────────────────────────────────────────────
function CyberScene({ variant }: { variant: "full" | "subtle" }) {
  const groupRef = useRef<THREE.Group>(null!);

  const nodeCount = variant === "full" ? 70 : 28;
  const spread = variant === "full" ? 4 : 3.5;
  const nodeData = useNodeData(nodeCount, spread);

  // Slow scene rotation
  useFrame(({ clock }) => {
    if (groupRef.current) {
      groupRef.current.rotation.y = clock.getElapsedTime() * 0.03;
    }
  });

  return (
    <group ref={groupRef}>
      <NetworkNodes nodeData={nodeData} variant={variant} />
      <ConnectionLines nodeData={nodeData} variant={variant} />
      {variant === "full" && <RadarSweep />}
      <PulseRings variant={variant} />
      <DataFlowParticles nodeData={nodeData} variant={variant} />
      <HexGrid variant={variant} />
      {/* Subtle ambient light for any mesh materials */}
      <ambientLight intensity={0.3} />
    </group>
  );
}

// ── Main Export ─────────────────────────────────────────────────────────────────
export default function CyberBackground({
  className = "",
  variant = "full",
}: {
  className?: string;
  variant?: "full" | "subtle";
}) {
  const [reducedMotion, setReducedMotion] = useState(false);
  const [lowPower, setLowPower] = useState(false);
  const [isVisible, setIsVisible] = useState(true);

  // Check prefers-reduced-motion
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // Low-power device heuristic
  useEffect(() => {
    const cores = navigator.hardwareConcurrency ?? 4;
    if (cores <= 2) setLowPower(true);
  }, []);

  // Visibility check for frameloop
  useEffect(() => {
    const handler = () => setIsVisible(!document.hidden);
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, []);

  // Fallback for reduced motion or low power
  if (reducedMotion || lowPower) {
    return (
      <div className={className} style={{ pointerEvents: "none" }}>
        <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 pointer-events-none">
          <div
            className="absolute inset-0 opacity-20 pointer-events-none"
            style={{
              backgroundImage: `radial-gradient(circle at 25% 25%, rgba(6,182,212,0.15) 0%, transparent 50%),
                radial-gradient(circle at 75% 75%, rgba(79,70,229,0.1) 0%, transparent 50%)`,
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className={className} style={{ pointerEvents: "none" }}>
      <Canvas
        dpr={[1, 2]}
        frameloop={isVisible ? "always" : "demand"}
        camera={{ position: [0, 1, 7], fov: 50 }}
        style={{ background: "transparent", pointerEvents: "none" }}
        gl={{ alpha: true, antialias: true, powerPreference: "high-performance" }}
      >
        {/* Dark scene fog */}
        <fog attach="fog" args={["#0a0e1a", 6, 16]} />
        <color attach="background" args={["#050816"]} />
        <CyberScene variant={variant} />
      </Canvas>
    </div>
  );
}
