/* Hallmark · component: AppGuard auth panel · theme: existing brand · v2.0.0 */
"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useAnimationFrame, useReducedMotion } from "motion/react"

const phrases = [
  "Focus on findings that matter",
  "Track vulnerabilities across your stack",
  "Monitor your application security posture",
  "Secure your deployment pipeline",
  "Stay compliant with automated policies",
]

const particles = Array.from({ length: 180 }, (_, i) => {
  const latitude = 1 - (2 * (i + 0.5)) / 180
  const ring = Math.sqrt(1 - latitude * latitude)
  const angle = i * 2.399963229728653
  const depth = (latitude + 1) / 2

  return {
    x: Math.cos(angle) * ring * 154,
    y: latitude * 154,
    z: Math.sin(angle) * ring * 154,
    radius: i % 17 === 0 ? 2.35 : 1.1,
    opacity: i % 17 === 0 ? 0.8 : 0.56 + depth * 0.2,
    color: i % 3 === 0 ? "hsl(var(--foreground))" : "hsl(var(--primary))",
  }
})

const networkEdges = particles.flatMap((particle, index) =>
  particles
    .map((target, targetIndex) => ({
      target,
      targetIndex,
      distance: Math.hypot(target.x - particle.x, target.y - particle.y, target.z - particle.z),
    }))
    .filter(({ targetIndex, distance }) => targetIndex !== index && distance > 8)
    .sort((a, b) => a.distance - b.distance)
    .slice(0, 3)
    .filter(({ targetIndex }) => targetIndex > index)
    .map(({ target, targetIndex }) => ({
      id: `${index}-${targetIndex}`,
      fromIndex: index,
      toIndex: targetIndex,
      opacity: Math.min(particle.opacity, target.opacity) * 0.48,
    })),
)

const signalEdges = networkEdges.filter((_, index) => index % 10 === 0)
const orbitRings = [
  Array.from({ length: 120 }, (_, i) => {
    const angle = (i / 120) * Math.PI * 2
    return { x: Math.cos(angle) * 198, y: Math.sin(angle) * 80, z: 0 }
  }),
  Array.from({ length: 120 }, (_, i) => {
    const angle = (i / 120) * Math.PI * 2
    return { x: Math.cos(angle) * 194, y: 0, z: Math.sin(angle) * 78 }
  }),
]
const blinkingCaretClass = "ml-0.5 inline-block h-[1.1em] w-[2px] animate-pulse motion-reduce:animate-none bg-foreground/55 align-middle" // taste-skill-ignore: the requested typewriter caret blinks while typing

type ProjectedPoint = { x: number; y: number; z: number; scale: number }

function projectPoint(point: { x: number; y: number; z: number }, time: number): ProjectedPoint {
  const yaw = (time / 42_000) * Math.PI * 2
  const pitch = 0.24
  const cosYaw = Math.cos(yaw)
  const sinYaw = Math.sin(yaw)
  const cosPitch = Math.cos(pitch)
  const sinPitch = Math.sin(pitch)
  const rotatedX = point.x * cosYaw + point.z * sinYaw
  const rotatedZ = -point.x * sinYaw + point.z * cosYaw
  const rotatedY = point.y * cosPitch - rotatedZ * sinPitch
  const depth = point.y * sinPitch + rotatedZ * cosPitch
  const scale = 520 / (520 - depth)

  return {
    x: 280 + rotatedX * scale,
    y: 230 + rotatedY * scale,
    z: depth,
    scale,
  }
}

function pathByDepth(points: ProjectedPoint[], front: boolean) {
  const segments: string[] = []
  for (let i = 0; i < points.length; i += 1) {
    const from = points[i]
    const to = points[(i + 1) % points.length]
    const isFront = (from.z + to.z) / 2 >= 0
    if (isFront !== front) continue
    segments.push(`M${from.x.toFixed(2)} ${from.y.toFixed(2)}L${to.x.toFixed(2)} ${to.y.toFixed(2)}`)
  }
  return segments.join("")
}

function HeroParticleOrb() {
  const reduceMotion = useReducedMotion()
  const particleRefs = useRef<(SVGCircleElement | null)[]>([])
  const edgeRefs = useRef<(SVGLineElement | null)[]>([])
  const signalRefs = useRef<(SVGCircleElement | null)[]>([])
  const orbitBackRefs = useRef<(SVGPathElement | null)[]>([])
  const orbitFrontRefs = useRef<(SVGPathElement | null)[]>([])

  const renderFrame = useCallback((time: number) => {
    const projectedParticles = particles.map((particle) => projectPoint(particle, time))
    const depthOpacity = (depth: number) => 0.08 + 0.92 * Math.max(0, Math.min(1, (depth + 154) / 308))

    projectedParticles.forEach((point, index) => {
      const node = particleRefs.current[index]
      if (!node) return
      node.setAttribute("cx", point.x.toFixed(2))
      node.setAttribute("cy", point.y.toFixed(2))
      node.setAttribute("r", (particles[index].radius * (0.78 + point.scale * 0.22)).toFixed(2))
      node.setAttribute("fill-opacity", (particles[index].opacity * depthOpacity(point.z)).toFixed(3))
    })

    networkEdges.forEach((edge, index) => {
      const node = edgeRefs.current[index]
      if (!node) return
      const from = projectedParticles[edge.fromIndex]
      const to = projectedParticles[edge.toIndex]
      const depth = (from.z + to.z) / 2
      node.setAttribute("x1", from.x.toFixed(2))
      node.setAttribute("y1", from.y.toFixed(2))
      node.setAttribute("x2", to.x.toFixed(2))
      node.setAttribute("y2", to.y.toFixed(2))
      node.setAttribute("stroke-opacity", (edge.opacity * depthOpacity(depth)).toFixed(3))
    })

    signalEdges.forEach((edge, index) => {
      const node = signalRefs.current[index]
      if (!node) return
      const from = projectedParticles[edge.fromIndex]
      const to = projectedParticles[edge.toIndex]
      const progress = (time / 1800 + index * 0.29) % 1
      const depth = from.z + (to.z - from.z) * progress
      node.setAttribute("cx", (from.x + (to.x - from.x) * progress).toFixed(2))
      node.setAttribute("cy", (from.y + (to.y - from.y) * progress).toFixed(2))
      node.setAttribute("opacity", (depthOpacity(depth) * Math.sin(progress * Math.PI)).toFixed(3))
    })

    orbitRings.forEach((ring, index) => {
      const points = ring.map((point) => projectPoint(point, time))
      orbitBackRefs.current[index]?.setAttribute("d", pathByDepth(points, false))
      orbitFrontRefs.current[index]?.setAttribute("d", pathByDepth(points, true))
    })
  }, [])

  useEffect(() => {
    renderFrame(0)
  }, [renderFrame])

  useAnimationFrame((time) => {
    if (!reduceMotion) renderFrame(time)
  })

  return (
    <div className="h-auto w-full max-w-[34rem]">
      <svg aria-hidden="true" viewBox="0 0 560 460" className="h-auto w-full overflow-visible">
        <defs>
          <radialGradient id="appguard-orb-glow">
            <stop stopColor="hsl(var(--primary))" stopOpacity=".16" />
            <stop offset=".72" stopColor="hsl(var(--primary))" stopOpacity=".035" />
            <stop offset="1" stopColor="hsl(var(--primary))" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="appguard-orb-core" cx="38%" cy="32%">
            <stop stopColor="hsl(var(--foreground))" stopOpacity=".78" />
            <stop offset=".4" stopColor="hsl(var(--primary))" stopOpacity=".28" />
            <stop offset="1" stopColor="hsl(var(--primary))" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="appguard-orb-orbit" x1="0" x2="1" y1="0" y2="1">
            <stop stopColor="hsl(var(--primary))" stopOpacity=".05" />
            <stop offset=".5" stopColor="hsl(var(--primary))" stopOpacity=".55" />
            <stop offset="1" stopColor="hsl(var(--primary))" stopOpacity=".18" />
          </linearGradient>
        </defs>

        {orbitRings.map((_, index) => (
          <path key={`orbit-back-${index}`} ref={(node) => { orbitBackRefs.current[index] = node }} fill="none" stroke="url(#appguard-orb-orbit)" strokeWidth="1" strokeOpacity=".16" />
        ))}
        <circle cx="280" cy="230" r="188" fill="url(#appguard-orb-glow)" />
        {networkEdges.map((edge, index) => (
          <line
            key={edge.id}
            ref={(node) => { edgeRefs.current[index] = node }}
            stroke="hsl(var(--primary))"
            strokeWidth=".7"
            strokeOpacity={edge.opacity}
          />
        ))}
        {particles.map((particle, index) => (
          <circle
            key={index}
            ref={(node) => { particleRefs.current[index] = node }}
            cx={280 + particle.x}
            cy={230 + particle.y}
            r={particle.radius}
            fill={particle.color}
            fillOpacity={particle.opacity}
          />
        ))}
        {signalEdges.map((edge, index) => (
          <circle
            key={`signal-${edge.id}`}
            ref={(node) => { signalRefs.current[index] = node }}
            r="1.5"
            fill="hsl(var(--foreground))"
            opacity="0"
          />
        ))}
        <circle cx="280" cy="230" r="92" fill="url(#appguard-orb-core)" opacity=".28" />
        {orbitRings.map((_, index) => (
          <path key={`orbit-front-${index}`} ref={(node) => { orbitFrontRefs.current[index] = node }} fill="none" stroke="url(#appguard-orb-orbit)" strokeWidth="1.2" strokeOpacity=".56" />
        ))}
      </svg>
    </div>
  )
}

export function AuthBackground() {
  const reduceMotion = useReducedMotion()
  const [phraseIndex, setPhraseIndex] = useState(0)
  const [chars, setChars] = useState(phrases[0].length)
  const phrase = phrases[phraseIndex]

  useEffect(() => {
    if (!reduceMotion) setChars(0)
  }, [reduceMotion])

  useEffect(() => {
    if (reduceMotion) return
    const timer = window.setTimeout(() => {
      if (chars < phrase.length) {
        setChars((current) => current + 1)
      } else {
        setPhraseIndex((current) => (current + 1) % phrases.length)
        setChars(0)
      }
    }, chars < phrase.length ? 42 : 2600)
    return () => window.clearTimeout(timer)
  }, [chars, phrase.length, reduceMotion])

  return (
    <section className="flex h-full min-h-[100dvh] w-full flex-col items-center justify-center gap-2 overflow-hidden bg-background px-10 xl:px-16">
      <div className="flex w-full items-center justify-center" aria-hidden="true">
        <HeroParticleOrb />
      </div>
      <p className="-mt-12 min-h-[2em] max-w-lg text-center text-lg font-light leading-relaxed tracking-wide text-foreground/75 xl:text-xl">
        {reduceMotion ? phrases[0] : phrase.slice(0, chars)}
        {!reduceMotion && (
          <span aria-hidden="true" className={blinkingCaretClass} />
        )}
      </p>
    </section>
  )
}
