"use client"

import { AnimatePresence, motion, useReducedMotion } from "motion/react"
import { useRouter } from "next/router"

export function PageTransition({ children }: { children: React.ReactNode }) {
  const { asPath } = useRouter()
  const reduceMotion = Boolean(useReducedMotion())

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={asPath.split("?")[0]}
        initial={{ opacity: 0, y: reduceMotion ? 0 : 4 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 0 }}
        transition={{ duration: reduceMotion ? 0 : 0.18, ease: [0.16, 1, 0.3, 1] }}
        className="min-h-full"
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}
