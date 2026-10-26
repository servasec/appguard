"use client"

import { useRouter } from "next/router"
import { useAuth } from "@/context/AuthContext"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { BackToTop } from "@/components/back-to-top"
import { useTheme } from "next-themes"
import {
  AppWindow,
  FolderKanban,
  Users,
  UsersRound,
  Shield,
  Sun,
  Moon,
  ChevronLeft,
  ChevronDown,
  KeyRound,
  User,
  LogOut,
  Scan,
  Bug,
  ScrollText,
  ScanLine,
  ShieldAlert,
  Menu,
  X,
} from "lucide-react"
import { useState, useEffect, useRef } from "react"
import Link from "next/link"
import type { User as UserProfile } from "@/lib/types"
import { Brand } from "@/components/brand"

interface NavItem {
  label: string
  href: string
  icon: React.ReactNode
  adminOnly?: boolean
  feature?: string
}

interface NavGroup {
  label: string
  items: NavItem[]
}

const navGroups: NavGroup[] = [
    {
      label: "Security",
      items: [
        { label: "Applications", href: "/applications", icon: <AppWindow className="h-4 w-4" /> },
        { label: "Groups", href: "/groups", icon: <FolderKanban className="h-4 w-4" /> },
        { label: "Scans", href: "/scans", icon: <Scan className="h-4 w-4" /> },
        { label: "Findings", href: "/findings", icon: <Bug className="h-4 w-4" /> },
        { label: "Policies", href: "/policies", icon: <ShieldAlert className="h-4 w-4" /> },
      ],
    },
    {
      label: "Administration",
      items: [
        { label: "Users", href: "/users", icon: <Users className="h-4 w-4" />, adminOnly: true },
        { label: "Teams", href: "/teams", icon: <UsersRound className="h-4 w-4" /> },
        { label: "Permissions", href: "/admin/permissions", icon: <Shield className="h-4 w-4" />, adminOnly: true },
        { label: "Scanner Types", href: "/admin/scanner-types", icon: <ScanLine className="h-4 w-4" />, adminOnly: true },
        { label: "Audit Log", href: "/admin/audit-log", icon: <ScrollText className="h-4 w-4" />, adminOnly: true, feature: "audit_log" },
        { label: "Single Sign-On", href: "/admin/sso", icon: <KeyRound className="h-4 w-4" />, adminOnly: true, feature: "sso" },
      ],
    },
]

function UserMenu({
  user,
  onLogout,
  collapsed,
}: {
  user: UserProfile | null
  onLogout: () => void
  collapsed: boolean
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [])

  if (collapsed) {
    return (
      <Link
        href="/profile"
        className="flex items-center justify-center w-full rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
        title="Profile"
      >
        <Avatar className="h-7 w-7 shrink-0">
          <AvatarFallback className="bg-accent text-accent-foreground text-[11px]">
            {user?.username?.charAt(0).toUpperCase() || "U"}
          </AvatarFallback>
        </Avatar>
      </Link>
    )
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground ${
          collapsed ? "justify-center" : ""
        }`}
      >
        <Avatar className="h-7 w-7 shrink-0">
          <AvatarFallback className="bg-accent text-accent-foreground text-[11px]">
            {user?.username?.charAt(0).toUpperCase() || "U"}
          </AvatarFallback>
        </Avatar>
        {!collapsed && (
          <>
            <div className="flex-1 min-w-0 text-left">
              <p className="text-sm font-medium truncate text-foreground">
                {user?.username}
              </p>
              <p className="text-[11px] text-muted-foreground/60 capitalize truncate">
                {user?.role}
              </p>
            </div>
            <ChevronDown
              className={`h-3.5 w-3.5 shrink-0 text-muted-foreground/50 transition-transform ${
                open ? "rotate-180" : ""
              }`}
            />
          </>
        )}
      </button>

      {open && (
        <div className="absolute bottom-full left-0 right-0 mb-1 rounded-md border bg-popover text-popover-foreground py-1 shadow-lg">
          <div className="px-3 py-2 text-xs text-muted-foreground border-b">
            Signed in as
          </div>
          <Link
            href="/profile"
            onClick={() => setOpen(false)}
            className="flex w-full items-center gap-2 px-3 py-2 text-sm text-foreground/80 hover:bg-accent transition-colors"
          >
            <User className="h-3.5 w-3.5" />
            Profile
          </Link>
          <button
            onClick={onLogout}
            className="flex w-full items-center gap-2 px-3 py-2 text-sm text-foreground/80 hover:bg-accent transition-colors"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </button>
        </div>
      )}
    </div>
  )
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { loggedIn, user, logout, authChecked } = useAuth()
  const { theme, setTheme } = useTheme()
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const sidebarCollapsed = collapsed && !mobileOpen
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    const saved = localStorage.getItem("appguard-sidebar-collapsed")
    if (saved === "true") {
      setCollapsed(true)
    }
  }, [])

  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem("appguard-sidebar-collapsed", String(collapsed))
    }
  }, [collapsed])

  useEffect(() => {
    setMobileOpen(false)
  }, [router.asPath])

  useEffect(() => {
    if (!mobileOpen) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileOpen(false)
    }
    window.addEventListener("keydown", closeOnEscape)
    return () => window.removeEventListener("keydown", closeOnEscape)
  }, [mobileOpen])

  const isPublicPage =
    router.pathname === "/login" || router.pathname === "/register"

  if (!authChecked || !loggedIn || isPublicPage) {
    return <>{children}</>
  }

  const handleLogout = async () => {
    await logout(true)
  }

  const isActive = (href: string) => {
    if (href === "/") return router.pathname === "/"
    return router.pathname.startsWith(href)
  }

  return (
    <div className="h-screen overflow-hidden bg-background flex">
      <header className="fixed inset-x-0 top-0 z-30 flex h-12 items-center justify-between border-b bg-background px-4 md:hidden">
        <Link href="/" aria-label="AppGuard home"><Brand /></Link>
        <button
          type="button"
          aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={mobileOpen}
          onClick={() => setMobileOpen(!mobileOpen)}
          className="flex h-10 w-10 items-center justify-center text-muted-foreground hover:text-foreground"
        >
          {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </header>
      {mobileOpen && <button className="fixed inset-0 z-40 bg-black/30 md:hidden" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-64 flex-col bg-sidebar shrink-0 transition-transform duration-200 md:relative md:z-auto md:translate-x-0 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        } ${collapsed ? "md:w-16" : "md:w-64"}`}
      >
        <div className="h-14 flex items-center justify-between px-4 shrink-0">
          <Link href="/" className="flex min-w-0 items-center gap-3 hover:opacity-80 transition-opacity" onClick={() => setMobileOpen(false)}>
            <Brand collapsed={sidebarCollapsed} />
          </Link>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
            className="flex h-9 w-9 items-center justify-center text-muted-foreground hover:text-foreground md:hidden"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-3 space-y-1">
          {navGroups.map((group) => {
            const visibleItems = group.items.filter((item) => {
              if (item.adminOnly && user?.role !== "admin") return false
              if (item.feature && !user?.features?.includes(item.feature)) return false
              return true
            })
            if (visibleItems.length === 0) return null

            return (
              <div key={group.label}>
                {!sidebarCollapsed && (
                  <div className="px-4 py-1.5">
                    <span className="text-xs font-semibold text-sidebar-foreground/60">
                      {group.label}
                    </span>
                  </div>
                )}
                {visibleItems.map((item) => {
                  const active = isActive(item.href)
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={() => setMobileOpen(false)}
                      className={`relative flex items-center h-9 text-sm transition-colors ${
                        sidebarCollapsed ? "justify-center" : "gap-3 px-4"
                      } ${
                        active
                          ? "bg-sidebar-accent text-sidebar-accent-foreground font-medium"
                          : "text-sidebar-foreground/85 hover:bg-sidebar-accent hover:text-sidebar-foreground"
                      }`}
                      title={sidebarCollapsed ? item.label : undefined}
                    >
                      {active && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full bg-primary" />
                      )}
                      <span className="shrink-0">{item.icon}</span>
                      {!sidebarCollapsed && <span>{item.label}</span>}
                    </Link>
                  )
                })}
              </div>
            )
          })}
        </nav>

        <div className="pt-1 pb-2 px-2 space-y-0.5 shrink-0">
          {mounted && (
            <button
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm text-sidebar-foreground/85 hover:bg-sidebar-accent hover:text-sidebar-foreground w-full transition-colors ${
                sidebarCollapsed ? "justify-center" : ""
              }`}
            >
              {theme === "dark" || theme === "catppuccin" || theme === "github" || theme === "nord" ? (
                <Sun className="h-4 w-4 shrink-0" />
              ) : (
                <Moon className="h-4 w-4 shrink-0" />
              )}
              {!sidebarCollapsed && (
                <span>{theme === "light" ? "Dark mode" : "Light mode"}</span>
              )}
            </button>
          )}

          <UserMenu user={user} onLogout={handleLogout} collapsed={collapsed && !mobileOpen} />

          <button
            onClick={() => setCollapsed(!collapsed)}
            className={`hidden md:flex items-center gap-3 px-3 py-2 rounded-md text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground w-full transition-colors ${
              collapsed ? "justify-center" : ""
            }`}
          >
            <ChevronLeft
              className={`h-4 w-4 shrink-0 transition-transform ${
                collapsed ? "rotate-180" : ""
              }`}
            />
            {!collapsed && <span>Collapse sidebar</span>}
          </button>
        </div>
      </aside>

      <main className="flex-1 flex flex-col min-w-0 min-h-0 pt-14 md:pt-2 px-0 md:pl-0 md:pr-2 pb-0 md:pb-2">
        <div id="main-scroll" className="bg-card rounded-none md:rounded-xl border-0 md:border border-border/60 flex-1 min-h-0 overflow-y-auto p-4 md:p-6">
          {children}
        </div>
        <BackToTop />
      </main>
    </div>
  )
}
