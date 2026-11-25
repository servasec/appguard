"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/router"
import { AnimatePresence, motion, useReducedMotion } from "motion/react"
import {
  AppWindow,
  Bug,
  ChevronDown,
  ChevronsLeft,
  ChevronsRight,
  FolderKanban,
  LogOut,
  Menu,
  Moon,
  PlugZap,
  Scan,
  ScrollText,
  Shield,
  ShieldAlert,
  Settings2,
  Sun,
  User,
  Users,
  UsersRound,
  X,
} from "lucide-react"
import { useAuth } from "@/context/AuthContext"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "next-themes"
import { Brand } from "@/components/brand"
import type { User as UserProfile } from "@/lib/types"

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
      { label: "Integrations", href: "/integrations", icon: <PlugZap className="h-4 w-4" /> },
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
      { label: "Audit Log", href: "/admin/audit-log", icon: <ScrollText className="h-4 w-4" />, adminOnly: true, feature: "audit_log" },
      { label: "Settings", href: "/settings", icon: <Settings2 className="h-4 w-4" />, adminOnly: true },
    ],
  },
]

const collapsedGroupSeparatorClass = "mx-auto mb-2 h-px w-6 bg-border first:hidden" // taste-skill-ignore: Extrack uses a one-pixel divider between collapsed groups

function SidebarNavItem({
  item,
  active,
  collapsed,
  reduceMotion,
  onNavigate,
}: {
  item: NavItem
  active: boolean
  collapsed: boolean
  reduceMotion: boolean
  onNavigate: () => void
}) {
  return (
    <Link
      href={item.href}
      onClick={onNavigate}
      title={collapsed ? item.label : undefined}
      aria-current={active ? "page" : undefined}
      className={`group relative flex h-9 items-center gap-2.5 rounded-lg px-2.5 text-[13px] font-medium transition-[color,background-color,transform] active:translate-y-px motion-reduce:active:translate-y-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
        collapsed ? "justify-center px-0" : ""
      } ${
        active
          ? "bg-primary/10 text-foreground"
          : "text-muted-foreground hover:bg-accent hover:text-foreground"
      }`}
    >
      {active && (
        <span
          aria-hidden="true"
          className="absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2"
        >
          <motion.span
            initial={reduceMotion ? false : { opacity: 0, scaleY: 0.65 }}
            animate={{ opacity: 1, scaleY: 1 }}
            transition={{ duration: reduceMotion ? 0 : 0.16, ease: [0.16, 1, 0.3, 1] }}
            className="block h-full w-full rounded-r-full bg-primary"
          />
        </span>
      )}
      <span className={`shrink-0 ${active ? "text-primary" : ""}`}>{item.icon}</span>
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  )
}

function AccountMenu({
  user,
  collapsed,
  theme,
  onToggleTheme,
  onLogout,
}: {
  user: UserProfile | null
  collapsed: boolean
  theme: string | undefined
  onToggleTheme: () => void
  onLogout: () => void
}) {
  const isDark = theme === "dark"

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="Account menu"
          className={`focus-ring group flex w-full items-center gap-2.5 rounded-lg p-1.5 text-left transition-colors hover:bg-accent ${
            collapsed ? "justify-center" : ""
          }`}
        >
          <Avatar className="h-7 w-7 shrink-0 text-[10px]">
            <AvatarFallback className="bg-muted text-foreground">
              {user?.username?.charAt(0).toUpperCase() || "U"}
            </AvatarFallback>
          </Avatar>
          {!collapsed && (
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium">{user?.username}</span>
              <span className="block truncate text-[10px] text-muted-foreground">
                {user?.role}
              </span>
            </span>
          )}
          {!collapsed && (
            <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground/50 transition-transform group-data-[state=open]:rotate-180" />
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align={collapsed ? "start" : "end"} sideOffset={6} className="w-56">
        <DropdownMenuLabel className="font-normal">
          <span className="block truncate text-xs font-medium">{user?.username}</span>
          <span className="block truncate text-[10px] text-muted-foreground">{user?.email}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild className="gap-2">
          <Link href="/profile">
            <User className="h-3.5 w-3.5" />
            Profile
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onToggleTheme} className="gap-2">
          {isDark ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
          {isDark ? "Light mode" : "Dark mode"}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={onLogout} className="gap-2 text-destructive focus:text-destructive">
          <LogOut className="h-3.5 w-3.5" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { loggedIn, user, logout, authChecked } = useAuth()
  const { theme, setTheme } = useTheme()
  const reduceMotion = Boolean(useReducedMotion())
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const saved = window.localStorage.getItem("appguard-sidebar-collapsed")
    setCollapsed(saved === "true")
  }, [])

  useEffect(() => {
    window.localStorage.setItem("appguard-sidebar-collapsed", String(collapsed))
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

  useEffect(() => {
    if (theme && theme !== "dark" && theme !== "light") setTheme("dark")
  }, [theme, setTheme])

  const isPublicPage = router.pathname === "/login" || router.pathname === "/register"
  if (!authChecked || !loggedIn || isPublicPage) return <>{children}</>

  const handleLogout = async () => {
    await logout(true)
  }

  const isActive = (href: string) =>
    href === "/" ? router.pathname === "/" : router.pathname.startsWith(href)

  const visibleGroups = navGroups
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => {
        if (item.adminOnly && user?.role !== "admin") return false
        if (item.feature && !user?.features?.includes(item.feature)) return false
        return true
      }),
    }))
    .filter((group) => group.items.length > 0)

  return (
    <div className="flex h-dvh overflow-hidden bg-background">
      <AnimatePresence initial={false}>
        {mobileOpen && (
          <motion.button
            key="mobile-menu-backdrop"
            type="button"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: reduceMotion ? 0.12 : 0.2 }}
            className="fixed inset-0 z-30 bg-foreground/15 lg:hidden"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      <motion.aside
        initial={false}
        animate={{ width: collapsed ? 72 : 248 }}
        transition={{ duration: reduceMotion ? 0 : 0.22, ease: [0.16, 1, 0.3, 1] }}
        className={`fixed inset-y-0 left-0 z-40 flex shrink-0 flex-col bg-sidebar transition-transform duration-200 motion-reduce:transition-none lg:relative lg:z-auto ${
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        }`}
      >
        <div className={`flex h-14 shrink-0 items-center ${collapsed ? "justify-center px-2" : "justify-between px-4"}`}>
          <Link href="/" aria-label="AppGuard home" className="min-w-0 hover:opacity-80 transition-opacity">
            <Brand collapsed={collapsed} />
          </Link>
          {!collapsed && (
            <div className="flex items-center gap-1">
              <button
                type="button"
                aria-label="Collapse sidebar"
                onClick={() => setCollapsed(true)}
                className="hidden h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring lg:inline-flex"
              >
                <ChevronsLeft className="h-4 w-4" />
              </button>
              <button
                type="button"
                aria-label="Close navigation"
                onClick={() => setMobileOpen(false)}
                className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring lg:hidden"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {collapsed && (
          <div className="hidden justify-center py-2 lg:flex">
            <button
              type="button"
              aria-label="Expand sidebar"
              onClick={() => setCollapsed(false)}
              className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <ChevronsRight className="h-4 w-4" />
            </button>
          </div>
        )}

        <nav className={`scrollbar-thin flex-1 overflow-y-auto py-4 ${collapsed ? "px-2" : "px-3"}`}>
          {visibleGroups.map((group) => (
            <div key={group.label} className="mb-5 last:mb-0">
              {!collapsed ? (
                <p className="mb-1.5 px-2.5 text-[11px] font-medium text-muted-foreground/80">
                  {group.label}
                </p>
              ) : (
                <div className={collapsedGroupSeparatorClass} />
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => (
                  <SidebarNavItem
                    key={item.href}
                    item={item}
                    active={isActive(item.href)}
                    collapsed={collapsed}
                    reduceMotion={reduceMotion}
                    onNavigate={() => setMobileOpen(false)}
                  />
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className={`shrink-0 p-2.5 ${collapsed ? "flex flex-col items-center gap-2" : ""}`}>
          <AccountMenu
            user={user}
            collapsed={collapsed}
            theme={theme}
            onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
            onLogout={handleLogout}
          />
        </div>
      </motion.aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between px-4 lg:hidden">
          <div className="flex items-center gap-2">
            <button
              type="button"
              aria-label="Open navigation"
              aria-expanded={mobileOpen}
              onClick={() => setMobileOpen(true)}
              className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <Menu className="h-4 w-4" />
            </button>
            <Brand />
          </div>
        </header>

        <main className="min-h-0 min-w-0 flex-1 p-3 sm:p-4 lg:p-5">
          <div id="main-scroll" className="scrollbar-thin h-full overflow-y-auto rounded-xl border border-border/70 bg-card p-5 sm:p-6 lg:p-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}
