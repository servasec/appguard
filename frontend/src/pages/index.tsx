import { useEffect, useState } from "react"
import { useRouter } from "next/router"
import { useAuth } from "@/context/AuthContext"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { PageHeader } from "@/components/page-header"
import {
  ArrowUpRight, Plus,
} from "lucide-react"
import Link from "next/link"
import axios from "@/lib/api"
import type { DashboardStats } from "@/lib/types"
import { severityBarColors, severityColors, statusColors } from "@/lib/constants"

const kpiConfig = [
  { label: "Total findings", key: "totalFindings" as const },
  { label: "Assigned to me", key: "myOpenFindings" as const },
  { label: "Overdue", key: "overdueFindings" as const },
  { label: "Recent scans", key: "recentScans" as const },
]

export default function Dashboard() {
  const router = useRouter()
  const { loggedIn, user, authChecked } = useAuth()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  useEffect(() => {
    if (authChecked && !loggedIn) {
      router.replace("/login")
    }
  }, [authChecked, loggedIn, router])

  useEffect(() => {
    if (authChecked && loggedIn) {
      axios
        .get("/api/dashboard/stats")
        .then((res) => { setStats(res.data); setLoadError(false) })
        .catch(() => { setLoadError(true) })
        .finally(() => setLoading(false))
    }
  }, [authChecked, loggedIn])

  if (!authChecked || !loggedIn) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    )
  }

  const totalSeverity = stats?.bySeverity.reduce((a, b) => a + b.count, 0) || 1

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeader crumbs={[{ label: "Dashboard" }]} />
        <Link href="/applications">
          <Button size="sm" className="gap-1.5 h-8">
            <Plus className="h-3.5 w-3.5" />
            New scan
          </Button>
        </Link>
      </div>

      {loadError && (
        <p role="alert" className="text-sm text-destructive">
          Dashboard data could not be loaded. Refresh the page to try again.
        </p>
      )}

      <section aria-label="Dashboard summary" className="grid grid-cols-2 divide-x divide-y border-y sm:grid-cols-4 sm:divide-y-0">
        {kpiConfig.map((cfg) => {
          const value = stats ? stats[cfg.key] : 0
          const attention = value > 0 && (cfg.key === "overdueFindings" || cfg.key === "myOpenFindings")
          return (
            <div key={cfg.key} className="min-h-20 px-4 py-3 sm:px-5">
              <p className="text-xs text-muted-foreground">{cfg.label}</p>
              {loading ? (
                <Skeleton className="mt-2 h-7 w-12" />
              ) : loadError ? (
                <p className="mt-1 text-2xl font-medium text-muted-foreground">n/a</p>
              ) : (
                <p className={`mt-1 text-2xl font-semibold tabular-nums ${attention ? "text-amber-700 dark:text-amber-400" : "text-foreground"}`}>
                  {value}
                </p>
              )}
            </div>
          )
        })}
      </section>

      {loading ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2 space-y-3">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-36 w-full" />
          </div>
          <div className="space-y-3">
            <Skeleton className="h-5 w-32" />
            <Skeleton className="h-28 w-full" />
          </div>
        </div>
      ) : stats ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2 space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Severity distribution</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2.5 pt-0">
                {stats.bySeverity.map((s) => (
                  <div key={s.severity} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="capitalize font-medium">{s.severity}</span>
                      <span className="text-muted-foreground">{s.count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${(s.count / totalSeverity) * 100}%`,
                          backgroundColor: severityBarColors[s.severity.toLowerCase()] || "hsl(var(--primary))",
                        }}
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">Top findings</CardTitle>
                  <Link href="/findings" className="text-xs text-primary hover:text-primary/80 flex items-center gap-1 transition-colors">
                    View all <ArrowUpRight className="h-3 w-3" />
                  </Link>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b bg-muted/30">
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground text-xs">Rule</th>
                        <th className="text-left px-4 py-2 font-medium text-muted-foreground text-xs">Title</th>
                        <th className="text-right px-4 py-2 font-medium text-muted-foreground text-xs">Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.topFindings.length === 0 ? (
                        <tr><td colSpan={3} className="px-4 py-6 text-center text-muted-foreground text-xs">No findings yet</td></tr>
                      ) : (
                        stats.topFindings.map((f, i) => (
                          <tr key={i} className="border-b last:border-0 hover:bg-muted/20 transition-colors">
                            <td className="px-4 py-2"><code className="text-[11px] font-mono bg-muted px-1.5 py-0.5 rounded">{f.ruleId}</code></td>
                            <td className="px-4 py-2 max-w-[300px] truncate text-xs">{f.title}</td>
                            <td className="px-4 py-2 text-right font-medium text-xs">{f.count}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Findings by status</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 pt-0">
                {stats.byStatus.map((s) => (
                  <div key={s.status} className="flex items-center justify-between text-xs">
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full bg-current ${statusColors[s.status] || ""}`} />
                      <span className="capitalize">{s.status.replace("_", " ")}</span>
                    </span>
                    <span className="font-medium">{s.count}</span>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Findings by scanner</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 pt-0">
                {stats.byScanner.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No scanner data</p>
                ) : (
                  stats.byScanner.map((s, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span>{s.scannerType}</span>
                      <span className="font-medium">{s.count}</span>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>

            {user?.features?.includes("risk_scoring") && stats.avgRiskScore != null && (
              <>
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground">Average risk score</CardTitle>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <div className={`text-2xl font-bold tracking-tight ${stats.avgRiskScore >= 0.6 ? "text-red-500" : stats.avgRiskScore >= 0.3 ? "text-orange-500" : "text-emerald-500"}`}>
                      {stats.avgRiskScore.toFixed(2)}
                    </div>
                  </CardContent>
                </Card>
                {stats.riskDistribution && stats.riskDistribution.length > 0 && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium">Risk distribution</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-1.5 pt-0">
                      {[...stats.riskDistribution].reverse().map((d) => {
                        const maxCount = Math.max(...stats.riskDistribution!.map((r) => r.count), 1)
                        return (
                          <div key={d.label} className="space-y-0.5">
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-muted-foreground">{d.label}</span>
                              <span className="font-medium">{d.count}</span>
                            </div>
                            <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                              <div
                                className="h-full rounded-full bg-primary transition-all duration-500"
                                style={{ width: `${(d.count / maxCount) * 100}%` }}
                              />
                            </div>
                          </div>
                        )
                      })}
                    </CardContent>
                  </Card>
                )}
                {stats.topRiskyFindings && stats.topRiskyFindings.length > 0 && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium">Top risky findings</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="divide-y">
                        {stats.topRiskyFindings.map((f) => (
                          <Link key={f.id} href={`/findings/${f.id}`} className="flex items-center gap-2.5 px-4 py-2 hover:bg-muted/20 transition-colors">
                            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border ${severityColors[f.severity?.toLowerCase()] || ""}`}>
                              {f.severity}
                            </span>
                            <span className="flex-1 min-w-0 text-xs truncate">{f.title}</span>
                            <span className={`text-[11px] font-mono font-medium shrink-0 ${f.riskScore >= 0.6 ? "text-red-500" : f.riskScore >= 0.3 ? "text-orange-500" : "text-emerald-500"}`}>
                              {f.riskScore.toFixed(2)}
                            </span>
                          </Link>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </>
            )}
          </div>
        </div>
      ) : null}
    </div>
  )
}
