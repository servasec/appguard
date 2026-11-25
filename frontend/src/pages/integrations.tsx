import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { PlugZap, Search } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/page-header";
import axios from "@/lib/api";
import type { ScannerIntegration } from "@/lib/types";
import { RepositoryCandidatesPanel } from "@/components/applications/RepositoryCandidatesPanel";

const statusLabels: Record<ScannerIntegration["status"], string> = {
  awaiting_report: "Awaiting first report",
  connected: "Connected",
  stale: "Stale",
  error: "Error",
  paused: "Paused",
  revoked: "Revoked",
};

function statusClass(status: ScannerIntegration["status"]) {
  if (status === "connected") return "text-emerald-600 dark:text-emerald-400";
  if (status === "error") return "text-destructive";
  if (status === "stale" || status === "awaiting_report") return "text-amber-600 dark:text-amber-400";
  return "text-muted-foreground";
}

export default function IntegrationsPage() {
  const router = useRouter();
  const { loggedIn, authChecked } = useAuth();
  const [integrations, setIntegrations] = useState<ScannerIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [category, setCategory] = useState("all");

  useEffect(() => {
    if (authChecked && !loggedIn) router.replace("/login");
  }, [authChecked, loggedIn, router]);

  useEffect(() => {
    if (!authChecked || !loggedIn) return;
    setLoading(true);
    const timer = window.setTimeout(() => {
      axios.get("/api/integrations", {
        params: {
          ...(search.trim() ? { q: search.trim() } : {}),
          ...(status !== "all" ? { status } : {}),
          ...(category !== "all" ? { category } : {}),
        },
      })
        .then((res) => { setIntegrations(res.data || []); setError(false); })
        .catch(() => { setIntegrations([]); setError(true); })
        .finally(() => setLoading(false));
    }, search ? 200 : 0);
    return () => window.clearTimeout(timer);
  }, [authChecked, loggedIn, search, status, category]);

  const categories = useMemo(() => Array.from(new Set([
    "SAST", "SCA", "Secrets", "IaC", "DAST", "Cloud & containers", "Generic",
    ...integrations.map((integration) => integration.category),
  ])).sort(), [integrations]);

  return (
    <div className="space-y-6">
      <PageHeader crumbs={[{ label: "Security" }, { label: "Integrations" }]} />
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Scanner integrations</h1>
        <p className="mt-1 text-sm text-muted-foreground">Track report delivery and find scanners that need attention across your projects.</p>
      </div>

      <RepositoryCandidatesPanel />

      <Card className="border-0 shadow-none">
        <div className="grid gap-4 p-4 sm:grid-cols-[minmax(220px,1fr)_180px_180px] sm:items-end">
          <div className="grid gap-2">
            <Label htmlFor="integration-search">Search projects or scanners</Label>
            <div className="relative"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input id="integration-search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Project or scanner name" className="pl-9" /></div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="integration-status">Status</Label>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger id="integration-status"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="awaiting_report">Awaiting report</SelectItem>
                <SelectItem value="connected">Connected</SelectItem>
                <SelectItem value="stale">Stale</SelectItem>
                <SelectItem value="error">Error</SelectItem>
                <SelectItem value="paused">Paused</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="integration-category">Category</Label>
            <Select value={category} onValueChange={setCategory}>
              <SelectTrigger id="integration-category"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All categories</SelectItem>
                {categories.map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>
      </Card>

      <Card className="border-0 shadow-none">
        <div className="divide-y divide-border/70 px-4">
          {loading ? (
            <div className="space-y-3 py-5"><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /><Skeleton className="h-12 w-full" /></div>
          ) : error ? (
            <p className="py-10 text-center text-sm text-destructive">Could not load scanner integrations. Refresh the page and try again.</p>
          ) : integrations.length ? integrations.map((integration) => (
            <div key={integration.id} className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <PlugZap className="h-4 w-4 text-primary" />
                  <span className="text-sm font-medium">{integration.name}</span>
                  <span className="text-xs text-muted-foreground">{integration.category} · {integration.scannerType.name}</span>
                  <span className={`text-xs font-medium ${statusClass(integration.status)}`}>{statusLabels[integration.status]}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                  <span>{integration.groupName ? `${integration.groupName} / ` : ""}{integration.applicationName}</span>
                  <span>{integration.lastSuccessAt ? `Last report ${new Date(integration.lastSuccessAt).toLocaleString()}` : "No successful report yet"}</span>
                  {integration.status === "error" && integration.lastError && <span className="text-destructive">{integration.lastError}</span>}
                </div>
              </div>
              <Link href={`/applications/${integration.applicationId}?tab=integrations`} className="shrink-0 rounded-md px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground">Open project</Link>
            </div>
          )) : (
            <div className="py-12 text-center">
              <PlugZap className="mx-auto mb-3 h-7 w-7 text-muted-foreground/50" />
              <p className="text-sm font-medium">No scanner integrations found</p>
              <p className="mt-1 text-xs text-muted-foreground">Create an integration from a project&apos;s Integrations tab.</p>
              <Link href="/applications" className="mt-3 inline-block text-xs font-medium text-primary hover:underline">Browse projects</Link>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
