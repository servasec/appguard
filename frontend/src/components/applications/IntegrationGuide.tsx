import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Check, Clipboard, ExternalLink, KeyRound, Pencil, Play, Plus, RotateCw, ShieldCheck, Trash2, Unplug } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import axios from "@/lib/api";
import type { Application, ScanItem, ScannerIntegration, ScannerType } from "@/lib/types";
import { RepositoryConnectionPanel } from "@/components/applications/RepositoryConnectionPanel";

type CIProvider = "github" | "gitlab" | "shell";

function uploadCommand(scanner: ScannerType, version: string, branch: string) {
  return `curl --fail-with-body --request POST "$APPGUARD_URL/ingest" --header "X-Api-Token: $APPGUARD_API_TOKEN" --form "file=@${scanner.name}-report.${scanner.formats?.[0]?.toLowerCase() || "json"}" --form "scannerType=${scanner.name}" --form "version=${version}" --form "branch=${branch}"`;
}

function workflowSnippet(provider: CIProvider, command: string) {
  if (provider === "github") {
    return [
      "name: Upload security report to AppGuard",
      "on: [push]",
      "jobs:",
      "  appguard-report:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - name: Upload scanner report",
      "        env:",
      "          APPGUARD_URL: ${{ vars.APPGUARD_URL }}",
      "          APPGUARD_API_TOKEN: ${{ secrets.APPGUARD_API_TOKEN }}",
      "        run: |",
      `          ${command}`,
      "",
    ].join("\n");
  }
  if (provider === "gitlab") {
    return [
      "upload_security_report:",
      "  stage: test",
      "  image: curlimages/curl:8.12.1",
      "  script:",
      "    - |",
      `      ${command}`,
      "  rules:",
      "    - if: $CI_COMMIT_BRANCH",
      "",
    ].join("\n");
  }
  return [
    "# Set APPGUARD_URL (including /api) and APPGUARD_API_TOKEN in your CI secret store.",
    "# Run this after your scanner has produced its report.",
    command,
    "",
  ].join("\n");
}

function statusLabel(status: ScannerIntegration["status"]) {
  return ({
    awaiting_report: "Awaiting first report",
    connected: "Connected",
    stale: "Stale",
    error: "Error",
    paused: "Paused",
    revoked: "Revoked",
  } as const)[status];
}

function statusTone(status: ScannerIntegration["status"]) {
  if (status === "connected") return "text-emerald-600 dark:text-emerald-400";
  if (status === "error") return "text-destructive";
  if (status === "stale" || status === "awaiting_report") return "text-amber-600 dark:text-amber-400";
  return "text-muted-foreground";
}

export function IntegrationGuide({ application, scans, onUpload }: {
  application: Application;
  scans: ScanItem[];
  onUpload: () => void;
}) {
  const [scannerTypes, setScannerTypes] = useState<ScannerType[]>([]);
  const [integrations, setIntegrations] = useState<ScannerIntegration[]>([]);
  const [catalogFailed, setCatalogFailed] = useState(false);
  const [integrationsFailed, setIntegrationsFailed] = useState(false);
  const [selectedScannerId, setSelectedScannerId] = useState("");
  const [integrationName, setIntegrationName] = useState("");
  const [provider, setProvider] = useState<CIProvider>("github");
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [busyIntegrationId, setBusyIntegrationId] = useState<number | null>(null);
  const [revealedToken, setRevealedToken] = useState("");
  const [editTarget, setEditTarget] = useState<ScannerIntegration | null>(null);
  const [editName, setEditName] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<ScannerIntegration | null>(null);

  const refreshIntegrations = async () => {
    try {
      const res = await axios.get(`/api/applications/${application.id}/integrations`);
      setIntegrations(res.data || []);
      setIntegrationsFailed(false);
    } catch {
      setIntegrationsFailed(true);
    }
  };

  useEffect(() => {
    axios.get("/api/scanner-types", { params: { enabled: "true" } })
      .then((res) => {
        const enabled = res.data || [];
        setScannerTypes(enabled);
        if (enabled.length) {
          setSelectedScannerId(String(enabled[0].id));
          setIntegrationName(enabled[0].name);
        }
      })
      .catch(() => setCatalogFailed(true));
    refreshIntegrations();
  }, [application.id]);

  const selectedScanner = scannerTypes.find((scanner) => String(scanner.id) === selectedScannerId);
  const selectedIntegration = integrations.find((integration) => integration.scannerTypeId === Number(selectedScannerId));
  const snippet = useMemo(() => {
    if (!selectedScanner || !selectedIntegration) return "";
    const command = uploadCommand(selectedScanner, "${CI_COMMIT_SHA:-${GITHUB_SHA:-latest}}", "${CI_COMMIT_REF_NAME:-${GITHUB_REF_NAME:-main}}");
    return workflowSnippet(provider, command);
  }, [provider, selectedScanner, selectedIntegration]);
  const groupedScanners = useMemo(() => scannerTypes.reduce<Record<string, ScannerType[]>>((groups, scanner) => {
    const category = scanner.category || "Other";
    (groups[category] ||= []).push(scanner);
    return groups;
  }, {}), [scannerTypes]);

  const copyText = async (value: string, message: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(message);
    } catch {
      toast.error("Clipboard access is unavailable in this browser");
    }
  };

  const createIntegration = async () => {
    if (!selectedScanner) return;
    setBusy(true);
    try {
      const res = await axios.post(`/api/applications/${application.id}/integrations`, {
        scannerTypeId: selectedScanner.id,
        name: integrationName.trim() || selectedScanner.name,
      });
      setRevealedToken(res.data.token);
      setSelectedScannerId(String(selectedScanner.id));
      await refreshIntegrations();
      toast.success("Scanner integration created");
    } catch (error: any) {
      toast.error(error?.response?.data?.error || "Failed to create scanner integration");
    } finally {
      setBusy(false);
    }
  };

  const runIntegrationAction = async (integration: ScannerIntegration, action: "pause" | "reconnect" | "rotate-token") => {
    setBusyIntegrationId(integration.id);
    try {
      const res = await axios.post(`/api/applications/${application.id}/integrations/${integration.id}/${action}`);
      if (action === "rotate-token") setRevealedToken(res.data.token);
      await refreshIntegrations();
      toast.success(action === "rotate-token" ? "Integration token rotated" : action === "pause" ? "Integration paused" : "Integration reconnected");
    } catch (error: any) {
      toast.error(error?.response?.data?.error || "Failed to update scanner integration");
    } finally {
      setBusyIntegrationId(null);
    }
  };

  const updateIntegrationName = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!editTarget) return;
    setBusyIntegrationId(editTarget.id);
    try {
      await axios.patch(`/api/applications/${application.id}/integrations/${editTarget.id}`, { name: editName });
      await refreshIntegrations();
      setEditTarget(null);
      toast.success("Integration name updated");
    } catch (error: any) {
      toast.error(error?.response?.data?.error || "Failed to update integration");
    } finally {
      setBusyIntegrationId(null);
    }
  };

  const revokeIntegration = async () => {
    if (!revokeTarget) return;
    setBusyIntegrationId(revokeTarget.id);
    try {
      await axios.delete(`/api/applications/${application.id}/integrations/${revokeTarget.id}`);
      await refreshIntegrations();
      setRevokeTarget(null);
      toast.success("Integration revoked");
    } catch (error: any) {
      toast.error(error?.response?.data?.error || "Failed to revoke integration");
    } finally {
      setBusyIntegrationId(null);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <Card className="border-0 shadow-none">
        <div className="p-5 sm:p-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold">Connect a scanner</h2>
              <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
                AppGuard collects and compares reports. Your CI pipeline runs the scanner; the integration token below only grants report upload for that scanner.
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={onUpload} className="shrink-0">Upload a report now</Button>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="integration-scanner">Scanner</Label>
              <Select value={selectedScannerId} onValueChange={(value) => {
                setSelectedScannerId(value);
                setIntegrationName(scannerTypes.find((scanner) => String(scanner.id) === value)?.name || "");
              }}>
                <SelectTrigger id="integration-scanner"><SelectValue placeholder="Choose a scanner" /></SelectTrigger>
                <SelectContent>
                  {Object.entries(groupedScanners).map(([category, scanners]) => (
                    <SelectGroup key={category}>
                      <SelectLabel>{category}</SelectLabel>
                      {scanners.map((scanner) => <SelectItem key={scanner.id} value={String(scanner.id)}>{scanner.name}</SelectItem>)}
                    </SelectGroup>
                  ))}
                </SelectContent>
              </Select>
              {selectedScanner && <p className="text-xs text-muted-foreground">Accepted report: {selectedScanner.formats?.join(" / ") || "JSON"}</p>}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="integration-name">Integration name</Label>
              <Input id="integration-name" value={integrationName} onChange={(event) => setIntegrationName(event.target.value)} maxLength={100} disabled={!!selectedIntegration} />
              <p className="text-xs text-muted-foreground">Keep the generated report filename aligned with the output path in your CI job.</p>
            </div>
          </div>

          {selectedScanner && !selectedIntegration && (
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-dashed p-4">
              <p className="text-sm text-muted-foreground">Create an integration to issue a scanner-scoped token and track its reports.</p>
              <Button onClick={createIntegration} disabled={busy || !integrationName.trim()} className="gap-2">
                <Plus className="h-4 w-4" />{busy ? "Creating…" : "Create integration"}
              </Button>
            </div>
          )}

          {selectedIntegration && (
            <>
              <div className="mt-5 overflow-hidden rounded-lg border border-border/70">
                <div className="flex items-center justify-between gap-3 border-b border-border/70 bg-muted/40 px-3 py-2">
                  <span className="text-xs font-medium">{provider === "github" ? "GitHub Actions" : provider === "gitlab" ? "GitLab CI" : "Shell"} upload step</span>
                  <Button variant="ghost" size="sm" onClick={() => copyText(snippet, "CI snippet copied")} className="h-7 gap-1.5 px-2 text-xs">
                    <Clipboard className="h-3.5 w-3.5" />Copy
                  </Button>
                </div>
                <pre className="max-h-[360px] overflow-auto bg-background p-4 text-xs leading-relaxed"><code>{snippet}</code></pre>
              </div>
              <div className="mt-4 grid gap-4 md:grid-cols-[1fr_auto] md:items-center">
                <div className="grid gap-2">
                  <Label htmlFor="integration-ci">CI provider</Label>
                  <Select value={provider} onValueChange={(value) => setProvider(value as CIProvider)}>
                    <SelectTrigger id="integration-ci"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="github">GitHub Actions</SelectItem>
                      <SelectItem value="gitlab">GitLab CI</SelectItem>
                      <SelectItem value="shell">Generic shell</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <p className="max-w-md text-xs text-muted-foreground">Set <code>APPGUARD_URL</code> to this instance&apos;s API base URL (including <code>/api</code>), and save the integration token as <code>APPGUARD_API_TOKEN</code> in your CI secret store.</p>
              </div>
              <p className="mt-3 text-xs text-muted-foreground">This example uploads an existing report. It does not run the scanner. The token is shown only when created or rotated.</p>
            </>
          )}

          {!selectedIntegration && !selectedScanner && (
            <p className="mt-5 rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              {catalogFailed ? "Could not load the scanner catalog. Refresh the page and try again." : "No enabled scanner types are available."}
            </p>
          )}
          {integrationsFailed && <p className="mt-3 text-sm text-destructive">Could not load this project&apos;s integrations.</p>}
        </div>
      </Card>

      <RepositoryConnectionPanel application={application} />

      <Card className="border-0 shadow-none">
        <div className="p-5 sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">Project integrations</h2>
              <p className="mt-1 text-sm text-muted-foreground">Connection state is based on received reports. An integration becomes stale after 30 days without a successful report.</p>
            </div>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </div>
          {integrations.length ? (
            <div className="mt-4 divide-y divide-border/70">
              {integrations.map((integration) => {
                const latestScan = scans.find((scan) => scan.scannerTypeId === integration.scannerTypeId);
                const busyThis = busyIntegrationId === integration.id;
                return (
                  <div key={integration.id} className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0 lg:flex-row lg:items-center lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="text-sm font-medium">{integration.name}</span>
                        <span className="text-xs text-muted-foreground">{integration.category} · {integration.scannerType.name}</span>
                        <span className={`text-xs font-medium ${statusTone(integration.status)}`}>{statusLabel(integration.status)}</span>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {integration.lastSuccessAt ? `Last successful report ${new Date(integration.lastSuccessAt).toLocaleString()}` : `Token ${integration.tokenPrefix} · awaiting first successful report`}
                        {integration.lastError && integration.status === "error" ? ` · ${integration.lastError}` : ""}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {latestScan && <Link href={`/scans/${latestScan.id}`} className="mr-1 inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"><ExternalLink className="h-3.5 w-3.5" />Latest scan</Link>}
                      <Button variant="ghost" size="sm" className="h-8 gap-1.5 px-2 text-xs" disabled={busyThis} onClick={() => { setEditTarget(integration); setEditName(integration.name); }}><Pencil className="h-3.5 w-3.5" />Rename</Button>
                      {integration.isActive && <Button variant="ghost" size="sm" className="h-8 gap-1.5 px-2 text-xs" disabled={busyThis} onClick={() => runIntegrationAction(integration, "pause")}><Unplug className="h-3.5 w-3.5" />Pause</Button>}
                      {(!integration.isActive || integration.status === "error") && <Button variant="ghost" size="sm" className="h-8 gap-1.5 px-2 text-xs" disabled={busyThis} onClick={() => runIntegrationAction(integration, "reconnect")}><Play className="h-3.5 w-3.5" />Reconnect</Button>}
                      <Button variant="ghost" size="sm" className="h-8 gap-1.5 px-2 text-xs" disabled={busyThis} onClick={() => runIntegrationAction(integration, "rotate-token")}><RotateCw className="h-3.5 w-3.5" />Rotate token</Button>
                      <Button variant="ghost" size="sm" className="h-8 gap-1.5 px-2 text-xs text-destructive hover:text-destructive" disabled={busyThis} onClick={() => setRevokeTarget(integration)}><Trash2 className="h-3.5 w-3.5" />Revoke</Button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-8 text-center text-sm text-muted-foreground">
              <KeyRound className="mx-auto mb-2 h-6 w-6 opacity-50" />
              No scanner integrations yet. Choose a scanner above to create the first one.
            </div>
          )}
          <p className="mt-4 border-t border-border/70 pt-4 text-xs text-muted-foreground">Legacy project API tokens continue to work. Reports uploaded with one are associated with the matching active scanner integration when available.</p>
        </div>
      </Card>

      <Dialog open={!!revealedToken} onOpenChange={(open) => { if (!open) setRevealedToken(""); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Copy the integration token</DialogTitle>
            <DialogDescription>This token is shown once. Save it as <code>APPGUARD_API_TOKEN</code> in the CI secret store for this project.</DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-3">
            <code className="min-w-0 flex-1 break-all text-xs">{revealedToken}</code>
            <Button variant="outline" size="sm" onClick={() => copyText(revealedToken, "Integration token copied")}><Clipboard className="mr-1.5 h-3.5 w-3.5" />Copy</Button>
          </div>
          <DialogFooter><Button onClick={() => setRevealedToken("")}><Check className="mr-1.5 h-4 w-4" />Done</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!editTarget} onOpenChange={(open) => !open && setEditTarget(null)}>
        <DialogContent>
          <form onSubmit={updateIntegrationName}>
            <DialogHeader>
              <DialogTitle>Rename integration</DialogTitle>
              <DialogDescription>Use a name that helps your team identify this scanner connection.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-2 py-4"><Label htmlFor="edit-integration-name">Name</Label><Input id="edit-integration-name" value={editName} onChange={(event) => setEditName(event.target.value)} maxLength={100} required /></div>
            <DialogFooter><Button type="button" variant="outline" onClick={() => setEditTarget(null)}>Cancel</Button><Button type="submit" disabled={busyIntegrationId === editTarget?.id}>Save</Button></DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={!!revokeTarget} onOpenChange={(open) => !open && setRevokeTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke scanner integration?</DialogTitle>
            <DialogDescription>This permanently invalidates the integration token for {revokeTarget?.name}. Existing scans remain in AppGuard.</DialogDescription>
          </DialogHeader>
          <DialogFooter><Button variant="outline" onClick={() => setRevokeTarget(null)}>Cancel</Button><Button variant="destructive" onClick={revokeIntegration} disabled={busyIntegrationId === revokeTarget?.id}>Revoke integration</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
