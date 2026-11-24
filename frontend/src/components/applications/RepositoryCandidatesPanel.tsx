import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/router";
import { useAuth } from "@/context/AuthContext";
import { Copy, ExternalLink, FolderGit2, GitBranch, Loader2, Plus } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import axios from "@/lib/api";
import type { Application } from "@/lib/types";

type Provider = "github" | "gitlab";
type Connection = { id: number; provider: Provider; accountName: string; status: string };
type Repository = { id: string; name: string; path: string; url: string };
type Group = { id: number; name: string };
type ProviderOptions = Record<Provider, { enabled: boolean }>;
type SetupResult = { appId?: number; token?: string; webhookUrl?: string; webhookSecret?: string; linkError?: boolean };

function projectSlug(repository: Repository) {
  return (repository.name.split("/").pop() || repository.name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 100) || "imported-project";
}

export function RepositoryCandidatesPanel() {
  const router = useRouter();
  const { loggedIn, authChecked } = useAuth();
  const [providers, setProviders] = useState<ProviderOptions | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [applications, setApplications] = useState<Application[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [connectionId, setConnectionId] = useState("");
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [applicationId, setApplicationId] = useState("");
  const [groupId, setGroupId] = useState("");
  const [projectName, setProjectName] = useState("");
  const [slug, setSlug] = useState("");
  const [createTarget, setCreateTarget] = useState<Repository | null>(null);
  const [result, setResult] = useState<SetupResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);

  const load = async () => {
    try {
      const [providerResponse, connectionResponse, applicationResponse, groupResponse] = await Promise.all([
        axios.get("/api/repository-connections/providers"),
        axios.get("/api/repository-connections/connections"),
        axios.get("/api/applications"),
        axios.get("/api/groups"),
      ]);
      setProviders(providerResponse.data);
      setConnections(connectionResponse.data || []);
      setApplications(applicationResponse.data || []);
      setGroups(groupResponse.data || []);
      setLoadFailed(false);
    } catch { setLoadFailed(true); }
  };

  useEffect(() => { if (authChecked && loggedIn) load(); }, [authChecked, loggedIn]);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const connected = params.get("repositoryConnection");
    const failed = params.get("repositoryConnectionError");
    if (connected) toast.success(`${connected === "github" ? "GitHub" : "GitLab"} account connected.`);
    if (failed) toast.error(`Repository authorization failed: ${failed.replace(/_/g, " ")}.`);
    if (connected || failed) {
      params.delete("repositoryConnection");
      params.delete("repositoryConnectionError");
      const query = params.toString();
      window.history.replaceState(window.history.state, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
    }
  }, []);

  const connect = async (provider: Provider) => {
    setBusy(true);
    try {
      const response = await axios.get(`/api/repository-connections/providers/${provider}/authorize`, { params: { returnTo: "/integrations" } });
      window.location.assign(response.data.authorizationUrl);
    } catch { toast.error(`Could not start ${provider} authorization.`); setBusy(false); }
  };

  const discover = async () => {
    if (!connectionId) return;
    setBusy(true);
    try {
      const response = await axios.get(`/api/repository-connections/connections/${connectionId}/repositories`);
      setRepositories(response.data || []);
      if (!response.data?.length) toast.message("No repositories are available for this connection.");
    } catch { toast.error("Could not load repositories. Reconnect the provider if its authorization expired."); }
    finally { setBusy(false); }
  };

  const linkToApplication = async (repository: Repository) => {
    if (!applicationId || !connectionId) return;
    setBusy(true);
    try {
      const response = await axios.post(`/api/applications/${applicationId}/repository-link`, { connectionId: Number(connectionId), repositoryId: repository.id });
      setResult({ webhookUrl: response.data.webhookUrl, webhookSecret: response.data.webhookSecret });
      toast.success("Repository mapped to the selected project.");
    } catch { toast.error("Could not map repository. It may already be linked to another project."); }
    finally { setBusy(false); }
  };

  const openCreate = (repository: Repository) => {
    setCreateTarget(repository);
    setProjectName(repository.name.split("/").pop() || repository.name);
    setSlug(projectSlug(repository));
    if (groups.length) setGroupId(String(groups[0].id));
  };

  const createProject = async (event: FormEvent) => {
    event.preventDefault();
    if (!createTarget || !groupId || !connectionId) return;
    setBusy(true);
    try {
      const created = await axios.post("/api/applications", {
        name: projectName,
        slug,
        groupId: Number(groupId),
        repositoryUrl: createTarget.url,
        description: "",
        assetCriticality: "medium",
      });
      try {
        const linked = await axios.post(`/api/applications/${created.data.id}/repository-link`, { connectionId: Number(connectionId), repositoryId: createTarget.id });
        setResult({ appId: created.data.id, token: created.data.apiToken, webhookUrl: linked.data.webhookUrl, webhookSecret: linked.data.webhookSecret });
      } catch {
        setResult({ appId: created.data.id, token: created.data.apiToken, linkError: true });
      }
      setCreateTarget(null);
      await load();
      toast.success("Project created from repository.");
    } catch { toast.error("Could not create the project. Check the project name, slug, and group permissions."); }
    finally { setBusy(false); }
  };

  const availableProviders = providers ? (["github", "gitlab"] as Provider[]).filter((provider) => providers[provider]?.enabled) : [];
  const resultOpen = !!result;

  return (
    <>
      <Card className="border-0 shadow-none">
        <div className="space-y-4 p-5 sm:p-6">
          <div className="flex items-start gap-3">
            <FolderGit2 className="mt-1 h-4 w-4 text-muted-foreground" />
            <div>
              <h2 className="text-lg font-semibold">Repository candidates</h2>
              <p className="mt-1 text-sm text-muted-foreground">Discover repositories, map one to an existing project, or create a project from it. AppGuard receives scanner reports from your CI.</p>
            </div>
          </div>

          {loadFailed && <p className="text-sm text-destructive">Could not load repository setup. Refresh the page and try again.</p>}
          {availableProviders.length === 0 ? (
            <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">Native repository providers are not configured on this AppGuard instance. CI report uploads remain available.</p>
          ) : <div className="flex flex-wrap gap-2">
            {availableProviders.map((provider) => <Button key={provider} variant="outline" size="sm" disabled={busy} onClick={() => connect(provider)}>Connect {provider === "github" ? "GitHub" : "GitLab"}</Button>)}
          </div>}

          {connections.length > 0 && <div className="space-y-3 border-t pt-4">
            <div className="flex flex-col gap-2 sm:flex-row">
              <select aria-label="Connected repository account" className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 text-sm" value={connectionId} onChange={(event) => { setConnectionId(event.target.value); setRepositories([]); }}>
                <option value="">Choose a connected account</option>
                {connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.provider} · {connection.accountName}</option>)}
              </select>
              <Button variant="outline" size="sm" disabled={!connectionId || busy} onClick={discover}>{busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <GitBranch className="mr-1.5 h-4 w-4" />}Discover repositories</Button>
            </div>

            {repositories.length > 0 && <>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <Label className="shrink-0" htmlFor="candidate-project">Map to existing project</Label>
                <select id="candidate-project" className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 text-sm" value={applicationId} onChange={(event) => setApplicationId(event.target.value)}>
                  <option value="">Choose a project</option>
                  {applications.map((application) => <option key={application.id} value={application.id}>{application.name}</option>)}
                </select>
              </div>
              <div className="divide-y rounded-lg border">
                {repositories.map((repository) => <div key={repository.id} className="flex flex-col gap-3 p-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <a href={repository.url} target="_blank" rel="noreferrer" className="inline-flex max-w-full items-center gap-1.5 truncate text-sm font-medium hover:underline"><span className="truncate">{repository.path}</span><ExternalLink className="h-3.5 w-3.5 shrink-0" /></a>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <Button size="sm" variant="outline" disabled={!applicationId || busy} onClick={() => linkToApplication(repository)}><GitBranch className="mr-1.5 h-3.5 w-3.5" />Map project</Button>
                    <Button size="sm" disabled={!groups.length || busy} onClick={() => openCreate(repository)}><Plus className="mr-1.5 h-3.5 w-3.5" />Create project</Button>
                  </div>
                </div>)}
              </div>
            </>}
            {connections.length > 0 && applications.length === 0 && <p className="text-xs text-muted-foreground">Create a project from one of these repositories, or add an existing project first.</p>}
          </div>}
        </div>
      </Card>

      <Dialog open={!!createTarget} onOpenChange={(open) => !open && setCreateTarget(null)}>
        <DialogContent>
          <form onSubmit={createProject}>
            <DialogHeader>
              <DialogTitle>Create project from repository</DialogTitle>
              <DialogDescription>{createTarget?.path} will become the project&apos;s repository and be linked to the provider account.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-5">
              <div className="grid gap-2"><Label htmlFor="candidate-name">Project name</Label><Input id="candidate-name" value={projectName} onChange={(event) => setProjectName(event.target.value)} maxLength={200} required /></div>
              <div className="grid gap-2"><Label htmlFor="candidate-slug">Project slug</Label><Input id="candidate-slug" value={slug} onChange={(event) => setSlug(event.target.value)} maxLength={100} required /></div>
              <div className="grid gap-2"><Label htmlFor="candidate-group">Group</Label><select id="candidate-group" className="h-9 rounded-md border bg-background px-3 text-sm" value={groupId} onChange={(event) => setGroupId(event.target.value)} required>{groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</select></div>
            </div>
            <DialogFooter><Button type="button" variant="outline" onClick={() => setCreateTarget(null)}>Cancel</Button><Button type="submit" disabled={busy || !projectName.trim() || !slug.trim() || !groupId}>{busy && <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />}Create project</Button></DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={resultOpen} onOpenChange={(open) => { if (!open) setResult(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{result?.linkError ? "Project created; repository needs linking" : result?.webhookSecret ? "Configure the GitLab webhook" : "Project connected"}</DialogTitle>
            <DialogDescription>
              {result?.linkError ? "The project was created, but this repository could not be linked. Open the project Integrations tab to finish the mapping." : result?.webhookSecret ? "Add this URL and secret to the GitLab project webhook settings and enable Push events." : result?.token ? "Save the project API token in your CI secret store. AppGuard will receive reports uploaded by your scanner." : "The repository is mapped to the selected AppGuard project."}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-3">
            {result?.token && <label className="grid gap-1 text-xs font-medium">Project API token<input readOnly value={result.token} className="h-9 rounded-md border bg-muted/40 px-3 font-mono text-xs" onFocus={(event) => event.currentTarget.select()} /></label>}
            {result?.webhookUrl && <label className="grid gap-1 text-xs font-medium">GitLab webhook URL<input readOnly value={result.webhookUrl} className="h-9 rounded-md border bg-muted/40 px-3 font-mono text-xs" onFocus={(event) => event.currentTarget.select()} /></label>}
            {result?.webhookSecret && <label className="grid gap-1 text-xs font-medium">Webhook secret (shown once)<input readOnly value={result.webhookSecret} className="h-9 rounded-md border bg-muted/40 px-3 font-mono text-xs" onFocus={(event) => event.currentTarget.select()} /></label>}
            {result?.linkError && result.appId && <p className="text-sm"><button className="text-primary underline" onClick={() => router.push(`/applications/${result.appId}?tab=integrations`)}>Open project integrations</button></p>}
          </div>
          <DialogFooter>
            {result?.token && <Button variant="outline" className="gap-1.5" onClick={() => { navigator.clipboard.writeText(result.token || ""); toast.success("Project token copied."); }}><Copy className="h-3.5 w-3.5" />Copy token</Button>}
            <Button onClick={() => setResult(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
