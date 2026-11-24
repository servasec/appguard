import { useEffect, useState } from "react";
import { Check, ExternalLink, GitBranch, Link2, Loader2, Unplug } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import axios from "@/lib/api";
import type { Application } from "@/lib/types";

type Provider = "github" | "gitlab";
type Connection = { id: number; provider: Provider; accountName: string; status: string };
type Repository = { id: string; name: string; path: string; url: string };
type Link = { id: number; provider: Provider; repositoryPath: string; repositoryUrl: string; webhookStatus: string; lastWebhookAt?: string };
type ProviderOptions = Record<Provider, { enabled: boolean }>;

export function RepositoryConnectionPanel({ application }: { application: Application }) {
  const [providers, setProviders] = useState<ProviderOptions | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [link, setLink] = useState<Link | null>(null);
  const [connectionId, setConnectionId] = useState("");
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [repositoryId, setRepositoryId] = useState("");
  const [webhookSetup, setWebhookSetup] = useState<{ url: string; secret: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    try {
      const [providersResponse, connectionsResponse, linkResponse] = await Promise.all([
        axios.get("/api/repository-connections/providers"),
        axios.get("/api/repository-connections/connections"),
        axios.get(`/api/applications/${application.id}/repository-link`),
      ]);
      setProviders(providersResponse.data);
      setConnections(connectionsResponse.data || []);
      setLink(linkResponse.data || null);
    } catch {
      toast.error("Could not load repository connections.");
    }
  };

  useEffect(() => { refresh(); }, [application.id]);

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
      const next = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
      window.history.replaceState(window.history.state, "", next);
    }
  }, []);

  const connect = async (provider: Provider) => {
    setBusy(true);
    try {
      const returnTo = `/applications/${application.id}?tab=integrations`;
      const response = await axios.get(`/api/repository-connections/providers/${provider}/authorize`, { params: { returnTo } });
      window.location.assign(response.data.authorizationUrl);
    } catch {
      toast.error(`Could not start ${provider === "github" ? "GitHub" : "GitLab"} authorization.`);
      setBusy(false);
    }
  };

  const loadRepositories = async () => {
    if (!connectionId) return;
    setBusy(true);
    try {
      const response = await axios.get(`/api/repository-connections/connections/${connectionId}/repositories`);
      setRepositories(response.data || []);
      setRepositoryId("");
      if (!response.data?.length) toast.message("No repositories are available for this connection.");
    } catch {
      toast.error("Could not load repositories. Reconnect the provider if its authorization expired.");
    } finally { setBusy(false); }
  };

  const linkRepository = async () => {
    if (!connectionId || !repositoryId) return;
    setBusy(true);
    try {
      const response = await axios.post(`/api/applications/${application.id}/repository-link`, { connectionId: Number(connectionId), repositoryId });
      setLink(response.data.link);
      if (response.data.webhookSecret) setWebhookSetup({ url: response.data.webhookUrl, secret: response.data.webhookSecret });
      setRepositories([]);
      toast.success("Repository linked to this project.");
    } catch {
      toast.error("Could not link this repository. It may already belong to another project.");
    } finally { setBusy(false); }
  };

  const unlinkRepository = async () => {
    setBusy(true);
    try {
      await axios.delete(`/api/applications/${application.id}/repository-link`);
      setLink(null);
      setWebhookSetup(null);
      toast.success("Repository disconnected.");
    } catch { toast.error("Could not disconnect the repository."); }
    finally { setBusy(false); }
  };

  const disconnect = async (connection: Connection) => {
    setBusy(true);
    try {
      await axios.delete(`/api/repository-connections/connections/${connection.id}`);
      if (connectionId === String(connection.id)) { setConnectionId(""); setRepositories([]); }
      await refresh();
      toast.success("Provider account disconnected.");
    } catch { toast.error("Unlink its repository from projects before disconnecting this account."); }
    finally { setBusy(false); }
  };

  const available = providers ? (["github", "gitlab"] as Provider[]).filter((provider) => providers[provider]?.enabled) : [];

  return (
    <Card className="border-0 shadow-none">
      <div className="p-5 sm:p-6">
        <div className="flex items-start gap-3">
          <GitBranch className="mt-1 h-4 w-4 text-muted-foreground" />
          <div>
            <h2 className="text-lg font-semibold">Repository connection</h2>
            <p className="mt-1 text-sm text-muted-foreground">Connect a repository to identify this project and receive push webhook health. Scans still run in your CI.</p>
          </div>
        </div>

        {link ? (
          <div className="mt-4 flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <a className="inline-flex max-w-full items-center gap-1.5 truncate text-sm font-medium hover:underline" href={link.repositoryUrl} target="_blank" rel="noreferrer">
                <span className="truncate">{link.repositoryPath}</span><ExternalLink className="h-3.5 w-3.5 shrink-0" />
              </a>
              <p className="mt-1 text-xs text-muted-foreground">{link.provider} · webhook {link.webhookStatus}{link.lastWebhookAt ? ` · last event ${new Date(link.lastWebhookAt).toLocaleString()}` : " · awaiting first event"}</p>
            </div>
            <Button variant="outline" size="sm" className="gap-1.5" disabled={busy} onClick={unlinkRepository}><Unplug className="h-3.5 w-3.5" />Disconnect repository</Button>
          </div>
        ) : available.length ? (
          <div className="mt-4 space-y-4">
            <div className="flex flex-wrap gap-2">
              {available.map((provider) => <Button key={provider} variant="outline" size="sm" disabled={busy} onClick={() => connect(provider)}>Connect {provider === "github" ? "GitHub" : "GitLab"}</Button>)}
            </div>
            {connections.length > 0 && <>
              <div className="flex flex-col gap-2 sm:flex-row">
                <select aria-label="Connected provider account" className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 text-sm" value={connectionId} onChange={(event) => { setConnectionId(event.target.value); setRepositories([]); }}>
                  <option value="">Choose a connected account</option>
                  {connections.map((connection) => <option key={connection.id} value={connection.id}>{connection.provider} · {connection.accountName}</option>)}
                </select>
                <Button variant="outline" size="sm" disabled={!connectionId || busy} onClick={loadRepositories}>{busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : null}Load repositories</Button>
              </div>
              {repositories.length > 0 && <div className="flex flex-col gap-2 sm:flex-row">
                <select aria-label="Repository to link" className="h-9 min-w-0 flex-1 rounded-md border bg-background px-3 text-sm" value={repositoryId} onChange={(event) => setRepositoryId(event.target.value)}>
                  <option value="">Choose a repository</option>
                  {repositories.map((repository) => <option key={repository.id} value={repository.id}>{repository.path}</option>)}
                </select>
                <Button size="sm" disabled={!repositoryId || busy} onClick={linkRepository}><Link2 className="mr-1.5 h-3.5 w-3.5" />Link repository</Button>
              </div>}
            </>}
            {connections.length > 0 && <div className="flex flex-wrap gap-x-4 gap-y-1 border-t pt-3">
              {connections.map((connection) => <button key={connection.id} type="button" className="text-xs text-muted-foreground hover:text-foreground" disabled={busy} onClick={() => disconnect(connection)}>Disconnect {connection.provider} · {connection.accountName}</button>)}
            </div>}
          </div>
        ) : <p className="mt-4 rounded-lg border border-dashed p-4 text-sm text-muted-foreground">Native repository connections are not configured on this AppGuard instance yet. CI report uploads remain available below.</p>}

        {webhookSetup && <div className="mt-4 space-y-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
          <p className="font-medium">Configure the GitLab project webhook</p>
          <p className="text-xs text-muted-foreground">Use the URL and secret below for Push events. The secret is shown only once.</p>
          <label className="block text-xs font-medium">Webhook URL<input readOnly value={webhookSetup.url} className="mt-1 h-9 w-full rounded-md border bg-background px-3 font-mono text-xs" onFocus={(event) => event.currentTarget.select()} /></label>
          <label className="block text-xs font-medium">Secret<input readOnly value={webhookSetup.secret} className="mt-1 h-9 w-full rounded-md border bg-background px-3 font-mono text-xs" onFocus={(event) => event.currentTarget.select()} /></label>
          <Button size="sm" variant="outline" className="gap-1.5" onClick={() => { navigator.clipboard.writeText(webhookSetup.secret); toast.success("Webhook secret copied."); }}><Check className="h-3.5 w-3.5" />Copy secret</Button>
        </div>}
      </div>
    </Card>
  );
}
