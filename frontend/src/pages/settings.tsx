import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  ArrowUpRight,
  CircleAlert,
  ScrollText,
  GitBranch,
  KeyRound,
  LockKeyhole,
  ScanLine,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import axios from "@/lib/api";
import type { ScannerType } from "@/lib/types";

type RepositoryProviders = {
  github: { enabled: boolean; permissions: string };
  gitlab: { enabled: boolean; permissions: string };
};

type SsoSettingsResponse = { vals: Record<string, string> };

function Status({ ready, label }: { ready: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${ready ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${ready ? "bg-emerald-500" : "bg-muted-foreground/50"}`} />
      {label}
    </span>
  );
}

function SettingsCard({
  icon,
  title,
  description,
  status,
  href,
  action,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  status?: React.ReactNode;
  href?: string;
  action?: string;
  children?: React.ReactNode;
}) {
  return (
    <Card className="flex h-full flex-col border-border/70 shadow-none">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-start gap-3">
            <span className="mt-0.5 rounded-md border bg-muted/50 p-2 text-muted-foreground">{icon}</span>
            <div className="min-w-0">
              <CardTitle className="text-base">{title}</CardTitle>
              <CardDescription className="mt-1.5 leading-relaxed">{description}</CardDescription>
            </div>
          </div>
          {status}
        </div>
      </CardHeader>
      {children && <CardContent className="flex-1 pt-0">{children}</CardContent>}
      {href && (
        <div className="mt-auto flex justify-end p-6 pt-2">
          <Button asChild variant="outline" size="sm" className="gap-1.5">
            <Link href={href}>{action || "Manage"}<ArrowUpRight className="h-3.5 w-3.5" /></Link>
          </Button>
        </div>
      )}
    </Card>
  );
}

export default function SettingsPage() {
  const router = useRouter();
  const { loggedIn, user, authChecked } = useAuth();
  const [loading, setLoading] = useState(true);
  const [scannerTypes, setScannerTypes] = useState<ScannerType[]>([]);
  const [scannerError, setScannerError] = useState(false);
  const [providers, setProviders] = useState<RepositoryProviders | null>(null);
  const [providersError, setProvidersError] = useState(false);
  const [ssoConfigured, setSsoConfigured] = useState<boolean | null>(null);
  const [ssoError, setSsoError] = useState(false);
  const ssoAvailable = Boolean(user?.features?.includes("sso"));

  useEffect(() => {
    if (!authChecked) return;
    if (!loggedIn) { router.replace("/login"); return; }
    if (user?.role !== "admin") { router.replace("/"); return; }

    let cancelled = false;
    setLoading(true);
    Promise.allSettled([
      axios.get<ScannerType[]>("/api/scanner-types"),
      axios.get<RepositoryProviders>("/api/repository-connections/providers"),
      ssoAvailable ? axios.get<SsoSettingsResponse>("/api/admin/settings/sso") : Promise.resolve(null),
    ]).then(([scannerResult, providerResult, ssoResult]) => {
      if (cancelled) return;
      if (scannerResult.status === "fulfilled") setScannerTypes(scannerResult.value.data || []);
      else setScannerError(true);
      if (providerResult.status === "fulfilled") setProviders(providerResult.value.data);
      else setProvidersError(true);
      if (ssoAvailable && ssoResult.status === "fulfilled" && ssoResult.value) {
        const vals = ssoResult.value.data.vals || {};
        const configured = [
          [vals.sso_github_client_id, vals.sso_github_client_secret],
          [vals.sso_gitlab_client_id, vals.sso_gitlab_client_secret],
          [vals.sso_oidc_client_id, vals.sso_oidc_client_secret, vals.sso_oidc_issuer_url],
        ].some((fields) => fields.every((value) => Boolean(value?.trim())));
        setSsoConfigured(configured);
      } else if (ssoAvailable) {
        setSsoError(true);
      }
      setLoading(false);
    });

    return () => { cancelled = true; };
  }, [authChecked, loggedIn, router, user, ssoAvailable]);

  if (!authChecked || !loggedIn || user?.role !== "admin") {
    return <div className="space-y-4"><Skeleton className="h-5 w-40" /><Skeleton className="h-24 w-full" /><Skeleton className="h-48 w-full" /></div>;
  }

  const enabledScanners = scannerTypes.filter((scanner) => scanner.enabled).length;

  return (
    <div className="space-y-6">
      <PageHeader crumbs={[{ label: "Administration" }, { label: "Settings" }]} />
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">Manage instance access, scanner capabilities, and provider connections from one place.</p>
      </div>

      <section aria-labelledby="settings-access-heading" className="space-y-3">
        <div>
          <h2 id="settings-access-heading" className="text-sm font-semibold">Access and security</h2>
          <p className="mt-1 text-xs text-muted-foreground">Identity configuration and administrative controls.</p>
        </div>
        <div className="grid gap-4 xl:grid-cols-3">
          <SettingsCard
            icon={<KeyRound className="h-4 w-4" />}
            title="Single sign-on"
            description={ssoAvailable ? "Configure GitHub, GitLab, or OIDC sign-in for this instance." : "Single sign-on is not available for this AppGuard license."}
            status={ssoAvailable ? loading || ssoConfigured === null && !ssoError ? <Status ready={false} label="Checking" /> : ssoError ? <Status ready={false} label="Could not check" /> : <Status ready={Boolean(ssoConfigured)} label={ssoConfigured ? "Configured" : "Needs setup"} /> : <Status ready={false} label="Unavailable" />}
            href={ssoAvailable ? "/admin/sso" : undefined}
            action="Configure SSO"
          />
          <SettingsCard
            icon={<ShieldCheck className="h-4 w-4" />}
            title="Permissions"
            description="Review role and resource access rules for users and teams."
            href="/admin/permissions"
            action="Manage permissions"
          />
          {user.features?.includes("audit_log") && <SettingsCard
            icon={<ScrollText className="h-4 w-4" />}
            title="Audit log"
            description="Review administrative and security-sensitive activity for this instance."
            href="/admin/audit-log"
            action="View audit log"
          />}
        </div>
      </section>

      <section aria-labelledby="settings-integrations-heading" className="space-y-3">
        <div>
          <h2 id="settings-integrations-heading" className="text-sm font-semibold">Security integrations</h2>
          <p className="mt-1 text-xs text-muted-foreground">Choose supported report types and check repository-provider readiness.</p>
        </div>
        <div className="grid gap-4 xl:grid-cols-2">
          <SettingsCard
            icon={<ScanLine className="h-4 w-4" />}
            title="Scanner catalog"
            description="Enable or disable scanner types that projects can connect to and report into AppGuard."
            status={loading ? <Status ready={false} label="Loading" /> : scannerError ? <Status ready={false} label="Unavailable" /> : <Status ready={enabledScanners > 0} label={`${enabledScanners} of ${scannerTypes.length} enabled`} />}
            href="/admin/scanner-types"
            action="Manage scanners"
          />
          <SettingsCard
            icon={<GitBranch className="h-4 w-4" />}
            title="Repository providers"
            description="GitHub and GitLab credentials are supplied through deployment configuration. Repository links and connected accounts are managed in Integrations."
            href="/integrations"
            action="Open integrations"
          >
            {providersError ? (
              <p className="text-xs text-destructive">Could not read provider configuration.</p>
            ) : providers ? (
              <div className="flex flex-wrap gap-x-5 gap-y-2">
                <Status ready={providers.github.enabled} label={`GitHub · ${providers.github.enabled ? providers.github.permissions : "not configured"}`} />
                <Status ready={providers.gitlab.enabled} label={`GitLab · ${providers.gitlab.enabled ? providers.gitlab.permissions : "not configured"}`} />
              </div>
            ) : <Skeleton className="h-4 w-48" />}
          </SettingsCard>
        </div>
      </section>

      <section aria-labelledby="settings-instance-heading" className="space-y-3">
        <div>
          <h2 id="settings-instance-heading" className="text-sm font-semibold">Deployment-managed settings</h2>
          <p className="mt-1 text-xs text-muted-foreground">These values affect the whole instance and are configured where AppGuard is deployed.</p>
        </div>
        <Card className="border-border/70 shadow-none">
          <CardContent className="flex flex-col gap-4 p-5 sm:flex-row sm:items-start">
            <span className="rounded-md border bg-muted/50 p-2 text-muted-foreground"><LockKeyhole className="h-4 w-4" /></span>
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-medium">Environment and Helm values</h3>
              <p className="mt-1 text-sm leading-relaxed text-muted-foreground">Public URL, registration policy, encryption keys, GitHub App private key, database access, and network settings remain in deployment configuration. Repository-provider credentials are supplied there too. SSO client credentials are managed in Single sign-on and stored encrypted. Secrets are never shown in this hub.</p>
              <p className="mt-3 flex items-start gap-2 text-xs text-muted-foreground"><CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />Provider configuration changes take effect after the backend restarts. Keep secret values in your deployment secret store.</p>
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
