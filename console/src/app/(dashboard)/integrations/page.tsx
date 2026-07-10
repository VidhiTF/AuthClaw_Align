"use client";

import { useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Cloud, GitBranch, KeyRound, Play, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { EmptyState } from '@/components/shared/states';
import { TableSkeleton } from '@/components/shared/loaders';
import { useAuth } from '@/hooks/use-auth';
import {
  CloudIntegration,
  CloudProvider,
  IntegrationValidationResult,
  useCreateIntegration,
  useDeleteIntegration,
  useIntegrationHealth,
  useIntegrations,
  useRequestIntegrationSync,
  useValidateExistingIntegration,
  useValidateIntegration,
} from '@/hooks/use-data';

type FormState = {
  provider_type: CloudProvider;
  target_identifier: string;
  display_name: string;
  aws_region: string;
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_session_token: string;
  aws_role_arn: string;
  aws_external_id: string;
  github_token: string;
  github_org: string;
  gcp_project_id: string;
  gcp_service_account_json: string;
  azure_client_id: string;
  azure_client_secret: string;
  azure_tenant_id: string;
};

type RoleAwareUser = {
  role?: string;
  role_name?: string;
  roles?: string[];
};

type ApiError = {
  response?: { data?: { detail?: string } };
  message?: string;
};

const initialForm: FormState = {
  provider_type: 'aws',
  target_identifier: '',
  display_name: '',
  aws_region: 'us-east-1',
  aws_access_key_id: '',
  aws_secret_access_key: '',
  aws_session_token: '',
  aws_role_arn: '',
  aws_external_id: '',
  github_token: '',
  github_org: '',
  gcp_project_id: '',
  gcp_service_account_json: '',
  azure_client_id: '',
  azure_client_secret: '',
  azure_tenant_id: '',
};

function userCanWrite(user: unknown) {
  const roleUser = (user || {}) as RoleAwareUser;
  const roles = [
    roleUser.role,
    roleUser.role_name,
    ...(Array.isArray(roleUser.roles) ? roleUser.roles : []),
  ].filter((role): role is string => typeof role === 'string' && role.length > 0).map((role) => role.toLowerCase());
  if (roles.length === 0) return true;
  return roles.some((role: string) => ['owner', 'admin', 'security_admin'].includes(role));
}

function errorMessage(error: unknown) {
  const apiError = error as ApiError;
  return apiError?.response?.data?.detail || apiError?.message || 'Request failed';
}

function parseJsonObject(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? parsed as Record<string, unknown>
    : {};
}

function providerIcon(provider: string) {
  if (provider === 'github') return GitBranch;
  if (provider === 'gcp') return Cloud;
  if (provider === 'azure') return Cloud;
  return ShieldCheck;
}

function statusTone(status: string) {
  switch (status) {
    case 'active':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'syncing':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    case 'error':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'disabled':
      return 'bg-neutral-800 text-neutral-400 border-neutral-700';
    default:
      return 'bg-white/5 text-neutral-400 border-white/10';
  }
}

function buildPayload(form: FormState) {
  const target =
    form.provider_type === 'github'
      ? form.github_org || form.target_identifier
      : form.provider_type === 'gcp'
        ? form.gcp_project_id || form.target_identifier
        : form.target_identifier;

  const credentials: Record<string, unknown> = {};
  if (form.provider_type === 'aws') {
    credentials.aws_region = form.aws_region;
    if (form.aws_access_key_id) credentials.aws_access_key_id = form.aws_access_key_id;
    if (form.aws_secret_access_key) credentials.aws_secret_access_key = form.aws_secret_access_key;
    if (form.aws_session_token) credentials.aws_session_token = form.aws_session_token;
    if (form.aws_role_arn) credentials.aws_role_arn = form.aws_role_arn;
    if (form.aws_external_id) credentials.external_id = form.aws_external_id;
  }
  if (form.provider_type === 'github') {
    credentials.github_org = target;
    credentials.github_token = form.github_token;
  }
  if (form.provider_type === 'gcp') {
    credentials.project_id = target;
    if (form.gcp_service_account_json) {
      try {
        Object.assign(credentials, parseJsonObject(form.gcp_service_account_json));
      } catch {
        credentials.service_account_json = form.gcp_service_account_json;
      }
    }
  }
  if (form.provider_type === 'azure') {
    credentials.azure_client_id = form.azure_client_id;
    credentials.azure_client_secret = form.azure_client_secret;
    credentials.azure_tenant_id = form.azure_tenant_id;
  }
  return {
    provider_type: form.provider_type,
    target_identifier: target,
    display_name: form.display_name || undefined,
    credentials,
  };
}

function clearSecrets(form: FormState): FormState {
  return {
    ...form,
    aws_access_key_id: '',
    aws_secret_access_key: '',
    aws_session_token: '',
    github_token: '',
    gcp_service_account_json: '',
    azure_client_secret: '',
  };
}

function ValidationPanel({ result }: { result: IntegrationValidationResult | null }) {
  if (!result) return null;
  return (
    <div className={`rounded-md border p-3 text-sm ${result.valid ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/20 bg-amber-500/10 text-amber-300'}`}>
      <div className="flex items-center gap-2 font-medium">
        {result.valid ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
        {result.valid ? 'Credentials valid' : 'Validation failed'}
      </div>
      {!result.valid && result.error_code && <p className="mt-2 text-xs text-neutral-300">{result.error_code}</p>}
      {result.missing_permissions?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {result.missing_permissions.map((permission) => (
            <Badge key={permission} variant="outline" className="border-amber-500/20 text-amber-300">{permission}</Badge>
          ))}
        </div>
      )}
    </div>
  );
}

export default function IntegrationsPage() {
  const { user } = useAuth();
  const canWrite = userCanWrite(user);
  const [showCreate, setShowCreate] = useState(false);
  const [queued, setQueued] = useState<Record<string, boolean>>({});
  const [validation, setValidation] = useState<IntegrationValidationResult | null>(null);
  const [form, setForm] = useState<FormState>(initialForm);

  const integrationsQuery = useIntegrations({ skip: 0, limit: 100 });
  const healthQuery = useIntegrationHealth();
  const createMutation = useCreateIntegration();
  const deleteMutation = useDeleteIntegration();
  const validateMutation = useValidateIntegration();
  const validateExistingMutation = useValidateExistingIntegration();
  const syncMutation = useRequestIntegrationSync();

  const integrations = integrationsQuery.data?.items || [];
  const healthById = useMemo(() => {
    const items = healthQuery.data?.items || [];
    return Object.fromEntries(items.map((item) => [item.integration_id, item]));
  }, [healthQuery.data]);

  const validateCurrent = async () => {
    try {
      const result = await validateMutation.mutateAsync(buildPayload(form));
      setValidation(result);
      setForm((current) => clearSecrets(current));
      toast[result.valid ? 'success' : 'warning'](result.valid ? 'Credentials validated' : 'Validation failed');
    } catch (err: unknown) {
      setForm((current) => clearSecrets(current));
      toast.error(errorMessage(err));
    }
  };

  const createCurrent = async () => {
    try {
      await createMutation.mutateAsync(buildPayload(form));
      toast.success('Integration created');
      setShowCreate(false);
      setValidation(null);
      setForm(initialForm);
    } catch (err: unknown) {
      setForm((current) => clearSecrets(current));
      toast.error(errorMessage(err));
    }
  };

  const revalidate = async (integration: CloudIntegration) => {
    try {
      const result = await validateExistingMutation.mutateAsync(integration.id);
      toast[result.valid ? 'success' : 'warning'](result.valid ? 'Integration valid' : result.error_code || 'Validation failed');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const sync = async (integration: CloudIntegration) => {
    setQueued((current) => ({ ...current, [integration.id]: true }));
    try {
      await syncMutation.mutateAsync(integration.id);
      toast.success('Sync requested', { description: 'ConnectorWorker will execute the scan asynchronously.' });
      setTimeout(() => setQueued((current) => ({ ...current, [integration.id]: false })), 4000);
    } catch (err: unknown) {
      setQueued((current) => ({ ...current, [integration.id]: false }));
      toast.error(errorMessage(err));
    }
  };

  const disableIntegration = async (integration: CloudIntegration) => {
    if (!window.confirm(`Disable ${integration.display_name || integration.target_identifier}?`)) return;
    try {
      await deleteMutation.mutateAsync(integration.id);
      toast.success('Integration disabled');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100">Cloud Integrations</h2>
          <p className="text-sm text-neutral-400 mt-1">Manage connector credentials, validation, health, and scan scheduling.</p>
        </div>
        <Button onClick={() => setShowCreate(true)} disabled={!canWrite}>
          <Plus className="w-4 h-4 mr-2" /> Add integration
        </Button>
      </div>

      {!canWrite && (
        <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">Your role can view integrations, but write actions are disabled.</div>
      )}

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2"><Cloud className="w-4 h-4 text-neutral-500" /> Configured integrations</CardTitle>
          <Button variant="ghost" size="sm" onClick={() => { integrationsQuery.refetch(); healthQuery.refetch(); }}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </Button>
        </div>
        {integrationsQuery.isLoading ? (
          <div className="p-4"><TableSkeleton columns={7} rows={6} /></div>
        ) : integrations.length === 0 ? (
          <EmptyState title="No integrations yet" description="Add AWS, GitHub, GCP, or Azure to start ingesting persisted security findings." icon={Cloud} action={canWrite ? { label: 'Add integration', onClick: () => setShowCreate(true) } : undefined} />
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead className="bg-neutral-900/90 border-b border-white/5">
                <tr>
                  {['Provider', 'Target', 'Status', 'Health', 'Last sync', 'Findings', 'Actions'].map((header) => (
                    <th key={header} className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">{header}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {integrations.map((integration) => {
                  const Icon = providerIcon(integration.provider_type);
                  const health = healthById[integration.id];
                  const breakerState = String(health?.circuit_breaker_state?.state || 'unknown').toLowerCase();
                  const syncDisabled = !canWrite || integration.status === 'disabled' || integration.status === 'syncing' || queued[integration.id] || syncMutation.isPending;
                  return (
                    <tr key={integration.id} className="hover:bg-white/[0.02]">
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-md bg-white/5 border border-white/10 flex items-center justify-center"><Icon className="w-4 h-4 text-blue-300" /></div>
                          <div>
                            <div className="text-neutral-100 font-medium uppercase">{integration.provider_type}</div>
                            <div className="text-xs text-neutral-500">{integration.display_name || 'Unnamed'}</div>
                          </div>
                        </div>
                      </td>
                      <td className="p-4 text-neutral-300 font-mono text-xs">{integration.target_identifier}</td>
                      <td className="p-4"><Badge variant="outline" className={statusTone(integration.status)}>{integration.status}</Badge></td>
                      <td className="p-4">
                        <div className="space-y-1 text-xs">
                          <div className={health?.registered_connector_available ? 'text-emerald-400' : 'text-red-400'}>
                            {health?.registered_connector_available ? 'registered' : 'unregistered'}
                          </div>
                          <div className={breakerState === 'open' ? 'text-red-400' : 'text-neutral-500'}>breaker: {breakerState}</div>
                          {health?.last_error_code && <div className="text-amber-300 max-w-[220px] truncate">{health.last_error_code}</div>}
                        </div>
                      </td>
                      <td className="p-4 text-neutral-400 text-xs">{integration.last_sync_at ? new Date(integration.last_sync_at).toLocaleString() : 'Never'}</td>
                      <td className="p-4 text-neutral-300">{integration.last_sync_finding_count}</td>
                      <td className="p-4">
                        <div className="flex flex-wrap gap-2">
                          <Button size="sm" variant="outline" onClick={() => revalidate(integration)} disabled={!canWrite || validateExistingMutation.isPending}>
                            <ShieldCheck className="w-3.5 h-3.5 mr-1" /> Validate
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => sync(integration)} disabled={syncDisabled}>
                            <Play className="w-3.5 h-3.5 mr-1" /> {queued[integration.id] ? 'Queued' : 'Sync'}
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => disableIntegration(integration)} disabled={!canWrite || integration.status === 'disabled' || deleteMutation.isPending}>
                            <Trash2 className="w-3.5 h-3.5 mr-1" /> Disable
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Dialog open={showCreate} onOpenChange={(open) => { setShowCreate(open); if (!open) { setForm(initialForm); setValidation(null); } }}>
        <DialogContent className="max-w-3xl bg-[#0a0a0a] border-white/10 text-neutral-100">
          <DialogHeader>
            <DialogTitle>Add cloud integration</DialogTitle>
            <DialogDescription>Credentials are sent directly to the API for validation and Vault storage. Secret fields are never prefilled.</DialogDescription>
          </DialogHeader>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-wider text-neutral-500">Provider</label>
              <select aria-label="Provider" value={form.provider_type} onChange={(event) => { setValidation(null); setForm({ ...initialForm, provider_type: event.target.value as CloudProvider }); }} className="w-full h-10 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm">
                <option value="aws">AWS</option>
                <option value="github">GitHub</option>
                <option value="gcp">GCP</option>
                <option value="azure">Azure</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-wider text-neutral-500">Display name</label>
              <Input aria-label="Display name" value={form.display_name} onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))} placeholder="Production account" className="bg-black/40 border-white/10 text-neutral-100" />
            </div>

            {form.provider_type === 'aws' && (
              <>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">AWS account ID</label><Input aria-label="AWS account ID" value={form.target_identifier} onChange={(e) => setForm((f) => ({ ...f, target_identifier: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Default region</label><Input aria-label="Default region" value={form.aws_region} onChange={(e) => setForm((f) => ({ ...f, aws_region: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Access key</label><Input aria-label="Access key" type="password" autoComplete="new-password" value={form.aws_access_key_id} onChange={(e) => setForm((f) => ({ ...f, aws_access_key_id: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Secret key</label><Input aria-label="Secret key" type="password" autoComplete="new-password" value={form.aws_secret_access_key} onChange={(e) => setForm((f) => ({ ...f, aws_secret_access_key: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Session token</label><Input aria-label="Session token" type="password" autoComplete="new-password" value={form.aws_session_token} onChange={(e) => setForm((f) => ({ ...f, aws_session_token: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Role ARN / external ID</label><Input aria-label="Role ARN / external ID" value={form.aws_role_arn} onChange={(e) => setForm((f) => ({ ...f, aws_role_arn: e.target.value }))} placeholder="arn:aws:iam::..." className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
              </>
            )}
            {form.provider_type === 'github' && (
              <>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Org or repo target</label><Input aria-label="Org or repo target" value={form.github_org} onChange={(e) => setForm((f) => ({ ...f, github_org: e.target.value, target_identifier: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">GitHub token</label><Input aria-label="GitHub token" type="password" autoComplete="new-password" value={form.github_token} onChange={(e) => setForm((f) => ({ ...f, github_token: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
              </>
            )}
            {form.provider_type === 'gcp' && (
              <>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Project ID</label><Input aria-label="Project ID" value={form.gcp_project_id} onChange={(e) => setForm((f) => ({ ...f, gcp_project_id: e.target.value, target_identifier: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5 md:col-span-2"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Service account JSON</label><textarea aria-label="Service account JSON" value={form.gcp_service_account_json} onChange={(e) => setForm((f) => ({ ...f, gcp_service_account_json: e.target.value }))} rows={5} className="w-full rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 py-2 text-xs font-mono" /></div>
              </>
            )}
            {form.provider_type === 'azure' && (
              <>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Subscription ID</label><Input aria-label="Subscription ID" value={form.target_identifier} onChange={(e) => setForm((f) => ({ ...f, target_identifier: e.target.value }))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Tenant ID</label><Input aria-label="Tenant ID" value={form.azure_tenant_id} onChange={(e) => setForm((f) => ({ ...f, azure_tenant_id: e.target.value }))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Client ID (App ID)</label><Input aria-label="Client ID" value={form.azure_client_id} onChange={(e) => setForm((f) => ({ ...f, azure_client_id: e.target.value }))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
                <div className="space-y-1.5"><label className="text-[10px] uppercase tracking-wider text-neutral-500">Client secret</label><Input aria-label="Client secret" type="password" autoComplete="new-password" value={form.azure_client_secret} onChange={(e) => setForm((f) => ({ ...f, azure_client_secret: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100 font-mono" /></div>
              </>
            )}
            <div className="md:col-span-2"><ValidationPanel result={validation} /></div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={validateCurrent} disabled={validateMutation.isPending}><KeyRound className="w-4 h-4 mr-1" /> Validate</Button>
            <Button onClick={createCurrent} disabled={createMutation.isPending}>Create integration</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
