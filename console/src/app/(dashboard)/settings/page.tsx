"use client";

import { useState } from 'react';
import { Copy, Eye, EyeOff, Plus, Server, Trash2, Key, ShieldCheck, Building, KeyRound, Users, Gauge, UserPlus, Save } from 'lucide-react';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import {
  RateLimitTier,
  TenantUser,
  useApiKeys,
  useAssignTenantUserRoles,
  useCreateApiKey,
  useCreateProvider,
  useCreateTenantUser,
  useDeleteProvider,
  useDeleteTenantUser,
  useProviders,
  useRateLimitTiers,
  useRevokeApiKey,
  useTenantDetails,
  useTenantUsers,
  useUpdateTenantDetails,
  useUpdateTenantUser,
} from '@/hooks/use-data';
import { CardSkeleton } from '@/components/shared/loaders';
import { EmptyState } from '@/components/shared/states';
import { toast } from 'sonner';
import { useAuth } from '@/hooks/use-auth';
import { apiClient } from '@/lib/api-client';
import { QRCodeSVG } from 'qrcode.react';
import { motion, AnimatePresence } from 'framer-motion';

type Provider = {
  id: string;
  name: string;
  provider_type: string;
  key_prefix?: string | null;
  is_active?: boolean;
};

type ApiKeyRecord = {
  id: string;
  name: string;
  key_prefix: string;
  is_active?: boolean;
  created_at: string;
};

type CreatedApiKey = {
  key_prefix?: string;
  raw_key?: string;
  revoked_key_count?: number;
};

type ApiError = {
  response?: {
    data?: {
      detail?: string;
    };
  };
};

type RoleAwareUser = {
  role?: string;
  role_name?: string;
  roles?: string[];
};

function rolesFor(user: unknown) {
  const roleUser = (user || {}) as RoleAwareUser;
  const roles = [
    roleUser.role,
    roleUser.role_name,
    ...(Array.isArray(roleUser.roles) ? roleUser.roles : []),
  ].filter((role): role is string => typeof role === 'string' && role.length > 0).map((role) => role.toLowerCase());
  return roles.length ? roles : ['owner'];
}

function hasAnyRole(user: unknown, allowed: string[]) {
  return rolesFor(user).some((role) => allowed.includes(role));
}

function errorMessage(error: unknown) {
  const apiError = error as ApiError;
  return apiError.response?.data?.detail || 'Request failed';
}

export default function SettingsPage() {
  const { user } = useAuth();
  const canManageTenant = hasAnyRole(user, ['owner', 'admin']);
  
  // Providers
  const { data: providers = [], isLoading: loading } = useProviders();
  const createMutation = useCreateProvider();
  const deleteMutation = useDeleteProvider();

  const [showCreate, setShowCreate] = useState(false);
  const [newProvider, setNewProvider] = useState({
    name: '',
    provider_type: 'openai',
    api_key: '',
    base_url: '',
  });

  // API Keys
  const { data: apiKeysData, isLoading: apiKeysLoading } = useApiKeys(0, 100);
  const apiKeys = (Array.isArray(apiKeysData) ? apiKeysData : (apiKeysData?.items || [])) as ApiKeyRecord[];
  const createKeyMutation = useCreateApiKey();
  const revokeKeyMutation = useRevokeApiKey();
  const tenantQuery = useTenantDetails();
  const updateTenantMutation = useUpdateTenantDetails();
  const usersQuery = useTenantUsers();
  const createUserMutation = useCreateTenantUser();
  const updateUserMutation = useUpdateTenantUser();
  const assignRolesMutation = useAssignTenantUserRoles();
  const deleteUserMutation = useDeleteTenantUser();
  const rateTiersQuery = useRateLimitTiers();

  const [showCreateKey, setShowCreateKey] = useState(false);
  const [generatedApiKey, setGeneratedApiKey] = useState<{ rawKey?: string; keyPrefix?: string; visible: boolean } | null>(null);
  const [newApiKey, setNewApiKey] = useState({
    name: '',
    expires_in_days: 0,
  });
  const [tenantDraft, setTenantDraft] = useState<Partial<{ name: string; status: string; plan: string }>>({});
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [newUser, setNewUser] = useState({ email: '', first_name: '', last_name: '', password: '', role_name: 'viewer' });
  const tenantForm = {
    name: tenantDraft.name ?? tenantQuery.data?.name ?? '',
    status: tenantDraft.status ?? tenantQuery.data?.status ?? 'active',
    plan: tenantDraft.plan ?? tenantQuery.data?.plan ?? 'free',
  };

  // MFA
  const [showMfaSetup, setShowMfaSetup] = useState(false);
  const [mfaUri, setMfaUri] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaSetupLoading, setMfaSetupLoading] = useState(false);

  const startMfaSetup = async () => {
    try {
      setMfaSetupLoading(true);
      const res = await apiClient.post('/auth/mfa/setup');
      setMfaUri(res.data.uri);
      setShowMfaSetup(true);
    } catch {
      toast.error('Failed to start MFA setup');
    } finally {
      setMfaSetupLoading(false);
    }
  };

  const verifyMfa = async () => {
    try {
      setMfaSetupLoading(true);
      await apiClient.post('/auth/mfa/verify', { code: mfaCode });
      toast.success('MFA successfully enabled!');
      setShowMfaSetup(false);
      // Ideally we would refresh the user context here, but reloading works
      window.location.reload();
    } catch (err: unknown) {
      const apiError = err as ApiError;
      toast.error(apiError.response?.data?.detail || 'Invalid MFA code');
    } finally {
      setMfaSetupLoading(false);
    }
  };

  const createApiKey = async () => {
    try {
      const result = await createKeyMutation.mutateAsync({ ...newApiKey, scope: 'gateway_only' }) as CreatedApiKey;
      toast.success('Gateway API key created', {
        description: (result.revoked_key_count || 0) > 0 ? 'Previous active gateway key was revoked automatically.' : undefined,
      });
      setGeneratedApiKey({ rawKey: result.raw_key, keyPrefix: result.key_prefix, visible: false });
      setShowCreateKey(false);
      setNewApiKey({ name: '', expires_in_days: 0 });
    } catch (err: unknown) {
      const apiError = err as ApiError;
      toast.error(apiError.response?.data?.detail || 'Failed to create API key');
    }
  };

  const saveTenant = async () => {
    try {
      await updateTenantMutation.mutateAsync(tenantForm);
      toast.success('Tenant settings updated');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const createTenantUser = async () => {
    try {
      await createUserMutation.mutateAsync(newUser);
      toast.success('User created');
      setShowCreateUser(false);
      setNewUser({ email: '', first_name: '', last_name: '', password: '', role_name: 'viewer' });
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const setUserRole = async (tenantUser: TenantUser, role: string) => {
    try {
      await assignRolesMutation.mutateAsync({ id: tenantUser.id, roles: [role] });
      toast.success('User role updated');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const toggleUserActive = async (tenantUser: TenantUser) => {
    try {
      await updateUserMutation.mutateAsync({ id: tenantUser.id, data: { is_active: !tenantUser.is_active } });
      toast.success(tenantUser.is_active ? 'User deactivated' : 'User activated');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const removeTenantUser = async (id: string) => {
    try {
      await deleteUserMutation.mutateAsync(id);
      toast.success('User removed');
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    }
  };

  const copyGeneratedApiKey = async () => {
    if (!generatedApiKey?.rawKey) {
      toast.error('Raw API key is not available after creation');
      return;
    }
    try {
      await navigator.clipboard.writeText(generatedApiKey.rawKey);
      toast.success('Gateway API key copied');
    } catch {
      toast.error('Could not copy API key');
    }
  };

  const revokeApiKey = async (id: string) => {
    try {
      await revokeKeyMutation.mutateAsync(id);
      toast.success('API Key revoked');
    } catch {
      toast.error('Failed to revoke API key');
    }
  };

  const createProvider = async () => {
    try {
      const payload = {
        name: newProvider.name,
        type: newProvider.provider_type,
        api_key: newProvider.api_key,
        config: newProvider.base_url ? { base_url: newProvider.base_url } : {},
        is_active: true
      };
      await createMutation.mutateAsync(payload);
      toast.success('Provider created');
      setShowCreate(false);
      setNewProvider({ name: '', provider_type: 'openai', api_key: '', base_url: '' });
    } catch (err: unknown) {
      const apiError = err as ApiError;
      toast.error(apiError.response?.data?.detail || 'Failed to create provider');
    }
  };

  const deleteProvider = async (id: string) => {
    try {
      await deleteMutation.mutateAsync(id);
      toast.success('Provider deleted');
    } catch {
      toast.error('Failed to delete provider');
    }
  };

  const getProviderIcon = (type: string) => {
    const colors: Record<string, string> = {
      openai: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
      anthropic: 'bg-orange-500/10 text-orange-400 border border-orange-500/20',
      azure_openai: 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
      groq: 'bg-pink-500/10 text-pink-400 border border-pink-500/20',
    };
    return colors[type] || 'bg-white/5 text-neutral-400 border border-white/10';
  };

  return (
    <div className="space-y-10 max-w-[1200px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans">Settings</h2>
          <p className="text-sm text-neutral-400 mt-1">Manage your organization, identity, and integration credentials.</p>
        </div>
      </div>

      {/* Organization Info */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Card className="glass-card overflow-hidden">
          <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
            <Building className="w-4 h-4 text-neutral-500" />
            <CardTitle className="text-neutral-100 text-base">Organization Profile</CardTitle>
          </div>
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div>
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium block mb-1.5">User</label>
                <p className="text-sm text-neutral-200 font-medium">{user?.first_name} {user?.last_name}</p>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium block mb-1.5">Email</label>
                <p className="text-sm text-neutral-200">{user?.email}</p>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium block mb-1.5">Tenant ID</label>
                <p className="text-xs text-neutral-400 font-mono bg-black/40 px-2 py-1 rounded border border-white/5 inline-block">{user?.tenant_id}</p>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium block mb-1.5">Security</label>
                <div className="flex items-center gap-4">
                  <Badge variant="outline" className={user?.mfa_enabled ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 uppercase tracking-wider text-[10px]" : "bg-neutral-800 text-neutral-400 border-neutral-700 uppercase tracking-wider text-[10px]"}>
                    {user?.mfa_enabled ? 'MFA Enabled' : 'MFA Disabled'}
                  </Badge>
                  {!user?.mfa_enabled && (
                    <Button size="sm" variant="ghost" onClick={startMfaSetup} disabled={mfaSetupLoading} className="h-6 text-[10px] text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 uppercase tracking-wider font-bold">
                      Setup MFA
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      <Dialog open={showMfaSetup} onOpenChange={setShowMfaSetup}>
        <DialogContent className="sm:max-w-md bg-[#0a0a0a] border-white/10 text-neutral-100 p-0 overflow-hidden shadow-2xl">
          <DialogHeader className="p-6 border-b border-white/5 bg-white/[0.02]">
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
              Multi-Factor Authentication
            </DialogTitle>
            <DialogDescription className="text-neutral-400 text-xs mt-1">
              Scan this QR code with Google Authenticator, Authy, or your preferred authenticator app.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center justify-center p-6 space-y-6">
            <div className="bg-white p-3 rounded-xl shadow-lg">
              <QRCodeSVG value={mfaUri} size={200} />
            </div>
            <div className="text-center w-full">
              <p className="text-[10px] uppercase tracking-wider text-neutral-500 mb-2">Manual Entry</p>
              <p className="text-xs text-neutral-400 bg-black/40 p-3 rounded-lg border border-white/5">
                Manual MFA secret display is disabled for console safety. Use the QR code or restart setup from a trusted device.
              </p>
            </div>
            <div className="w-full pt-2">
              <p className="text-[10px] uppercase tracking-wider text-neutral-500 mb-2 text-center">Enter 6-digit code</p>
              <Input
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="000000"
                className="bg-black/40 border-white/10 text-neutral-100 text-center tracking-[1em] font-mono text-xl h-14"
                maxLength={6}
              />
            </div>
          </div>
          <DialogFooter className="p-4 border-t border-white/5 bg-white/[0.02] flex gap-2">
            <Button variant="ghost" onClick={() => setShowMfaSetup(false)} className="text-neutral-400 hover:text-white">Cancel</Button>
            <Button onClick={verifyMfa} disabled={mfaCode.length !== 6 || mfaSetupLoading} className="bg-blue-600 hover:bg-blue-500 text-white">Verify & Enable</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <motion.div className="space-y-4" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-neutral-100 flex items-center gap-2">
              <Building className="w-5 h-5 text-neutral-500" />
              Tenant Administration
            </h3>
            <p className="text-sm text-neutral-400 mt-1">Manage tenant status, plan tier, users, RBAC, API keys, and rate-limit tiers from one admin surface.</p>
          </div>
          {!canManageTenant && (
            <Badge variant="outline" className="bg-amber-500/10 text-amber-300 border-amber-500/20">Read-only role</Badge>
          )}
        </div>

        <Card className="glass-card">
          <CardContent className="p-5 space-y-4">
            <div className="grid md:grid-cols-4 gap-4">
              <div className="space-y-1.5">
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Tenant name</label>
                <Input value={tenantForm.name} disabled={!canManageTenant || tenantQuery.isLoading} onChange={(e) => setTenantDraft((current) => ({ ...current, name: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Tenant status</label>
                <select aria-label="Tenant status" value={tenantForm.status} disabled={!canManageTenant} onChange={(e) => setTenantDraft((current) => ({ ...current, status: e.target.value }))} className="w-full h-10 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm">
                  <option value="active">Active</option>
                  <option value="suspended">Suspended</option>
                  <option value="deactivated">Deactivated</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Rate-limit tier</label>
                <select aria-label="Rate-limit tier" value={tenantForm.plan} disabled={!canManageTenant} onChange={(e) => setTenantDraft((current) => ({ ...current, plan: e.target.value }))} className="w-full h-10 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm">
                  {['free', 'starter', 'professional', 'enterprise'].map((plan) => <option key={plan} value={plan}>{plan}</option>)}
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Tenant slug</label>
                <p className="h-10 flex items-center rounded-md border border-white/10 bg-black/40 px-3 text-xs font-mono text-neutral-400">{tenantQuery.data?.slug || 'loading'}</p>
              </div>
            </div>
            <div className="flex justify-end">
              <Button onClick={saveTenant} disabled={!canManageTenant || updateTenantMutation.isPending} className="bg-blue-600 hover:bg-blue-500 text-white">
                <Save className="w-4 h-4 mr-2" />
                Save Tenant
              </Button>
            </div>
          </CardContent>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="glass-card overflow-hidden">
            <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Users className="w-4 h-4 text-blue-400" />
                <CardTitle className="text-neutral-100 text-base">User management and RBAC</CardTitle>
              </div>
              <Button size="sm" variant="outline" disabled={!canManageTenant} onClick={() => setShowCreateUser((current) => !current)}>
                <UserPlus className="w-4 h-4 mr-2" />
                Add User
              </Button>
            </div>
            <CardContent className="p-0">
              <AnimatePresence>
                {showCreateUser && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden border-b border-white/5">
                    <div className="p-4 grid md:grid-cols-2 gap-3">
                      <Input aria-label="New user email" placeholder="email" value={newUser.email} onChange={(e) => setNewUser((current) => ({ ...current, email: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
                      <Input aria-label="New user password" placeholder="temporary password" type="password" value={newUser.password} onChange={(e) => setNewUser((current) => ({ ...current, password: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
                      <Input aria-label="New user first name" placeholder="first name" value={newUser.first_name} onChange={(e) => setNewUser((current) => ({ ...current, first_name: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
                      <Input aria-label="New user last name" placeholder="last name" value={newUser.last_name} onChange={(e) => setNewUser((current) => ({ ...current, last_name: e.target.value }))} className="bg-black/40 border-white/10 text-neutral-100" />
                      <select aria-label="New user role" value={newUser.role_name} onChange={(e) => setNewUser((current) => ({ ...current, role_name: e.target.value }))} className="h-10 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm">
                        {['viewer', 'analyst', 'auditor', 'operator', 'admin', 'owner'].map((role) => <option key={role} value={role}>{role}</option>)}
                      </select>
                      <Button onClick={createTenantUser} disabled={createUserMutation.isPending || !newUser.email || !newUser.password}>Create User</Button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
              {usersQuery.isLoading ? (
                <div className="p-4"><CardSkeleton /></div>
              ) : (usersQuery.data || []).length === 0 ? (
                <EmptyState title="No tenant users" description="Users with tenant roles appear here." icon={Users} />
              ) : (
                <div className="overflow-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-neutral-900/90 border-b border-white/5">
                      <tr>
                        {['User', 'Role', 'Status', 'Actions'].map((header) => <th key={header} className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">{header}</th>)}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {(usersQuery.data || []).map((tenantUser: TenantUser) => (
                        <tr key={tenantUser.id} className="hover:bg-white/[0.02]">
                          <td className="p-4">
                            <div className="font-medium text-neutral-100">{tenantUser.first_name || ''} {tenantUser.last_name || ''}</div>
                            <div className="text-xs text-neutral-500">{tenantUser.email}</div>
                          </td>
                          <td className="p-4">
                            <select aria-label={`Role for ${tenantUser.email}`} value={tenantUser.roles?.[0] || 'viewer'} disabled={!canManageTenant} onChange={(e) => setUserRole(tenantUser, e.target.value)} className="h-9 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-2 text-sm">
                              {['viewer', 'analyst', 'auditor', 'operator', 'admin', 'owner'].map((role) => <option key={role} value={role}>{role}</option>)}
                            </select>
                          </td>
                          <td className="p-4">
                            <Badge variant="outline" className={tenantUser.is_active ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-neutral-800 text-neutral-400 border-neutral-700'}>{tenantUser.is_active ? 'Active' : 'Disabled'}</Badge>
                          </td>
                          <td className="p-4">
                            <div className="flex flex-wrap gap-2">
                              <Button size="sm" variant="outline" disabled={!canManageTenant} onClick={() => toggleUserActive(tenantUser)}>{tenantUser.is_active ? 'Disable' : 'Enable'}</Button>
                              <Button size="sm" variant="outline" disabled={!canManageTenant || tenantUser.id === user?.id} onClick={() => removeTenantUser(tenantUser.id)}>Remove</Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="glass-card overflow-hidden">
            <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
              <Gauge className="w-4 h-4 text-blue-400" />
              <CardTitle className="text-neutral-100 text-base">Rate-limit tiers</CardTitle>
            </div>
            <CardContent className="p-0">
              {rateTiersQuery.isLoading ? (
                <div className="p-4"><CardSkeleton /></div>
              ) : (
                <div className="overflow-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-neutral-900/90 border-b border-white/5">
                      <tr>
                        {['Tier', 'RPM', 'Daily', 'Concurrent', 'Streams', 'Reports/hr'].map((header) => <th key={header} className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">{header}</th>)}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {(rateTiersQuery.data || []).map((tier: RateLimitTier) => (
                        <tr key={tier.plan_name} className={tenantForm.plan === tier.plan_name ? 'bg-blue-500/5' : 'hover:bg-white/[0.02]'}>
                          <td className="p-4"><Badge variant="outline" className={tenantForm.plan === tier.plan_name ? 'bg-blue-500/10 text-blue-300 border-blue-500/20' : 'bg-white/5 text-neutral-300 border-white/10'}>{tier.plan_name}</Badge></td>
                          <td className="p-4 text-neutral-300">{tier.requests_per_minute.toLocaleString()}</td>
                          <td className="p-4 text-neutral-300">{tier.requests_per_day.toLocaleString()}</td>
                          <td className="p-4 text-neutral-300">{tier.concurrent_gateway_requests.toLocaleString()}</td>
                          <td className="p-4 text-neutral-300">{tier.concurrent_streams.toLocaleString()}</td>
                          <td className="p-4 text-neutral-300">{tier.report_generation_per_hour.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </motion.div>

      {/* AI Providers */}
      <motion.div className="space-y-4" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-neutral-100 flex items-center gap-2">
              <Server className="w-5 h-5 text-neutral-500" />
              Upstream AI Providers
            </h3>
            <p className="text-sm text-neutral-400 mt-1">Configure your target LLM connections.</p>
          </div>
          <Button onClick={() => setShowCreate(!showCreate)} className="bg-white/10 hover:bg-white/20 text-white border border-white/5" disabled={createMutation.isPending}>
            <Plus className="w-4 h-4 mr-2" />
            Add Provider
          </Button>
        </div>

        <AnimatePresence>
          {showCreate && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
              <Card className="glass-card">
                <CardContent className="space-y-4 p-6">
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Provider Alias</label>
                      <Input
                        placeholder="e.g. Production OpenAI"
                        value={newProvider.name}
                        onChange={(e) => setNewProvider(p => ({ ...p, name: e.target.value }))}
                        className="bg-black/40 border-white/10 text-neutral-100 focus-visible:ring-blue-500/50"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Type</label>
                      <select
                        value={newProvider.provider_type}
                        onChange={(e) => setNewProvider(p => ({ ...p, provider_type: e.target.value }))}
                        className="w-full h-10 rounded-md bg-black/40 border border-white/10 text-neutral-100 px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                      >
                        <option value="openai">OpenAI</option>
                        <option value="anthropic">Anthropic</option>
                        <option value="azure_openai">Azure OpenAI</option>
                        <option value="groq">Groq</option>
                      </select>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">API Key</label>
                      <Input
                        type="password"
                        placeholder="sk-..."
                        value={newProvider.api_key}
                        onChange={(e) => setNewProvider(p => ({ ...p, api_key: e.target.value }))}
                        className="bg-black/40 border-white/10 text-neutral-100 focus-visible:ring-blue-500/50 font-mono"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Base URL (Optional)</label>
                      <Input
                        placeholder="https://api.openai.com/v1"
                        value={newProvider.base_url}
                        onChange={(e) => setNewProvider(p => ({ ...p, base_url: e.target.value }))}
                        className="bg-black/40 border-white/10 text-neutral-100 focus-visible:ring-blue-500/50 font-mono"
                      />
                    </div>
                  </div>
                  <div className="flex gap-3 pt-2">
                    <Button onClick={createProvider} disabled={createMutation.isPending} className="bg-blue-600 hover:bg-blue-500 text-white">Save Provider</Button>
                    <Button variant="ghost" onClick={() => setShowCreate(false)} className="text-neutral-400 hover:text-white">Cancel</Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {loading ? (
          <div className="grid md:grid-cols-2 gap-4"><CardSkeleton /><CardSkeleton /></div>
        ) : (providers as Provider[]).length === 0 ? (
          <EmptyState 
            title="No Upstream Providers" 
            description="Configure at least one upstream AI provider (e.g. OpenAI) to proxy traffic to."
            icon={Server}
            action={{
              label: "Add Provider",
              onClick: () => setShowCreate(true)
            }}
          />
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(providers as Provider[]).map((provider) => (
              <Card key={provider.id} className="glass-card hover:border-white/10 transition-colors group">
                <CardContent className="p-5 flex flex-col h-full">
                  <div className="flex items-start justify-between mb-4">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center shadow-inner ${getProviderIcon(provider.provider_type)}`}>
                      <Server className="w-6 h-6" />
                    </div>
                    <Button 
                      variant="ghost" 
                      size="icon"
                      onClick={() => deleteProvider(provider.id)}
                      disabled={deleteMutation.isPending}
                      className="h-8 w-8 text-neutral-500 hover:text-red-400 hover:bg-red-400/10 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-neutral-100 text-base">{provider.name}</h3>
                    <div className="flex gap-2 mt-2">
                      <Badge variant="outline" className="bg-white/5 border-white/10 text-neutral-400 text-[10px] uppercase tracking-wider">
                        {provider.provider_type}
                      </Badge>
                      <Badge variant="outline" className={provider.is_active ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 text-[10px] uppercase tracking-wider" : "bg-neutral-800 text-neutral-500 border-neutral-700 text-[10px] uppercase tracking-wider"}>
                        {provider.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                  </div>
                  <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs text-neutral-500 font-mono">
                      <Key className="w-3.5 h-3.5" />
                      {provider.key_prefix ? `${provider.key_prefix}••••••••` : 'stored in secret manager'}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </motion.div>

      {/* API Keys */}
      <motion.div className="space-y-4" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-neutral-100 flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-neutral-500" />
              Gateway API Keys
            </h3>
            <p className="text-sm text-neutral-400 mt-1">Manage the organization gateway token for the AuthClaw proxy. Creating a new key revokes the previous active gateway key.</p>
          </div>
          <Button onClick={() => setShowCreateKey(!showCreateKey)} className="bg-white/10 hover:bg-white/20 text-white border border-white/5" disabled={createKeyMutation.isPending}>
            <Plus className="w-4 h-4 mr-2" />
            Generate Key
          </Button>
        </div>

        <AnimatePresence>
          {showCreateKey && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
              <Card className="glass-card">
                <CardContent className="space-y-4 p-6">
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Key Name</label>
                      <Input
                        placeholder="e.g. Production Application Server"
                        value={newApiKey.name}
                        onChange={(e) => setNewApiKey(k => ({ ...k, name: e.target.value }))}
                        className="bg-black/40 border-white/10 text-neutral-100 focus-visible:ring-blue-500/50"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">Expiration (Days)</label>
                      <Input
                        type="number"
                        placeholder="Optional (leave 0 for no expiration)"
                        value={newApiKey.expires_in_days || ''}
                        onChange={(e) => setNewApiKey(k => ({ ...k, expires_in_days: parseInt(e.target.value) || 0 }))}
                        className="bg-black/40 border-white/10 text-neutral-100 focus-visible:ring-blue-500/50"
                      />
                    </div>
                  </div>
                  <div className="flex gap-3 pt-2">
                    <Button onClick={createApiKey} disabled={createKeyMutation.isPending} className="bg-blue-600 hover:bg-blue-500 text-white">Generate Token</Button>
                    <Button variant="ghost" onClick={() => setShowCreateKey(false)} className="text-neutral-400 hover:text-white">Cancel</Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        <Dialog open={!!generatedApiKey} onOpenChange={(open) => !open && setGeneratedApiKey(null)}>
          <DialogContent className="sm:max-w-md bg-[#0a0a0a] border-white/10 text-neutral-100 shadow-2xl p-0 overflow-hidden">
            <DialogHeader className="p-6 border-b border-white/5 bg-white/[0.02]">
              <DialogTitle className="text-xl flex items-center gap-2">
                <KeyRound className="w-5 h-5 text-amber-400" />
                Gateway API Key Created
              </DialogTitle>
              <DialogDescription className="text-neutral-400 mt-2 text-sm leading-relaxed">
                Copy this key now and store it securely. AuthClaw only shows the real gateway key once, immediately after generation.
              </DialogDescription>
            </DialogHeader>
            <div className="p-6 space-y-4">
              {generatedApiKey?.rawKey ? (
                <div className="space-y-2">
                  <label className="text-[10px] uppercase tracking-wider text-neutral-500 font-medium">AuthClaw Gateway API Key</label>
                  <div className="flex items-center gap-2">
                    <Input
                      readOnly
                      type={generatedApiKey.visible ? 'text' : 'password'}
                      value={generatedApiKey.rawKey}
                      className="bg-black/40 border-white/10 text-emerald-300 font-mono text-xs h-11"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      onClick={() => setGeneratedApiKey((current) => current ? { ...current, visible: !current.visible } : current)}
                      className="h-11 w-11 shrink-0"
                      title={generatedApiKey.visible ? 'Hide API key' : 'Show API key'}
                    >
                      {generatedApiKey.visible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      onClick={copyGeneratedApiKey}
                      className="h-11 w-11 shrink-0"
                      title="Copy API key"
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                  <p className="text-xs text-amber-300/90">
                    One-time reveal. Existing keys will only show their prefix later.
                  </p>
                </div>
              ) : (
                <p className="rounded-md border border-white/10 bg-black/40 p-3 text-sm text-neutral-300">
                  Created key prefix: {generatedApiKey?.keyPrefix || 'available in key list'}. Raw key was not returned by the API.
                </p>
              )}
            </div>
            <DialogFooter className="p-4 border-t border-white/5 bg-white/[0.02]">
              <Button type="button" onClick={() => setGeneratedApiKey(null)} className="w-full bg-blue-600 hover:bg-blue-500 text-white">
                Close
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {apiKeysLoading ? (
          <div className="grid gap-4"><CardSkeleton /></div>
        ) : apiKeys.length === 0 ? (
          <EmptyState 
            title="No API Keys Active" 
            description="Create an API key to authenticate your applications with the AuthClaw proxy."
            icon={KeyRound}
            action={{
              label: "Generate Key",
              onClick: () => setShowCreateKey(true)
            }}
          />
        ) : (
          <div className="grid gap-4">
            {apiKeys.map((apiKey) => (
              <Card key={apiKey.id} className="glass-card flex flex-col sm:flex-row items-start sm:items-center justify-between p-5 gap-4">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-neutral-400 shadow-inner">
                    <KeyRound className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="font-semibold text-neutral-100">{apiKey.name}</h3>
                      <Badge variant="outline" className={apiKey.is_active ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 text-[10px] uppercase tracking-wider" : "bg-neutral-800 text-neutral-500 border-neutral-700 text-[10px] uppercase tracking-wider"}>
                        {apiKey.is_active ? 'Active' : 'Revoked'}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 mt-2">
                      <p className="text-xs text-neutral-400 font-mono bg-black/40 px-2 py-0.5 rounded border border-white/5">
                        {apiKey.key_prefix}••••••••••••
                      </p>
                      <p className="text-xs text-neutral-500 hidden sm:block">
                        Created: {new Date(apiKey.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="w-full sm:w-auto flex justify-end">
                  <Button 
                    variant="ghost" 
                    size="sm"
                    onClick={() => revokeApiKey(apiKey.id)}
                    disabled={revokeKeyMutation.isPending}
                    className="text-neutral-500 hover:text-red-400 hover:bg-red-400/10 bg-black/20 border border-white/5 h-9 px-4"
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Revoke
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
}
