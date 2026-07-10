"use client";

import { useState } from 'react';
import { Plus, Network, Trash2, Edit, ChevronRight, Server, Search, Shield } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useGatewayRoutes, useCreateGatewayRoute, useUpdateGatewayRoute, useDeleteGatewayRoute, useProviders, usePolicies } from '@/hooks/use-data';
import { CardSkeleton } from '@/components/shared/loaders';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';

type GatewayRoute = {
  id: string;
  name: string;
  description?: string | null;
  provider_id?: string | null;
  is_default: boolean;
  is_active: boolean;
  redaction: string;
  config?: Record<string, unknown>;
  created_at: string;
};

type Provider = {
  id: string;
  name: string;
  type?: string;
};

type PolicyLite = {
  id?: string;
  policy_id?: string;
  name?: string;
  is_active?: boolean;
  priority?: number;
  policy?: { id?: string; name?: string; is_active?: boolean; priority?: number };
};

type GatewayRouteForm = {
  name: string;
  description: string;
  provider_id: string;
  model: string;
  policy_id: string;
  is_default: boolean;
  is_active: boolean;
  redaction: string;
};

type ApiError = {
  response?: {
    data?: {
      detail?: string;
    };
  };
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function getPolicyId(policy: PolicyLite) {
  const value = policy.id || policy.policy_id || policy.policy?.id || '';
  return UUID_RE.test(value) ? value : '';
}

// ─── Modal wrapper ─────────────────────────────────────────────────────────────

interface ModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}

function Modal({ title, onClose, children }: ModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <motion.div 
        initial={{ opacity: 0 }} 
        animate={{ opacity: 1 }} 
        exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div 
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="bg-[#0a0a0a] border border-white/10 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl relative z-10 overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-white/5 bg-white/[0.02] shrink-0">
          <h2 className="text-lg font-bold text-neutral-100 flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-400" />
            {title}
          </h2>
          <button 
            onClick={onClose}
            className="text-neutral-500 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>
        
        {/* Content Area - Scrollable */}
        <div className="flex-1 overflow-y-auto p-6 bg-transparent">
          {children}
        </div>
      </motion.div>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function GatewayRoutesPage() {
  const { data: routes, isLoading } = useGatewayRoutes();
  const { data: providers } = useProviders();
  const { data: policies } = usePolicies();
  const createMutation = useCreateGatewayRoute();
  const updateMutation = useUpdateGatewayRoute();
  const deleteMutation = useDeleteGatewayRoute();

  const [showCreate, setShowCreate] = useState(false);
  const [editingRoute, setEditingRoute] = useState<GatewayRoute | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // ── Form State ──
  const initialFormState: GatewayRouteForm = {
    name: '',
    description: '',
    provider_id: '',
    model: 'llama-3.1-8b-instant',
    policy_id: '',
    is_default: false,
    is_active: true,
    redaction: 'mask',
  };
  const [formData, setFormData] = useState<GatewayRouteForm>(initialFormState);

  // ── Handlers ──

  const handleOpenCreate = () => {
    setFormData(initialFormState);
    setShowCreate(true);
  };

  const handleOpenEdit = (route: GatewayRoute) => {
    setFormData({
      name: route.name,
      description: route.description || '',
      provider_id: route.provider_id || '',
      model: String(route.config?.model || route.config?.default_model || ''),
      policy_id: String(route.config?.policy_id || ''),
      is_default: route.is_default,
      is_active: route.is_active,
      redaction: route.redaction,
    });
    setEditingRoute(route);
  };

  const handleSave = async () => {
    if (!formData.provider_id) {
      toast.error('Select a provider before saving this route');
      return;
    }
    try {
      const payload: Record<string, unknown> = {
        name: formData.name,
        description: formData.description,
        provider_id: formData.provider_id,
        is_default: formData.is_default,
        is_active: formData.is_active,
        redaction: formData.redaction,
        config: {
          model: formData.model.trim() || undefined,
          policy_id: formData.policy_id || undefined,
        },
      };
      
      if (editingRoute) {
        await updateMutation.mutateAsync({ id: editingRoute.id, data: payload });
        toast.success(`Gateway route "${payload.name}" updated.`);
        setEditingRoute(null);
      } else {
        await createMutation.mutateAsync(payload);
        toast.success(`Gateway route "${payload.name}" created.`);
        setShowCreate(false);
      }
    } catch (err: unknown) {
      const apiError = err as ApiError;
      toast.error(apiError.response?.data?.detail || 'Failed to save gateway route');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete the gateway route "${name}"?`)) return;
    try {
      await deleteMutation.mutateAsync(id);
      toast.success(`Gateway route "${name}" deleted.`);
    } catch (err: unknown) {
      const apiError = err as ApiError;
      toast.error(apiError.response?.data?.detail || 'Failed to delete gateway route');
    }
  };

  const renderForm = () => (
    <div className="space-y-6">
      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-2 col-span-2">
          <label className="text-[11px] uppercase tracking-wider text-neutral-500 font-bold block">Route Name *</label>
          <input
            type="text"
            value={formData.name}
            onChange={e => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g. Production GPT-4 Route"
            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          />
        </div>
        
        <div className="space-y-2 col-span-2">
          <label className="text-[11px] uppercase tracking-wider text-neutral-500 font-bold block">Description</label>
          <input
            type="text"
            value={formData.description}
            onChange={e => setFormData({ ...formData, description: e.target.value })}
            placeholder="Optional description"
            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          />
        </div>

        <div className="space-y-2">
          <label className="text-[11px] uppercase tracking-wider text-neutral-500 font-bold block">Target Provider *</label>
          <select
            value={formData.provider_id}
            onChange={e => setFormData({ ...formData, provider_id: e.target.value })}
            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          >
            <option value="">Select provider</option>
            {(providers as Provider[] | undefined)?.map((p) => (
              <option key={p.id} value={p.id}>{p.name} ({p.type})</option>
            ))}
          </select>
        </div>

        <div className="space-y-2">
          <label className="text-[11px] uppercase tracking-wider text-neutral-500 font-bold block">Model Override *</label>
          <input
            type="text"
            value={formData.model}
            onChange={e => setFormData({ ...formData, model: e.target.value })}
            placeholder="e.g. llama-3.1-8b-instant"
            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          />
        </div>

        <div className="space-y-2">
          <label className="text-[11px] uppercase tracking-wider text-neutral-500 font-bold block">Redaction Strategy</label>
          <select
            value={formData.redaction}
            onChange={e => setFormData({ ...formData, redaction: e.target.value })}
            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          >
            <option value="mask">Mask (Replace with Entity)</option>
            <option value="hash">Hash (SHA-256)</option>
            <option value="synthetic">Synthetic (Backend-supported only)</option>
          </select>
        </div>

        <div className="space-y-2">
          <label className="text-[11px] uppercase tracking-wider text-neutral-500 font-bold block">Attached Policy</label>
          <select
            value={formData.policy_id}
            onChange={e => setFormData({ ...formData, policy_id: e.target.value })}
            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          >
            <option value="">Tenant active policies</option>
            {(policies as PolicyLite[] | undefined)?.filter((policy) => policy.is_active ?? policy.policy?.is_active).map((policy) => {
              const policyId = getPolicyId(policy);
              const policyName = policy.name || policy.policy?.name || 'Unnamed policy';
              const priority = policy.priority ?? policy.policy?.priority ?? 0;
              return policyId ? <option key={policyId} value={policyId}>{policyName} (priority {priority})</option> : null;
            })}
          </select>
          <p className="text-[11px] text-neutral-500">Disabled or cross-tenant policies are rejected by the backend.</p>
        </div>

        <div className="flex items-center gap-6 col-span-2 mt-2">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.is_default}
              onChange={e => setFormData({ ...formData, is_default: e.target.checked })}
              className="w-4 h-4 rounded border-white/10 bg-black/40 text-blue-500 focus:ring-blue-500/50"
            />
            <span className="text-sm font-medium text-neutral-200">Default Route</span>
          </label>

          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.is_active}
              onChange={e => setFormData({ ...formData, is_active: e.target.checked })}
              className="w-4 h-4 rounded border-white/10 bg-black/40 text-blue-500 focus:ring-blue-500/50"
            />
            <span className="text-sm font-medium text-neutral-200">Active</span>
          </label>
        </div>
      </div>

      <div className="flex justify-end gap-3 pt-6 border-t border-white/5">
        <Button variant="ghost" onClick={() => { setShowCreate(false); setEditingRoute(null); }} className="text-neutral-400">
          Cancel
        </Button>
        <Button onClick={handleSave} disabled={!formData.name || !formData.provider_id || createMutation.isPending || updateMutation.isPending} className="bg-blue-600 hover:bg-blue-500 text-white">
          {editingRoute ? 'Save Changes' : 'Create Route'}
        </Button>
      </div>
    </div>
  );

  const filteredRoutes = ((routes as GatewayRoute[] | undefined) ?? []).filter((r) => 
    r.name.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans flex items-center gap-2">
            <Network className="w-6 h-6 text-blue-500" />
            Gateway Routes
          </h2>
          <p className="text-sm text-neutral-400 mt-1">Manage traffic routing, target providers, and redaction strategies.</p>
        </div>
      </div>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-96">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
            <input 
              type="text" 
              placeholder="Search routes..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-black/40 border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all"
            />
          </div>
          <Button 
            className="w-full sm:w-auto bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/20"
            onClick={handleOpenCreate}
          >
            <Plus className="w-4 h-4 mr-2" />
            Create Route
          </Button>
        </div>

        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-6 space-y-4">
              <CardSkeleton /><CardSkeleton /><CardSkeleton />
            </div>
          ) : filteredRoutes.length === 0 ? (
            <div className="p-10 flex justify-center">
              <div className="text-center max-w-sm">
                <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto mb-4">
                  <Network className="w-6 h-6 text-neutral-400" />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">No Gateway Routes Found</h3>
                <p className="text-sm text-neutral-400 mb-6">You haven&apos;t defined any routing rules yet. Create a route to direct AI traffic to your providers.</p>
                <Button onClick={handleOpenCreate} variant="outline" className="border-white/10 text-white hover:bg-white/5">Create First Route</Button>
              </div>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {filteredRoutes.map((route) => {
                const isExpanded = expandedId === route.id;
                const provider = (providers as Provider[] | undefined)?.find((p) => p.id === route.provider_id);
                const attachedPolicy = (policies as PolicyLite[] | undefined)?.find((p) => (
                  (p.id || p.policy_id || p.policy?.id) === route.config?.policy_id
                ));
                
                return (
                  <motion.div 
                    key={route.id} 
                    layout="position"
                    className={`transition-colors duration-200 ${isExpanded ? 'bg-white/[0.02]' : 'hover:bg-white/[0.01]'}`}
                  >
                    <div 
                      className="p-5 flex items-center justify-between cursor-pointer"
                      onClick={() => setExpandedId(isExpanded ? null : route.id)}
                    >
                      <div className="flex items-center gap-4 flex-1">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center border shadow-inner ${
                          route.is_active 
                            ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' 
                            : 'bg-neutral-800 border-neutral-700 text-neutral-500'
                        }`}>
                          <Network className="w-5 h-5" />
                        </div>
                        
                        <div className="space-y-1 flex-1">
                          <div className="flex items-center gap-3">
                            <h3 className="font-semibold text-neutral-200 text-base">{route.name}</h3>
                            <div className="flex gap-2">
                              {route.is_default && (
                                <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20 text-[10px] uppercase tracking-wider px-2 py-0">Default</Badge>
                              )}
                              {!route.is_active && (
                                <Badge variant="outline" className="bg-neutral-800 text-neutral-400 border-neutral-700 text-[10px] uppercase tracking-wider px-2 py-0">Inactive</Badge>
                              )}
                            </div>
                          </div>
                          
                          <div className="flex items-center gap-4 text-xs text-neutral-500">
                            {route.description && <span className="truncate max-w-md">{route.description}</span>}
                            {provider ? (
                              <span className="flex items-center gap-1.5 bg-black/30 px-2 py-0.5 rounded border border-white/5">
                                <Server className="w-3 h-3 text-neutral-400" />
                                <span className="font-medium text-neutral-300">{provider.name}</span>
                              </span>
                            ) : (
                              <span className="flex items-center gap-1.5 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 text-red-400">
                                <Server className="w-3 h-3" />
                                <span className="font-medium">No Provider</span>
                              </span>
                            )}
                            <span className="flex items-center gap-1.5 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20 text-purple-400">
                               <Shield className="w-3 h-3" />
                               <span className="font-medium capitalize text-[10px]">Redaction: {route.redaction}</span>
                            </span>
                            {Boolean(route.config?.model) && (
                              <span className="font-mono text-[10px] text-neutral-400">
                                Model: {String(route.config?.model)}
                              </span>
                            )}
                            {attachedPolicy && (
                              <span className="flex items-center gap-1.5 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 text-emerald-400">
                                <Shield className="w-3 h-3" />
                                <span className="font-medium text-[10px]">Policy: {attachedPolicy.name || attachedPolicy.policy?.name}</span>
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 ml-4">
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="h-8 w-8 text-neutral-400 hover:text-white hover:bg-white/10 z-10"
                          onClick={(e) => { e.stopPropagation(); handleOpenEdit(route); }}
                        >
                          <Edit className="w-4 h-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="h-8 w-8 text-red-400 hover:text-red-300 hover:bg-red-500/10 z-10"
                          onClick={(e) => { e.stopPropagation(); handleDelete(route.id, route.name); }}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                        <ChevronRight className={`w-5 h-5 text-neutral-600 transition-transform duration-300 ${isExpanded ? 'rotate-90' : ''}`} />
                      </div>
                    </div>

                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden border-t border-white/5"
                        >
                          <div className="p-6 bg-black/20 text-sm space-y-4">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                              <div>
                                <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-bold mb-1">Route ID</p>
                                <p className="font-mono text-xs text-neutral-400">{route.id}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-bold mb-1">Created At</p>
                                <p className="text-neutral-300">{new Date(route.created_at).toLocaleString()}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-bold mb-1">Redaction Strategy</p>
                                <p className="text-neutral-300 capitalize">{route.redaction}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-bold mb-1">Model Override</p>
                                <p className="text-neutral-300 font-mono text-xs">{String(route.config?.model || route.config?.default_model || 'Route request model')}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-bold mb-1">Status</p>
                                <p className={route.is_active ? 'text-emerald-400' : 'text-neutral-500'}>
                                  {route.is_active ? 'Active' : 'Inactive'}
                                </p>
                              </div>
                              <div>
                                <p className="text-[10px] text-neutral-500 uppercase tracking-wider font-bold mb-1">Attached Policy</p>
                                <p className="text-neutral-300">{attachedPolicy ? `${attachedPolicy.name || attachedPolicy.policy?.name} (${(attachedPolicy.is_active ?? attachedPolicy.policy?.is_active) ? 'active' : 'disabled'})` : 'Tenant active policies'}</p>
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / Edit Modal */}
      <AnimatePresence>
        {(showCreate || editingRoute) && (
          <Modal
            title={editingRoute ? `Edit Route: ${editingRoute.name}` : 'Create Gateway Route'}
            onClose={() => { setShowCreate(false); setEditingRoute(null); }}
          >
            {renderForm()}
          </Modal>
        )}
      </AnimatePresence>
    </div>
  );
}
