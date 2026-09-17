"use client";

import Image from "next/image";
import React, { useCallback, useEffect, useState } from "react";
import {
  Users,
  KeyRound,
  Building,
  Plus,
  Trash2,
  Lock,
  Unlock,
  CheckCircle,
  Copy,
  Check,
  AlertTriangle,
  Mail,
  ShieldAlert,
  Cloud,
  RotateCw
} from "lucide-react";
import ModalShell from "@/components/modal-shell";
import { flashCopy } from "@/lib/clipboard";
import { getErrorMessage } from "@/lib/errors";
import { jsonRequest, responseJson, responseJsonOr, toggleValue } from "@/lib/client-fetch";
import { useRuntimeConfig } from "@/lib/runtime-config";

interface UserItem {
  id: string;
  email: string;
  role: string;
  mfa_enabled: boolean;
  is_active: boolean;
  created_at: string;
}

interface APIKeyItem {
  id: string;
  name: string;
  scopes: string[];
  is_active: boolean;
  created_at: string;
  last_used?: string | null;
  last_used_ip?: string | null;
  last_used_request_id?: string | null;
  expires_at: string;
  revoked_at?: string | null;
  rotated_at?: string | null;
  rotated_from_id?: string | null;
}

interface InviteResult {
  signup_id: string;
  email: string;
  tenant_name: string;
  invited_role: string;
  expires_at: string;
  delivery: string;
  next_resend_at: string;
  dev_otp?: string;
}

interface PendingInvite {
  signup_id: string;
  email: string;
  tenant_name: string;
  invited_role?: string | null;
  expires_at: string;
  sent_at?: string | null;
  resend_count: number;
  delivery?: string | null;
  delivery_error?: string | null;
}

interface SecurityState {
  user_id: string;
  email: string;
  role: string;
  mfa_enabled: boolean;
  enrollment_pending?: boolean;
}

interface MFASetupState extends SecurityState {
  mfa_secret: string;
  provisioning_uri: string;
  backup_codes: string[];
  qr_code_base64: string;
}

interface UsageLimitState {
  limits_enabled: boolean;
  requests_per_minute: number;
  burst_10_seconds: number;
  daily_requests_limit: number;
  max_body_bytes: number;
  max_daily_spend_usd: number;
  estimated_cost_per_1k_requests_usd: number;
  requests_today: number;
  blocked_today: number;
  allowed_today: number;
  bytes_today: number;
  estimated_spend_today_usd: number;
  requests_remaining_today: number;
  spend_remaining_today_usd: number;
}

interface WorkerConnectorAction {
  name: string;
  scope: string;
  destructive: boolean;
}

interface WorkerConnector {
  connector: string;
  display_name: string;
  status: string;
  credential_source: string;
  scopes: string[];
  actions: WorkerConnectorAction[];
}

interface WorkerTokenItem {
  id: string;
  connector: string;
  purpose: string;
  action_id: string;
  workflow_id?: string | null;
  scopes: string[];
  permission_boundary: {
    allowed_actions?: string[];
    allow_destructive?: boolean;
    destructive_actions?: string[];
  };
  token_prefix: string;
  status: string;
  issued_at: string;
  expires_at: string;
  revoked_at?: string | null;
  last_used_at?: string | null;
  last_used_action?: string | null;
  use_count: number;
  metadata?: Record<string, unknown>;
}

type CloudProvider = "aws" | "github" | "gcp";

interface CloudCatalogItem {
  provider: CloudProvider;
  display_name: string;
  fields: string[];
  optional_fields: string[];
}

interface CloudConnectorItem {
  id: string;
  provider: CloudProvider;
  display_name: string;
  status: string;
  last_error?: string | null;
  created_at?: string | null;
  metadata: Record<string, string | number | boolean | null | undefined>;
}

interface SsoConfig {
  enabled: boolean;
  status: string;
  issuer: string;
  client_id: string;
  redirect_uri: string;
  scopes: string[];
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  email_claim: string;
  groups_claim: string;
  tenant_claim: string;
  tenant_claim_value: string;
  role_mapping: Record<string, string>;
  default_role: string;
  auto_provision: boolean;
  require_mfa: boolean;
  accepted_amr: string[];
  accepted_acr: string[];
  max_auth_age_seconds: number;
  has_client_secret: boolean;
  last_tested_at?: string | null;
  last_error?: string | null;
}

const defaultSsoConfig: SsoConfig = {
  enabled: false,
  status: "disabled",
  issuer: "",
  client_id: "",
  redirect_uri: "",
  scopes: ["openid", "email", "profile"],
  authorization_endpoint: "",
  token_endpoint: "",
  jwks_uri: "",
  email_claim: "email",
  groups_claim: "groups",
  tenant_claim: "tenant_id",
  tenant_claim_value: "",
  role_mapping: {},
  default_role: "viewer",
  auto_provision: false,
  require_mfa: true,
  accepted_amr: ["mfa"],
  accepted_acr: [],
  max_auth_age_seconds: 43200,
  has_client_secret: false,
};

const cloudDefaults: Record<CloudProvider, Record<string, string>> = {
  aws: { access_key_id: "", secret_access_key: "", region: "us-east-1", bucket: "" },
  github: { token: "", owner: "", repo: "" },
  gcp: { service_account_json: "", project_id: "" },
};

const flashBooleanCopy = async (text: string, setCopied: (copied: boolean) => void) => {
  await flashCopy(text, setCopied, true, false, 2000);
};

type SettingsModalProps = {
  title: string;
  onClose: () => void;
  onBackdropClose?: () => void;
  error?: string | null;
  children: React.ReactNode;
  maxWidthClass?: string;
};

function SettingsModal({
  title,
  onClose,
  onBackdropClose = onClose,
  error,
  children,
  maxWidthClass = "max-w-[400px]",
}: SettingsModalProps) {
  return (
    <ModalShell
      title={title}
      onClose={onClose}
      onBackdropClose={onBackdropClose}
      error={error}
      maxWidthClass={maxWidthClass}
    >
      {children}
    </ModalShell>
  );
}

export default function SettingsPage() {
  const runtimeConfig = useRuntimeConfig();
  const [activeTab, setActiveTab] = useState<"users" | "security" | "keys" | "cloud" | "workers" | "limits" | "tenant">("users");
  const controlPlaneHost = runtimeConfig?.api_url || "";

  // List States
  const [users, setUsers] = useState<UserItem[]>([]);
  const [pendingInvites, setPendingInvites] = useState<PendingInvite[]>([]);
  const [apiKeys, setApiKeys] = useState<APIKeyItem[]>([]);
  const [securityState, setSecurityState] = useState<SecurityState | null>(null);
  const [mfaSetup, setMfaSetup] = useState<MFASetupState | null>(null);
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState<string[]>([]);
  const [mfaBusy, setMfaBusy] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [usageLimits, setUsageLimits] = useState<UsageLimitState | null>(null);
  const [usageError, setUsageError] = useState<string | null>(null);
  const [workerConnectors, setWorkerConnectors] = useState<WorkerConnector[]>([]);
  const [workerTokens, setWorkerTokens] = useState<WorkerTokenItem[]>([]);
  const [workerError, setWorkerError] = useState<string | null>(null);
  const [workerSubmitting, setWorkerSubmitting] = useState(false);
  const [workerCopied, setWorkerCopied] = useState(false);
  const [generatedWorkerToken, setGeneratedWorkerToken] = useState<string | null>(null);
  const [cloudCatalog, setCloudCatalog] = useState<CloudCatalogItem[]>([]);
  const [cloudConnectors, setCloudConnectors] = useState<CloudConnectorItem[]>([]);
  const [cloudProvider, setCloudProvider] = useState<CloudProvider>("aws");
  const [cloudDisplayName, setCloudDisplayName] = useState("Production cloud");
  const [cloudForm, setCloudForm] = useState<Record<string, string>>(cloudDefaults.aws);
  const [cloudError, setCloudError] = useState<string | null>(null);
  const [cloudMessage, setCloudMessage] = useState<string | null>(null);
  const [cloudSubmitting, setCloudSubmitting] = useState(false);
  const [ssoConfig, setSsoConfig] = useState<SsoConfig>(defaultSsoConfig);
  const [ssoClientSecret, setSsoClientSecret] = useState("");
  const [ssoRoleMappingText, setSsoRoleMappingText] = useState("{}");
  const [ssoError, setSsoError] = useState<string | null>(null);
  const [ssoMessage, setSsoMessage] = useState<string | null>(null);
  const [ssoBusy, setSsoBusy] = useState(false);
  const [workerForm, setWorkerForm] = useState({
    connector: "aws",
    purpose: "scan",
    action_id: "s3.sync",
    ttl_seconds: 900,
    scopes: ["aws:s3:read"],
  });
  const [tenantId, setTenantId] = useState("Unknown");
  const [tenantStatus, setTenantStatus] = useState("active");
  const [sessionRole, setSessionRole] = useState("viewer");
  const [loading, setLoading] = useState(true);

  // User Form Modal States
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [userEmail, setUserEmail] = useState("");
  const [userRole, setUserRole] = useState("viewer");
  const [userError, setUserError] = useState<string | null>(null);
  const [userSubmitting, setUserSubmitting] = useState(false);
  const [inviteResult, setInviteResult] = useState<InviteResult | null>(null);

  // Key Form Modal States
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [keyScopes, setKeyScopes] = useState<string[]>(["read"]);
  const [keyExpiresInDays, setKeyExpiresInDays] = useState(90);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [keySubmitting, setKeySubmitting] = useState(false);
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [inviteCopied, setInviteCopied] = useState(false);
  const [tenantActionError, setTenantActionError] = useState<string | null>(null);
  const [tenantActionBusy, setTenantActionBusy] = useState(false);
  const isOwner = sessionRole === "owner";

  const fetchUsersAndKeys = useCallback(async () => {
    try {
      // Fetch users
      const uRes = await fetch("/api/users");
      if (uRes.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (uRes.ok) {
        const uData = await uRes.json();
        setUsers(uData || []);
      }

      const invitesRes = await fetch("/api/users/invites");
      if (invitesRes.ok) {
        const invitesData = await invitesRes.json();
        setPendingInvites(invitesData || []);
      } else if (invitesRes.status === 403) {
        setPendingInvites([]);
      }

      // Fetch keys
      const kRes = await fetch("/api/api-keys");
      if (kRes.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (kRes.ok) {
        const kData = await kRes.json();
        setApiKeys(kData || []);
      }

      // Fetch tenant context from cookie endpoint or simple session endpoin
      const dashboardRes = await fetch("/api/dashboard");
      if (dashboardRes.status === 401) {
        window.location.href = "/login";
        return;
      }

      const tenantRes = await fetch("/api/tenants/current");
      if (tenantRes.ok) {
        const tenantData = await tenantRes.json();
        setTenantStatus(tenantData.status || "active");
      }

      const securityRes = await fetch("/api/users/me/security");
      if (securityRes.ok) {
        setSecurityState(await securityRes.json());
      }

      const ssoRes = await fetch("/api/auth/oidc/admin-config");
      if (ssoRes.ok) {
        const ssoData = await ssoRes.json();
        setSsoConfig({ ...defaultSsoConfig, ...ssoData });
        setSsoRoleMappingText(JSON.stringify(ssoData.role_mapping || {}, null, 2));
        setSsoError(null);
      } else if (ssoRes.status !== 403) {
        const ssoData = await ssoRes.json().catch(() => ({}));
        setSsoError(ssoData.error || "Could not load SSO configuration");
      }

      const usageRes = await fetch("/api/usage-limits");
      if (usageRes.ok) {
        setUsageLimits(await usageRes.json());
        setUsageError(null);
      } else if (usageRes.status !== 403) {
        const usageData = await usageRes.json().catch(() => ({}));
        setUsageError(usageData.error || "Could not load usage limits");
      }

      const connectorsRes = await fetch("/api/ephemeral-workers/connectors");
      if (connectorsRes.ok) {
        const connectorsData = await connectorsRes.json();
        setWorkerConnectors(connectorsData.connectors || []);
      }

      const workerTokensRes = await fetch("/api/ephemeral-workers/tokens");
      if (workerTokensRes.ok) {
        setWorkerTokens(await workerTokensRes.json());
        setWorkerError(null);
      } else if (workerTokensRes.status !== 403) {
        const workerData = await workerTokensRes.json().catch(() => ({}));
        setWorkerError(workerData.error || "Could not load worker tokens");
      }

      const cloudRes = await fetch("/api/cloud");
      if (cloudRes.ok) {
        const cloudData = await cloudRes.json();
        setCloudCatalog(cloudData.catalog || []);
        setCloudConnectors(cloudData.connectors || []);
        setCloudError(null);
      } else if (cloudRes.status !== 403) {
        const cloudData = await cloudRes.json().catch(() => ({}));
        setCloudError(cloudData.error || "Could not load cloud connectors");
      }
    } catch (err: unknown) {
      console.warn("Settings fetchUsersAndKeys failed:", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchSession = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/session");
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (res.ok) {
        const data = await res.json();
        setTenantId(data.tenantId || "Unknown");
        setSessionRole((data.role || "viewer").toLowerCase());
      }
    } catch (err: unknown) {
      console.warn("Settings fetchSession failed:", err instanceof Error ? err.message : "Unknown error");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchUsersAndKeys();
      void fetchSession();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [fetchUsersAndKeys, fetchSession]);

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userEmail) return;
    setUserSubmitting(true);
    setUserError(null);

    try {
      const res = await fetch("/api/users/invite", jsonRequest("POST", {
        email: userEmail,
        role: userRole
      }));
      const data = await responseJson<{ error?: string } & InviteResult>(res);

      if (!res.ok) {
        throw new Error(data.error || "Failed to send invite");
      }

      setUserEmail("");
      setUserRole("viewer");
      setInviteResult(data);
      await fetchUsersAndKeys();
    } catch (err: unknown) {
      setUserError(getErrorMessage(err, "An unexpected error occurred"));
    } finally {
      setUserSubmitting(false);
    }
  };

  const handleCancelInvite = async (id: string) => {
    if (!isOwner) return;
    if (!confirm("Cancel this pending invite? The existing link and OTP will stop working.")) return;
    try {
      const res = await fetch(`/api/users/invites/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to cancel invite");
      setPendingInvites(pendingInvites.filter((invite) => invite.signup_id !== id));
    } catch (err: unknown) {
      setUserError(getErrorMessage(err, "Could not cancel invite"));
    }
  };

  const handleSetupMfa = async () => {
    setMfaBusy(true);
    setMfaError(null);
    try {
      const res = await fetch("/api/users/me/mfa/setup", { method: "POST" });
      const data = await responseJson<{ error?: string } & MFASetupState>(res);
      if (!res.ok) throw new Error(data.error || "Failed to enable MFA");
      setMfaSetup(data);
      setSecurityState(data);
    } catch (err: unknown) {
      setMfaError(getErrorMessage(err, "Could not enable MFA"));
    } finally {
      setMfaBusy(false);
    }
  };

  const handleConfirmMfa = async () => {
    const code = prompt("Enter the 6-digit code from your authenticator to finish enrollment:")?.trim();
    if (!code) return;
    setMfaBusy(true);
    setMfaError(null);
    try {
      const res = await fetch("/api/users/me/mfa/confirm", jsonRequest("POST", { code }));
      const data = await responseJson<{ error?: string } & SecurityState>(res);
      if (!res.ok) throw new Error(data.error || "Failed to confirm MFA");
      setSecurityState(data);
      setMfaSetup(null);
      await fetchUsersAndKeys();
    } catch (err: unknown) {
      setMfaError(getErrorMessage(err, "Could not confirm MFA"));
    } finally {
      setMfaBusy(false);
    }
  };

  const handleDisableMfa = async () => {
    if (!confirm("Disable MFA for your console user? Approval-sensitive actions will no longer ask for your TOTP code.")) return;
    const code = prompt("Enter your current TOTP or backup code to disable MFA:")?.trim();
    if (!code) return;
    setMfaBusy(true);
    setMfaError(null);
    try {
      const res = await fetch("/api/users/me/mfa/disable", jsonRequest("POST", { code }));
      const data = await responseJson<{ error?: string } & SecurityState>(res);
      if (!res.ok) throw new Error(data.error || "Failed to disable MFA");
      setMfaSetup(null);
      setSecurityState(data);
      await fetchUsersAndKeys();
    } catch (err: unknown) {
      setMfaError(getErrorMessage(err, "Could not disable MFA"));
    } finally {
      setMfaBusy(false);
    }
  };

  const handleRegenerateMfaRecoveryCodes = async () => {
    const code = prompt("Enter your current TOTP or backup code to replace all recovery codes:")?.trim();
    if (!code) return;
    setMfaBusy(true);
    setMfaError(null);
    try {
      const res = await fetch("/api/users/me/mfa/recovery-codes", jsonRequest("POST", { code }));
      const data = await responseJson<{ error?: string; backup_codes?: string[] }>(res);
      if (!res.ok || !data.backup_codes) throw new Error(data.error || "Failed to regenerate recovery codes");
      setMfaRecoveryCodes(data.backup_codes);
    } catch (err: unknown) {
      setMfaError(getErrorMessage(err, "Could not regenerate recovery codes"));
    } finally {
      setMfaBusy(false);
    }
  };

  const handleSaveSsoConfig = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isOwner && sessionRole !== "admin") return;
    setSsoBusy(true);
    setSsoError(null);
    setSsoMessage(null);
    try {
      let roleMapping: Record<string, string>;
      try {
        roleMapping = JSON.parse(ssoRoleMappingText || "{}");
      } catch {
        throw new Error("Group role mapping must be valid JSON");
      }
      const res = await fetch("/api/auth/oidc/admin-config", jsonRequest("PUT", {
        enabled: ssoConfig.enabled,
        issuer: ssoConfig.issuer,
        client_id: ssoConfig.client_id,
        client_secret: ssoClientSecret || undefined,
        redirect_uri: ssoConfig.redirect_uri,
        scopes: ssoConfig.scopes,
        authorization_endpoint: ssoConfig.authorization_endpoint || undefined,
        token_endpoint: ssoConfig.token_endpoint || undefined,
        jwks_uri: ssoConfig.jwks_uri || undefined,
        email_claim: ssoConfig.email_claim,
        groups_claim: ssoConfig.groups_claim,
        tenant_claim: ssoConfig.tenant_claim,
        tenant_claim_value: ssoConfig.tenant_claim_value,
        role_mapping: roleMapping,
        default_role: ssoConfig.default_role,
        auto_provision: ssoConfig.auto_provision,
        require_mfa: ssoConfig.require_mfa,
        accepted_amr: ssoConfig.accepted_amr,
        accepted_acr: ssoConfig.accepted_acr,
        max_auth_age_seconds: ssoConfig.max_auth_age_seconds,
      }));
      const data = await responseJson<{ error?: string } & SsoConfig>(res);
      if (!res.ok) throw new Error(data.error || "Could not save SSO configuration");
      setSsoConfig({ ...defaultSsoConfig, ...data });
      setSsoRoleMappingText(JSON.stringify(data.role_mapping || {}, null, 2));
      setSsoClientSecret("");
      setSsoMessage("Enterprise SSO configuration saved.");
    } catch (err: unknown) {
      setSsoError(getErrorMessage(err, "Could not save SSO configuration"));
    } finally {
      setSsoBusy(false);
    }
  };

  const handleTestSsoConfig = async () => {
    setSsoBusy(true);
    setSsoError(null);
    setSsoMessage(null);
    try {
      const res = await fetch("/api/auth/oidc/admin-config/test", { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) throw new Error(data.error || data.detail || "SSO test failed");
      setSsoMessage(`SSO metadata verified. JWKS keys: ${data.jwks_keys}.`);
      await fetchUsersAndKeys();
    } catch (err: unknown) {
      setSsoError(getErrorMessage(err, "SSO test failed"));
    } finally {
      setSsoBusy(false);
    }
  };

  const handleDeleteUser = async (id: string) => {
    if (!isOwner) return;
    if (!confirm("Are you sure you want to remove this user from the tenant?")) return;
    try {
      const res = await fetch(`/api/users/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete user");
      setUsers(users.map((u) => u.id === id ? { ...u, is_active: false } : u));
    } catch (err: unknown) {
      alert(getErrorMessage(err, "Could not delete user"));
    }
  };

  const handleGenerateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isOwner) return;
    if (!keyName) return;
    setKeySubmitting(true);
    setKeyError(null);
    setGeneratedKey(null);

    try {
      const res = await fetch("/api/api-keys", jsonRequest("POST", {
        name: keyName,
        scopes: keyScopes,
        expires_in_days: keyExpiresInDays
      }));
      const data = await responseJson<{ error?: string; api_key: string }>(res);
      if (!res.ok) {
        throw new Error(data.error || "Failed to generate key");
      }

      setGeneratedKey(data.api_key);
      setKeyName("");
      setKeyScopes(["read"]);
      setKeyExpiresInDays(90);
      await fetchUsersAndKeys();
    } catch (err: unknown) {
      setKeyError(getErrorMessage(err, "An unexpected error occurred"));
    } finally {
      setKeySubmitting(false);
    }
  };

  const handleRevokeKey = async (id: string) => {
    if (!isOwner) return;
    if (!confirm("Are you sure you want to revoke this API key? Systems utilizing this key will be rejected immediately.")) return;
    try {
      const res = await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to revoke key");
      setApiKeys(apiKeys.filter((k) => k.id !== id));
    } catch (err: unknown) {
      alert(getErrorMessage(err, "Could not revoke key"));
    }
  };

  const handleRotateKey = async (key: APIKeyItem) => {
    if (!isOwner) return;
    if (!confirm("Rotate this API key? The old secret will stop working immediately.")) return;
    try {
      const res = await fetch(`/api/api-keys/${key.id}/rotate`, jsonRequest("POST", {
        name: key.name,
        scopes: key.scopes,
        expires_in_days: 90
      }));
      const data = await responseJson<{ error?: string; api_key: string }>(res);
      if (!res.ok) throw new Error(data.error || "Failed to rotate key");
      setGeneratedKey(data.api_key);
      await fetchUsersAndKeys();
    } catch (err: unknown) {
      alert(getErrorMessage(err, "Could not rotate key"));
    }
  };

  const toggleScope = (scope: string) => {
    setKeyScopes(toggleValue(keyScopes, scope));
  };

  const copyToClipboard = async () => {
    if (generatedKey) await flashBooleanCopy(generatedKey, setCopied);
  };

  const selectedCloudCatalog = cloudCatalog.find((item) => item.provider === cloudProvider);

  const updateCloudProvider = (provider: CloudProvider) => {
    setCloudProvider(provider);
    setCloudForm(cloudDefaults[provider]);
    setCloudDisplayName(`${provider.toUpperCase()} connector`);
    setCloudError(null);
    setCloudMessage(null);
  };

  const refreshCloudConnectors = async () => {
    const res = await fetch("/api/cloud");
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setCloudError(data.error || "Could not load cloud connectors");
      return;
    }
    setCloudCatalog(data.catalog || []);
    setCloudConnectors(data.connectors || []);
    setCloudError(null);
  };

  const handleSaveCloudConnector = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isOwner && sessionRole !== "admin") return;
    setCloudSubmitting(true);
    setCloudError(null);
    setCloudMessage(null);
    try {
      const metadata: Record<string, string> = {};
      for (const field of selectedCloudCatalog?.optional_fields || []) {
        if (cloudForm[field]) metadata[field] = cloudForm[field];
      }
      const res = await fetch("/api/cloud", jsonRequest("POST", {
        provider: cloudProvider,
        display_name: cloudDisplayName,
        credentials: cloudForm,
        metadata,
      }));
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not connect cloud provider");
      setCloudMessage(`${data.display_name || "Connector"} saved. Secrets are encrypted and hidden from this point on.`);
      setCloudForm(cloudDefaults[cloudProvider]);
      await refreshCloudConnectors();
    } catch (err: unknown) {
      setCloudError(getErrorMessage(err, "Could not connect cloud provider"));
    } finally {
      setCloudSubmitting(false);
    }
  };

  const handleVerifyCloudConnector = async (id: string) => {
    setCloudError(null);
    setCloudMessage(null);
    try {
      const res = await fetch(`/api/cloud/${id}/verify`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Verification failed");
      setCloudMessage(data.result?.ok ? "Connector verified." : data.result?.error || "Verification failed");
      await refreshCloudConnectors();
    } catch (err: unknown) {
      setCloudError(getErrorMessage(err, "Verification failed"));
    }
  };

  const handleRevokeCloudConnector = async (id: string) => {
    if (!isOwner && sessionRole !== "admin") return;
    if (!confirm("Revoke this cloud login? Stored credentials stop being usable immediately.")) return;
    setCloudError(null);
    try {
      const res = await fetch(`/api/cloud/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Could not revoke cloud connector");
      await refreshCloudConnectors();
    } catch (err: unknown) {
      setCloudError(getErrorMessage(err, "Could not revoke cloud connector"));
    }
  };

  const refreshWorkers = async () => {
    const [connectorsRes, tokensRes] = await Promise.all([
      fetch("/api/ephemeral-workers/connectors"),
      fetch("/api/ephemeral-workers/tokens"),
    ]);
    if (connectorsRes.ok) {
      const connectorsData = await connectorsRes.json();
      setWorkerConnectors(connectorsData.connectors || []);
    }
    if (tokensRes.ok) {
      setWorkerTokens(await tokensRes.json());
      setWorkerError(null);
    }
  };

  const selectedWorkerConnector = workerConnectors.find((item) => item.connector === workerForm.connector);
  const selectedWorkerAction = selectedWorkerConnector?.actions.find((item) => item.name === workerForm.action_id);

  const updateWorkerConnector = (connector: string) => {
    const nextConnector = workerConnectors.find((item) => item.connector === connector);
    const firstAction = nextConnector?.actions[0];
    setWorkerForm({
      connector,
      purpose: "scan",
      action_id: firstAction?.name || "",
      ttl_seconds: 900,
      scopes: firstAction?.scope ? [firstAction.scope] : [],
    });
    setGeneratedWorkerToken(null);
    setWorkerError(null);
  };

  const updateWorkerAction = (actionName: string) => {
    const action = selectedWorkerConnector?.actions.find((item) => item.name === actionName);
    setWorkerForm((current) => ({
      ...current,
      action_id: actionName,
      scopes: action?.scope ? Array.from(new Set([...current.scopes, action.scope])) : current.scopes,
    }));
  };

  const toggleWorkerScope = (scope: string) => {
    setWorkerForm((current) => ({
      ...current,
      scopes: current.scopes.includes(scope)
        ? current.scopes.filter((item) => item !== scope)
        : [...current.scopes, scope],
    }));
  };

  const handleIssueWorkerToken = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!isOwner && sessionRole !== "admin") return;
    setWorkerSubmitting(true);
    setWorkerError(null);
    setGeneratedWorkerToken(null);

    try {
      const destructiveAction = selectedWorkerAction?.destructive ? [workerForm.action_id] : [];
      const res = await fetch("/api/ephemeral-workers/tokens", jsonRequest("POST", {
        connector: workerForm.connector,
        purpose: workerForm.purpose,
        action_id: workerForm.action_id,
        ttl_seconds: workerForm.ttl_seconds,
        scopes: workerForm.scopes,
        allow_destructive: destructiveAction.length > 0,
        destructive_actions: destructiveAction,
        metadata: { source: "console.settings" },
      }));
      const data = await responseJson<{ error?: string; token: string }>(res);
      if (!res.ok) throw new Error(data.error || "Failed to issue worker token");
      setGeneratedWorkerToken(data.token);
      await refreshWorkers();
    } catch (err: unknown) {
      setWorkerError(getErrorMessage(err, "Could not issue worker token"));
    } finally {
      setWorkerSubmitting(false);
    }
  };

  const handleRevokeWorkerToken = async (id: string) => {
    if (!isOwner && sessionRole !== "admin") return;
    if (!confirm("Revoke this worker token? Running workers using it will be denied on their next action.")) return;
    try {
      const res = await fetch(`/api/ephemeral-workers/tokens/${id}/revoke`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to revoke worker token");
      await refreshWorkers();
    } catch (err: unknown) {
      setWorkerError(getErrorMessage(err, "Could not revoke worker token"));
    }
  };

  const copyWorkerToken = async () => {
    if (generatedWorkerToken) await flashBooleanCopy(generatedWorkerToken, setWorkerCopied);
  };

  const inviteLink = inviteResult
    ? `${typeof window !== "undefined" ? window.location.origin : ""}/signup?invite=${inviteResult.signup_id}`
    : "";

  const copyInviteLink = async () => {
    if (inviteLink) await flashBooleanCopy(inviteLink, setInviteCopied);
  };

  const handleTenantStatusChange = async (nextStatus: "active" | "disabled") => {
    if (!isOwner) return;
    const confirmed = confirm(
      nextStatus === "disabled"
        ? "Disable this tenant? Gateway requests and most console actions will be rejected until reactivated."
        : "Reactivate this tenant?"
    );
    if (!confirmed) return;
    setTenantActionBusy(true);
    setTenantActionError(null);
    try {
      const res = await fetch("/api/tenants/current/status", jsonRequest("PATCH", { status: nextStatus }));
      const data = await responseJsonOr<{ error?: string; status?: string }>(res, {});
      if (!res.ok) {
        throw new Error(data.error || "Failed to disable tenant");
      }
      setTenantStatus(data.status || nextStatus);
    } catch (err: unknown) {
      setTenantActionError(getErrorMessage(err, "Could not update tenant status"));
    } finally {
      setTenantActionBusy(false);
    }
  };

  return (
    <div className="ac-page ac-page-settings space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">
          Tenant Settings
        </h1>
        <p className="text-[#6B7488] text-sm mt-1">
          Manage access, API keys, cloud credentials, worker tokens, and tenant safety controls.
        </p>
      </div>

      <div className="ac-settings-workspace">
      {/* Tabs Selector */}
      <div className="ac-settings-nav flex gap-6 overflow-x-auto border-b border-[#E6E9F0]" aria-label="Settings sections">
        <button
          onClick={() => setActiveTab("users")}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            activeTab === "users" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "users" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <Users className="h-4 w-4" />
          User Management
        </button>
        <button
          onClick={() => setActiveTab("security")}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            activeTab === "security" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "security" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <Lock className="h-4 w-4" />
          Security / MFA
        </button>
        <button
          onClick={() => setActiveTab("keys")}
          disabled={!isOwner}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            !isOwner ? "text-[#6B7488] cursor-not-allowed" : activeTab === "keys" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "keys" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <KeyRound className="h-4 w-4" />
          API Keys Lifecycle
        </button>
        <button
          onClick={() => setActiveTab("cloud")}
          disabled={!isOwner && sessionRole !== "admin"}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            !isOwner && sessionRole !== "admin" ? "text-[#6B7488] cursor-not-allowed" : activeTab === "cloud" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "cloud" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <Cloud className="h-4 w-4" />
          Cloud Logins
        </button>
        <button
          onClick={() => setActiveTab("workers")}
          disabled={!isOwner && sessionRole !== "admin"}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            !isOwner && sessionRole !== "admin" ? "text-[#6B7488] cursor-not-allowed" : activeTab === "workers" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "workers" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <RotateCw className="h-4 w-4" />
          Worker Tokens
        </button>
        <button
          onClick={() => setActiveTab("limits")}
          disabled={!isOwner && sessionRole !== "admin"}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            !isOwner && sessionRole !== "admin" ? "text-[#6B7488] cursor-not-allowed" : activeTab === "limits" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "limits" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <ShieldAlert className="h-4 w-4" />
          Usage Limits
        </button>
        <button
          onClick={() => setActiveTab("tenant")}
          className={`pb-3.5 text-sm font-semibold transition relative ${
            activeTab === "tenant" ? "text-indigo-400" : "text-[#6B7488] hover:text-[#0E1726]"
          }`}
        >
          {activeTab === "tenant" && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />}
          <Building className="h-4 w-4" />
          Tenant Status
        </button>
      </div>

      {/* Tab: Users Management */}
      {activeTab === "users" && (
        <div className="space-y-6">
          <div className="flex justify-between items-center bg-white border border-[#E6E9F0] p-4 rounded-xl">
            <div className="text-xs">
              <h3 className="font-bold text-[#0E1726] flex items-center gap-1.5">
                <Users className="w-4 h-4 text-indigo-400" />
                Active Members
              </h3>
              <p className="text-[#6B7488] mt-0.5">Manage permissions and view 2FA setup status.</p>
            </div>
            <button
              onClick={() => { setUserEmail(""); setUserRole("viewer"); setUserError(null); setInviteResult(null); setIsUserModalOpen(true); }}
              disabled={!isOwner}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Plus className="w-4 h-4" />
              {isOwner ? "Add Member" : "Owner Only"}
            </button>
          </div>

          <div className="rounded-[20px] bg-white border border-[#E6E9F0] shadow-xl overflow-hidden">
            {loading ? (
              <div className="p-8 text-center flex justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-500" />
              </div>
            ) : users.length === 0 ? (
              <div className="p-12 text-center text-[#6B7488] text-xs">No users associated with this tenant.</div>
            ) : (
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#E6E9F0] bg-[#F5F7FA]/40 text-[#6B7488] font-bold uppercase tracking-wider text-[10px]">
                    <th className="px-6 py-4">Email</th>
                    <th className="px-6 py-4">Role</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4">Joined At</th>
                    <th className="px-6 py-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6E9F0]/50">
                  {users.map((u) => (
                    <tr key={u.id} className={`hover:bg-[#F5F7FA]/10 transition-colors ${!u.is_active ? "opacity-55" : ""}`}>
                      <td className="px-6 py-4">
                        <div className="font-semibold text-[#0E1726]">{u.email}</div>
                        <div className="mt-1 text-[10px] text-[#6B7488]">
                          MFA {u.mfa_enabled ? "enabled" : "disabled"}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-0.5 rounded bg-[#F5F7FA] text-[#475069] capitalize border border-[#E6E9F0] font-semibold text-[10px]">
                          {u.role}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {u.is_active ? (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-450">
                            <Lock className="w-3.5 h-3.5 text-emerald-500" />
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-red-300">
                            <Unlock className="w-3.5 h-3.5 text-[#6B7488]" />
                            Inactive
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-[#6B7488] font-mono">
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        {isOwner && u.is_active ? (
                          <button
                            onClick={() => handleDeleteUser(u.id)}
                            className="p-1.5 rounded bg-red-950/20 hover:bg-red-950/80 text-red-400 border border-red-900/30 hover:border-red-800 transition"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        ) : (
                          <span className="text-[10px] text-[#6B7488]">Owner only</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {isOwner && (
            <div className="rounded-[20px] bg-white border border-[#E6E9F0] shadow-xl overflow-hidden">
              <div className="flex items-center justify-between border-b border-[#E6E9F0] px-5 py-4">
                <div>
                  <h3 className="text-sm font-bold text-[#0E1726]">Pending Invites</h3>
                  <p className="mt-1 text-xs text-[#6B7488]">Track tenant invitations that have not been verified yet.</p>
                </div>
                <span className="rounded-full border border-[#E6E9F0] px-2 py-0.5 text-[10px] font-semibold text-[#6B7488]">
                  {pendingInvites.length} pending
                </span>
              </div>
              {pendingInvites.length === 0 ? (
                <div className="p-6 text-xs text-[#6B7488]">No pending invites.</div>
              ) : (
                <div className="divide-y divide-[#E6E9F0]/70">
                  {pendingInvites.map((invite) => (
                    <div key={invite.signup_id} className="flex items-center justify-between gap-4 p-4 text-xs">
                      <div className="min-w-0">
                        <div className="font-semibold text-[#0E1726]">{invite.email}</div>
                        <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-[#6B7488]">
                          <span className="capitalize">{invite.invited_role || "viewer"}</span>
                          <span>Expires {new Date(invite.expires_at).toLocaleString()}</span>
                          <span>Sent {invite.resend_count + 1} time{invite.resend_count === 0 ? "" : "s"}</span>
                        </div>
                        {invite.delivery_error && <div className="mt-1 text-[10px] text-red-300">{invite.delivery_error}</div>}
                      </div>
                      <div className="flex shrink-0 gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            setUserEmail(invite.email);
                            setUserRole(invite.invited_role || "viewer");
                            setUserError(null);
                            setInviteResult(null);
                            setIsUserModalOpen(true);
                          }}
                          className="rounded-lg border border-[#E6E9F0] px-3 py-2 text-[10px] font-semibold text-[#0E1726] hover:bg-[#F5F7FA]"
                        >
                          Resend
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCancelInvite(invite.signup_id)}
                          className="rounded-lg border border-red-900/50 px-3 py-2 text-[10px] font-semibold text-red-300 hover:bg-red-950/40"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab: Security / MFA */}
      {activeTab === "security" && (
        <div className="space-y-6">
          <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-[#0E1726]">Multi-Factor Authentication</h3>
                <p className="mt-1 max-w-2xl text-xs text-[#6B7488]">
                  TOTP MFA protects approval-sensitive console actions. Keep backup codes somewhere safe after setup.
                </p>
                {securityState && (
                  <div className="mt-4 text-xs text-[#6B7488]">
                    Signed in as <span className="font-semibold text-[#0E1726]">{securityState.email}</span>{" "}
                    with role <span className="capitalize text-[#0E1726]">{securityState.role}</span>.
                  </div>
                )}
                {mfaError && <div className="mt-3 text-xs text-red-300">{mfaError}</div>}
              </div>
              <span
                className={`shrink-0 rounded-full border px-3 py-1 text-[10px] font-bold uppercase ${
                  securityState?.mfa_enabled
                    ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                    : "border-amber-500/25 bg-amber-500/10 text-amber-200"
                }`}
              >
                MFA {securityState?.mfa_enabled ? "enabled" : "disabled"}
              </span>
            </div>

            <div className="mt-6 flex flex-wrap gap-3">
              {!securityState?.mfa_enabled ? (
                <button
                  type="button"
                  onClick={handleSetupMfa}
                  disabled={mfaBusy}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-60"
                >
                  {mfaBusy ? "Enabling..." : "Enable MFA"}
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={handleRegenerateMfaRecoveryCodes}
                    disabled={mfaBusy}
                    className="rounded-lg border border-indigo-300 bg-indigo-50 px-4 py-2 text-xs font-semibold text-indigo-800 hover:bg-indigo-100 disabled:opacity-60"
                  >
                    {mfaBusy ? "Verifying..." : "Replace recovery codes"}
                  </button>
                  {!(["owner", "admin"].includes(securityState?.role || "")) && (
                    <button
                      type="button"
                      onClick={handleDisableMfa}
                      disabled={mfaBusy}
                      className="rounded-lg border border-red-900/50 bg-red-950/20 px-4 py-2 text-xs font-semibold text-red-200 hover:bg-red-950/50 disabled:opacity-60"
                    >
                      {mfaBusy ? "Disabling..." : "Disable MFA"}
                    </button>
                  )}
                </>
              )}
            </div>

            {mfaRecoveryCodes.length > 0 && (
              <div className="mt-4 rounded-xl border border-amber-300 bg-amber-50 p-4">
                <div className="text-xs font-semibold text-amber-950">New one-time recovery codes</div>
                <p className="mt-1 text-xs text-amber-900">Save these now. The previous recovery codes no longer work.</p>
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
                  {mfaRecoveryCodes.map((code) => (
                    <span key={code} className="select-all rounded border border-amber-300 bg-white px-2 py-1 text-center font-mono text-xs text-amber-950">
                      {code}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {mfaSetup && (
              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4 flex flex-col items-center justify-center">
                  <div className="mb-3 text-[10px] font-bold uppercase tracking-wider text-[#6B7488] w-full text-left">Scan with Authenticator App</div>
                  <Image
                    src={`data:image/png;base64,${mfaSetup.qr_code_base64}`}
                    alt="MFA QR Code"
                    width={128}
                    height={128}
                    unoptimized
                    className="w-32 h-32 rounded bg-white p-1"
                  />
                </div>
                <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4 flex flex-col justify-center">
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Authenticator Secret (Manual Entry)</div>
                  <div className="select-all break-all font-mono text-xs text-[#0E1726]">{mfaSetup.mfa_secret}</div>
                  <div className="mt-3 text-[10px] text-[#6B7488]">
                    Add this secret to Google Authenticator, 1Password, Authy, or any TOTP app.
                  </div>
                </div>
                <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4 md:col-span-2">
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Backup Codes</div>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                    {mfaSetup.backup_codes.map((code) => (
                      <span key={code} className="rounded border border-[#E6E9F0] bg-[#F5F7FA] px-2 py-1 font-mono text-xs text-[#0E1726] text-center">
                        {code}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 md:col-span-2">
                  <div className="text-xs font-semibold text-amber-950">Enrollment is not active yet</div>
                  <p className="mt-1 text-xs text-amber-900">
                    Save the backup codes, then confirm a current authenticator code. Until confirmation, the existing factor remains active.
                  </p>
                  <button
                    type="button"
                    onClick={handleConfirmMfa}
                    disabled={mfaBusy}
                    className="mt-3 rounded-lg bg-amber-900 px-4 py-2 text-xs font-semibold text-white hover:bg-amber-800 disabled:opacity-60"
                  >
                    {mfaBusy ? "Confirming..." : "Confirm MFA enrollment"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {(isOwner || sessionRole === "admin") && (
            <form onSubmit={handleSaveSsoConfig} className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-xl">
              <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <h3 className="text-base font-bold text-[#0E1726]">Enterprise SSO</h3>
                  <p className="mt-1 max-w-2xl text-xs text-[#6B7488]">
                    OIDC sign-in uses authorization code flow, JWKS token validation, tenant mapping, and IdP group-to-role mapping.
                  </p>
                </div>
                <label className="inline-flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs font-semibold text-[#475069]">
                  <input
                    type="checkbox"
                    checked={ssoConfig.enabled}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, enabled: event.target.checked }))}
                    className="rounded border-[#E6E9F0] text-indigo-500 focus:ring-0"
                  />
                  SSO enabled
                </label>
              </div>

              {(ssoError || ssoMessage) && (
                <div className={`mb-4 rounded-lg border p-3 text-xs ${ssoError ? "border-red-500/20 bg-red-500/10 text-red-300" : "border-emerald-500/20 bg-emerald-500/10 text-emerald-300"}`}>
                  {ssoError || ssoMessage}
                </div>
              )}

              <div className="grid gap-4 md:grid-cols-2">
                {[
                  ["Issuer", "issuer", "https://idp.example.com"],
                  ["Client ID", "client_id", "authclaw-console"],
                  ["Redirect URI", "redirect_uri", "https://app.example.com/api/auth/oidc/callback"],
                  ["Authorization Endpoint", "authorization_endpoint", "Defaults to issuer/authorize"],
                  ["Token Endpoint", "token_endpoint", "Defaults to issuer/token"],
                  ["JWKS URI", "jwks_uri", "Defaults to issuer/.well-known/jwks.json"],
                  ["Email Claim", "email_claim", "email"],
                  ["Groups Claim", "groups_claim", "groups"],
                  ["Tenant Claim", "tenant_claim", "tenant_id"],
                  ["Tenant Claim Value", "tenant_claim_value", "Immutable external tenant ID"],
                ].map(([label, key, placeholder]) => (
                  <label key={key} className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                    {label}
                    <input
                      value={String(ssoConfig[key as keyof SsoConfig] || "")}
                      onChange={(event) => setSsoConfig((current) => ({ ...current, [key]: event.target.value }))}
                      placeholder={placeholder}
                      className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                    />
                  </label>
                ))}
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  Client Secre
                  <input
                    type="password"
                    value={ssoClientSecret}
                    onChange={(event) => setSsoClientSecret(event.target.value)}
                    placeholder={ssoConfig.has_client_secret ? "Stored encrypted; enter only to rotate" : "Required for confidential clients"}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                  />
                </label>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  Scopes
                  <input
                    value={ssoConfig.scopes.join(" ")}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, scopes: event.target.value.split(/\s+/).filter(Boolean) }))}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                  />
                </label>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  Default Role
                  <select
                    value={ssoConfig.default_role}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, default_role: event.target.value }))}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                  >
                    {["viewer", "operator", "developer", "admin", "owner"].map((role) => <option key={role} value={role}>{role}</option>)}
                  </select>
                </label>
                <label className="flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs font-semibold text-[#475069]">
                  <input
                    type="checkbox"
                    checked={ssoConfig.auto_provision}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, auto_provision: event.target.checked }))}
                    className="rounded border-[#E6E9F0] text-indigo-500 focus:ring-0"
                  />
                  Auto-provision verified SSO users
                </label>
                <label className="flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs font-semibold text-[#475069]">
                  <input
                    type="checkbox"
                    checked={ssoConfig.require_mfa}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, require_mfa: event.target.checked }))}
                    className="rounded border-[#E6E9F0] text-indigo-500 focus:ring-0"
                  />
                  Require IdP MFA context
                </label>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  Accepted AMR values
                  <input
                    value={ssoConfig.accepted_amr.join(" ")}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, accepted_amr: event.target.value.split(/\s+/).filter(Boolean) }))}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                  />
                </label>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  Accepted ACR values
                  <input
                    value={ssoConfig.accepted_acr.join(" ")}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, accepted_acr: event.target.value.split(/\s+/).filter(Boolean) }))}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                  />
                </label>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  Maximum authentication age (seconds)
                  <input
                    type="number"
                    min="0"
                    value={ssoConfig.max_auth_age_seconds}
                    onChange={(event) => setSsoConfig((current) => ({ ...current, max_auth_age_seconds: Number(event.target.value) }))}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                  />
                </label>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] md:col-span-2">
                  Group Role Mapping JSON
                  <textarea
                    value={ssoRoleMappingText}
                    onChange={(event) => setSsoRoleMappingText(event.target.value)}
                    rows={5}
                    className="mt-1 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 font-mono text-xs normal-case tracking-normal text-[#0E1726] outline-none focus:border-indigo-500"
                    placeholder='{"idp-admins":"admin","idp-viewers":"viewer"}'
                  />
                </label>
              </div>

              <div className="mt-5 flex flex-wrap justify-end gap-3">
                <button
                  type="button"
                  onClick={handleTestSsoConfig}
                  disabled={ssoBusy || !ssoConfig.issuer || !ssoConfig.client_id}
                  className="rounded-lg border border-[#E6E9F0] px-4 py-2 text-xs font-semibold text-[#475069] hover:bg-[#F5F7FA] disabled:opacity-50"
                >
                  Test Metadata
                </button>
                <button
                  type="submit"
                  disabled={ssoBusy}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
                >
                  {ssoBusy ? "Saving..." : "Save SSO"}
                </button>
              </div>
            </form>
          )}
        </div>
      )}

      {/* Tab: API Keys Lifecycle */}
      {activeTab === "keys" && isOwner && (
        <div className="space-y-6">
          <div className="flex justify-between items-center bg-white border border-[#E6E9F0] p-4 rounded-xl">
            <div className="text-xs">
              <h3 className="font-bold text-[#0E1726] flex items-center gap-1.5">
                <KeyRound className="w-4 h-4 text-indigo-400" />
                Active Credentials
              </h3>
              <p className="text-[#6B7488] mt-0.5">Generate service tokens for application integrations.</p>
            </div>
            <button
              onClick={() => { setKeyName(""); setKeyScopes(["read"]); setKeyError(null); setGeneratedKey(null); setIsKeyModalOpen(true); }}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition"
            >
              <Plus className="w-4 h-4" />
              Generate API Key
            </button>
          </div>

          <div className="rounded-[20px] bg-white border border-[#E6E9F0] shadow-xl overflow-hidden">
            {loading ? (
              <div className="p-8 text-center flex justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-indigo-500" />
              </div>
            ) : apiKeys.length === 0 ? (
              <div className="p-12 text-center text-[#6B7488] text-xs">No active API keys found. Click generate to create one.</div>
            ) : (
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#E6E9F0] bg-[#F5F7FA]/40 text-[#6B7488] font-bold uppercase tracking-wider text-[10px]">
                    <th className="px-6 py-4">Key ID / Name</th>
                    <th className="px-6 py-4">Scopes</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4">Created At</th>
                    <th className="px-6 py-4">Expires</th>
                    <th className="px-6 py-4">Last Used</th>
                    <th className="px-6 py-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6E9F0]/50">
                  {apiKeys.map((k) => (
                    <tr key={k.id} className="hover:bg-[#F5F7FA]/10 transition-colors">
                      <td className="px-6 py-4">
                        <div className="font-semibold text-[#0E1726]">{k.name}</div>
                        <div className="text-[10px] text-[#6B7488] font-mono mt-0.5">{k.id}</div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {k.scopes.map((s) => (
                            <span key={s} className="px-1.5 py-0.5 rounded bg-[#F5F7FA] text-[9px] text-[#6B7488] font-bold border border-[#E6E9F0] uppercase">
                              {s}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-bold text-[10px]">
                          Active
                        </span>
                      </td>
                      <td className="px-6 py-4 text-[#6B7488] font-mono">
                        {new Date(k.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-[#6B7488] font-mono">
                        {new Date(k.expires_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-[#6B7488] font-mono">
                        <div>{k.last_used ? new Date(k.last_used).toLocaleString() : "Never"}</div>
                        {k.last_used_ip && <div className="text-[9px] text-[#6B7488]">{k.last_used_ip}</div>}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleRotateKey(k)}
                          className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-[#F5F7FA] hover:bg-[#F5F7FA] text-[#475069] border border-[#E6E9F0] text-[10px] font-semibold transition"
                        >
                          <RotateCw className="w-3 h-3" />
                          Rotate
                        </button>
                        <button
                          onClick={() => handleRevokeKey(k.id)}
                          className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-red-950/20 hover:bg-red-950/80 text-red-400 border border-red-900/30 hover:border-red-800 text-[10px] font-semibold transition"
                        >
                          Revoke
                        </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Tab: Cloud Logins */}
      {activeTab === "cloud" && (isOwner || sessionRole === "admin") && (
        <div className="space-y-6">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
            <form onSubmit={handleSaveCloudConnector} className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl">
              <div className="mb-5 flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-[#0E1726] flex items-center gap-2">
                    <Cloud className="w-4 h-4 text-indigo-400" />
                    Cloud Credential Vault
                  </h3>
                  <p className="mt-1 text-xs text-[#6B7488]">
                    Store AWS, GitHub, or GCP credentials for verified scans and approved remediation. Secrets are encrypted and never shown again.
                  </p>
                </div>
                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-bold uppercase text-emerald-300">
                  Encrypted
                </span>
              </div>

              {(cloudError || cloudMessage) && (
                <div className={`mb-4 rounded-lg border p-3 text-xs ${cloudError ? "border-red-500/20 bg-red-500/10 text-red-300" : "border-emerald-500/20 bg-emerald-500/10 text-emerald-300"}`}>
                  {cloudError || cloudMessage}
                </div>
              )}

              <div className="mb-4 grid grid-cols-3 gap-2">
                {(["aws", "github", "gcp"] as CloudProvider[]).map((provider) => (
                  <button
                    key={provider}
                    type="button"
                    onClick={() => updateCloudProvider(provider)}
                    className={`rounded-lg border px-3 py-2 text-xs font-bold uppercase ${
                      cloudProvider === provider
                        ? "border-indigo-500 bg-indigo-500/10 text-indigo-500"
                        : "border-[#E6E9F0] bg-[#F5F7FA] text-[#6B7488]"
                    }`}
                  >
                    {provider}
                  </button>
                ))}
              </div>

              <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Display Name</label>
              <input
                value={cloudDisplayName}
                onChange={(event) => setCloudDisplayName(event.target.value)}
                className="mb-4 w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
              />

              <div className="space-y-3">
                {[...(selectedCloudCatalog?.fields || []), ...(selectedCloudCatalog?.optional_fields || [])].map((field) => (
                  <div key={field}>
                    <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                      {field.replace(/_/g, " ")}
                      {selectedCloudCatalog?.optional_fields.includes(field) ? "" : " *"}
                    </label>
                    {field.includes("json") ? (
                      <textarea
                        value={cloudForm[field] || ""}
                        onChange={(event) => setCloudForm((current) => ({ ...current, [field]: event.target.value }))}
                        rows={6}
                        className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 font-mono text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                      />
                    ) : (
                      <input
                        type={field.includes("secret") || field === "token" ? "password" : "text"}
                        value={cloudForm[field] || ""}
                        onChange={(event) => setCloudForm((current) => ({ ...current, [field]: event.target.value }))}
                        className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                      />
                    )}
                  </div>
                ))}
              </div>

              <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900">
                Use scoped tokens or service accounts. Remediation actions require fresh MFA and are audited on the Cloud page.
              </div>

              <div className="mt-5 flex justify-end">
                <button
                  type="submit"
                  disabled={cloudSubmitting || !cloudDisplayName.trim()}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Cloud className="w-4 h-4" />
                  {cloudSubmitting ? "Saving..." : "Save Credential"}
                </button>
              </div>
            </form>

            <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold text-[#0E1726]">Connector Health</h3>
                  <p className="mt-1 text-xs text-[#6B7488]">Verify, inspect, and revoke cloud logins from one place.</p>
                </div>
                <button
                  type="button"
                  onClick={refreshCloudConnectors}
                  className="rounded-lg border border-[#E6E9F0] p-2 text-[#475069] hover:bg-[#F5F7FA]"
                >
                  <RotateCw className="w-4 h-4" />
                </button>
              </div>

              {cloudConnectors.length === 0 ? (
                <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-6 text-center text-xs text-[#6B7488]">
                  No cloud logins connected yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {cloudConnectors.map((connector) => (
                    <div key={connector.id} className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-semibold text-[#0E1726]">{connector.display_name}</span>
                            <span className="font-mono text-[10px] uppercase text-[#6B7488]">{connector.provider}</span>
                            <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${
                              connector.status === "connected"
                                ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                                : connector.status === "error"
                                  ? "border-red-500/25 bg-red-500/10 text-red-300"
                                  : "border-[#E6E9F0] bg-white text-[#6B7488]"
                            }`}>
                              {connector.status}
                            </span>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2">
                            {Object.entries(connector.metadata || {}).slice(0, 4).map(([key, value]) => (
                              <span key={key} className="rounded border border-[#E6E9F0] bg-white px-2 py-1 font-mono text-[10px] text-[#6B7488]">
                                {key}: {String(value)}
                              </span>
                            ))}
                          </div>
                          {connector.last_error && <div className="mt-2 text-xs text-red-300">{connector.last_error}</div>}
                        </div>
                        <div className="flex shrink-0 gap-2">
                          <button
                            type="button"
                            onClick={() => handleVerifyCloudConnector(connector.id)}
                            className="rounded border border-[#E6E9F0] p-1.5 text-[#475069] hover:bg-white"
                          >
                            <RotateCw className="h-3.5 w-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleRevokeCloudConnector(connector.id)}
                            className="rounded border border-red-900/50 p-1.5 text-red-300 hover:bg-red-950/40"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab: Worker Tokens */}
      {activeTab === "workers" && (isOwner || sessionRole === "admin") && (
        <div className="space-y-6">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
            <form onSubmit={handleIssueWorkerToken} className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl">
              <div className="mb-5 flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-[#0E1726] flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-indigo-400" />
                    Issue Worker Token
                  </h3>
                  <p className="mt-1 text-xs text-[#6B7488]">
                    Short-lived credentials that limit what a scan or remediation worker is allowed to do.
                  </p>
                </div>
                <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-bold uppercase text-emerald-300">
                  Max 30m
                </span>
              </div>

              {workerError && (
                <div className="mb-4 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-200">
                  {workerError}
                </div>
              )}

              {generatedWorkerToken && (
                <div className="mb-4 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3">
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-emerald-300">
                    Copy Worker Token Once
                  </div>
                  <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-[#F5F7FA] p-2">
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-emerald-100">
                      {generatedWorkerToken}
                    </span>
                    <button
                      type="button"
                      onClick={copyWorkerToken}
                      className="rounded border border-[#E6E9F0] p-1.5 text-[#475069] hover:bg-[#F5F7FA]"
                    >
                      {workerCopied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              )}

              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                    Connector
                  </label>
                  <select
                    value={workerForm.connector}
                    onChange={(event) => updateWorkerConnector(event.target.value)}
                    className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  >
                    {workerConnectors.map((connector) => (
                      <option key={connector.connector} value={connector.connector}>
                        {connector.display_name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                    Purpose
                  </label>
                  <select
                    value={workerForm.purpose}
                    onChange={(event) => setWorkerForm((current) => ({ ...current, purpose: event.target.value }))}
                    className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  >
                    <option value="scan">Scan</option>
                    <option value="remediation">Remediation</option>
                    <option value="audit">Audit</option>
                    <option value="test">Test</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                    Action
                  </label>
                  <select
                    value={workerForm.action_id}
                    onChange={(event) => updateWorkerAction(event.target.value)}
                    className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  >
                    {(selectedWorkerConnector?.actions || []).map((action) => (
                      <option key={action.name} value={action.name}>
                        {action.name}{action.destructive ? " (destructive)" : ""}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                    Token Lifetime
                  </label>
                  <input
                    type="number"
                    min={60}
                    max={1800}
                    value={workerForm.ttl_seconds}
                    onChange={(event) => setWorkerForm((current) => ({ ...current, ttl_seconds: Number(event.target.value) }))}
                    className="w-full rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#0E1726] focus:border-indigo-500/80 focus:outline-none"
                  />
                </div>
              </div>

              <div className="mt-4">
                <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Scopes</div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {(selectedWorkerConnector?.scopes || []).map((scope) => (
                    <label key={scope} className="flex items-center gap-2 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] px-3 py-2 text-xs text-[#475069]">
                      <input
                        type="checkbox"
                        checked={workerForm.scopes.includes(scope)}
                        onChange={() => toggleWorkerScope(scope)}
                        className="rounded border-[#E6E9F0] bg-[#F5F7FA] text-indigo-500 focus:ring-0 focus:ring-offset-0"
                      />
                      <span className="font-mono text-[11px]">{scope}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900">
                Destructive actions are denied unless the selected action is explicitly marked destructive and allowlisted into the token boundary.
              </div>

              <div className="mt-5 flex justify-end">
                <button
                  type="submit"
                  disabled={workerSubmitting || workerForm.scopes.length === 0 || !workerForm.action_id}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Plus className="w-4 h-4" />
                  {workerSubmitting ? "Issuing..." : "Issue Token"}
                </button>
              </div>
            </form>

            <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-5 shadow-xl">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold text-[#0E1726]">Allowed Worker Actions</h3>
                  <p className="mt-1 text-xs text-[#6B7488]">Every connector starts denied and only these actions can be issued into a token.</p>
                </div>
                <button
                  type="button"
                  onClick={refreshWorkers}
                  className="rounded-lg border border-[#E6E9F0] p-2 text-[#475069] hover:bg-[#F5F7FA]"
                >
                  <RotateCw className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-3">
                {workerConnectors.map((connector) => (
                  <div key={connector.connector} className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="text-sm font-bold text-[#0E1726]">{connector.display_name}</div>
                        <div className="mt-1 text-[10px] text-[#6B7488]">
                          {connector.credential_source} - {connector.actions.length} actions
                        </div>
                      </div>
                      <span className="rounded-full border border-[#E6E9F0] px-2 py-0.5 text-[10px] font-semibold uppercase text-[#475069]">
                        {connector.status}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {connector.actions.slice(0, 6).map((action) => (
                        <span
                          key={action.name}
                          className={`rounded border px-2 py-1 font-mono text-[10px] ${
                            action.destructive
                              ? "border-red-900/50 bg-red-950/20 text-red-200"
                              : "border-[#E6E9F0] bg-[#F5F7FA] text-[#475069]"
                          }`}
                        >
                          {action.name}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-[20px] border border-[#E6E9F0] bg-white shadow-xl overflow-hidden">
            <div className="flex items-center justify-between border-b border-[#E6E9F0] px-5 py-4">
              <div>
                <h3 className="text-sm font-bold text-[#0E1726]">Recent Worker Tokens</h3>
                <p className="mt-1 text-xs text-[#6B7488]">Raw secrets are never stored or shown after creation.</p>
              </div>
              <span className="rounded-full border border-[#E6E9F0] px-2 py-0.5 text-[10px] font-semibold text-[#6B7488]">
                {workerTokens.length} tokens
              </span>
            </div>
            {workerTokens.length === 0 ? (
              <div className="p-6 text-xs text-[#6B7488]">No worker tokens issued yet.</div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="border-b border-[#E6E9F0] bg-[#F5F7FA]/40 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
                  <tr>
                    <th className="px-5 py-3">Connector</th>
                    <th className="px-5 py-3">Action</th>
                    <th className="px-5 py-3">Boundary</th>
                    <th className="px-5 py-3">Expires</th>
                    <th className="px-5 py-3">Status</th>
                    <th className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6E9F0]/60">
                  {workerTokens.map((token) => (
                    <tr key={token.id} className="hover:bg-[#F5F7FA]/10">
                      <td className="px-5 py-4">
                        <div className="font-semibold text-[#0E1726] uppercase">{token.connector}</div>
                        <div className="mt-1 font-mono text-[10px] text-[#6B7488]">{token.token_prefix}</div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="font-mono text-[#475069]">{token.action_id}</div>
                        <div className="mt-1 text-[10px] text-[#6B7488]">{token.purpose}</div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="text-[10px] text-[#6B7488]">
                          {(token.permission_boundary.allowed_actions || []).length} allowed actions
                        </div>
                        <div className="mt-1 text-[10px] text-[#6B7488]">
                          uses {token.use_count}
                          {token.last_used_action ? ` - last ${token.last_used_action}` : ""}
                        </div>
                      </td>
                      <td className="px-5 py-4 text-[#6B7488]">
                        {new Date(token.expires_at).toLocaleString()}
                      </td>
                      <td className="px-5 py-4">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${
                          token.status === "active"
                            ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                            : "border-[#E6E9F0] bg-[#F5F7FA] text-[#6B7488]"
                        }`}>
                          {token.status}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-right">
                        {token.status === "active" ? (
                          <button
                            type="button"
                            onClick={() => handleRevokeWorkerToken(token.id)}
                            className="rounded border border-red-900/50 p-1.5 text-red-300 hover:bg-red-950/40"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        ) : (
                          <span className="text-[10px] text-[#6B7488]">Locked</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Tab: Usage Limits */}
      {activeTab === "limits" && (isOwner || sessionRole === "admin") && (
        <div className="space-y-6">
          <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-[#0E1726]">Gateway Usage & Spend Guardrails</h3>
                <p className="mt-1 max-w-2xl text-xs text-[#6B7488]">
                  These caps are enforced at the gateway before provider egress. Spend is an estimate from request volume, not a provider invoice.
                </p>
                {usageError && <p className="mt-2 text-xs text-red-300">{usageError}</p>}
              </div>
              <span
                className={`shrink-0 rounded-full border px-3 py-1 text-[10px] font-bold uppercase ${
                  usageLimits?.limits_enabled
                    ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                    : "border-red-500/25 bg-red-500/10 text-red-200"
                }`}
              >
                Limits {usageLimits?.limits_enabled ? "on" : "off"}
              </span>
            </div>

            {!usageLimits ? (
              <div className="mt-6 rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-6 text-xs text-[#6B7488]">
                Usage limits are not available for this role or session.
              </div>
            ) : (
              <div className="mt-6 grid gap-4 md:grid-cols-4">
                {[
                  ["Requests Today", usageLimits.requests_today.toLocaleString(), `${usageLimits.requests_remaining_today.toLocaleString()} left`],
                  ["Daily Request Cap", usageLimits.daily_requests_limit.toLocaleString(), "Hard gateway limit"],
                  ["Est. Spend Today", `$${usageLimits.estimated_spend_today_usd.toFixed(4)}`, `$${usageLimits.spend_remaining_today_usd.toFixed(2)} left`],
                  ["Blocked Today", usageLimits.blocked_today.toLocaleString(), "Policy/rate blocks"],
                ].map(([label, value, sub]) => (
                  <div key={label} className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">{label}</div>
                    <div className="mt-2 text-2xl font-bold text-[#0E1726]">{value}</div>
                    <div className="mt-1 text-[10px] text-[#6B7488]">{sub}</div>
                  </div>
                ))}
                <div className="md:col-span-4 grid gap-4 md:grid-cols-4">
                  <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Minute Limit</div>
                    <div className="mt-2 text-sm font-semibold text-[#0E1726]">{usageLimits.requests_per_minute} req/min</div>
                  </div>
                  <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Burst Limit</div>
                    <div className="mt-2 text-sm font-semibold text-[#0E1726]">{usageLimits.burst_10_seconds} req/10s</div>
                  </div>
                  <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Body Limit</div>
                    <div className="mt-2 text-sm font-semibold text-[#0E1726]">{Math.round(usageLimits.max_body_bytes / 1024)} KB</div>
                  </div>
                  <div className="rounded-xl border border-[#E6E9F0] bg-[#F5F7FA] p-4">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">Spend Guardrail</div>
                    <div className="mt-2 text-sm font-semibold text-[#0E1726]">
                      ${usageLimits.max_daily_spend_usd.toFixed(2)} / day
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: Tenant Status */}
      {activeTab === "tenant" && (
        <div className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-xl space-y-6">
          <div className="flex items-center gap-2 border-b border-[#E6E9F0] pb-3">
            <Building className="w-5 h-5 text-indigo-400" />
            <h3 className="text-base font-bold text-[#0E1726]">Active Tenant</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs leading-relaxed max-w-2xl">
            <div className="space-y-4">
              <div>
                <p className="text-[#6B7488] text-[10px] font-bold uppercase tracking-wider">Tenant UUID</p>
                <div className="flex items-center gap-2 mt-1.5">
                  <span className="font-mono text-[#475069] select-all px-2.5 py-1.5 rounded bg-[#F5F7FA] border border-[#E6E9F0]">
                    {tenantId}
                  </span>
                </div>
              </div>

              <div>
                <p className="text-[#6B7488] text-[10px] font-bold uppercase tracking-wider">Control Plane Host</p>
                <p className="text-[#475069] mt-1 font-mono">{controlPlaneHost || "Loading runtime configuration…"}</p>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-[#6B7488] text-[10px] font-bold uppercase tracking-wider">Security Strategy</p>
              <p className="text-[#475069] mt-1.5">Row Level Isolation (RLS) is active on the PostgreSQL storage layer.</p>
                <p className="text-[#6B7488] mt-1.5">Current console role: <span className="capitalize text-[#475069]">{sessionRole}</span></p>
              </div>

              <div>
                <p className="text-[#6B7488] text-[10px] font-bold uppercase tracking-wider">Subscription Tier</p>
                <span className="inline-block px-2.5 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 font-semibold text-[10px] mt-1 uppercase">
                  Enterprise Sandbox
                </span>
                <p className="mt-3 text-[#6B7488] text-[10px] font-bold uppercase tracking-wider">Tenant Status</p>
                <span className={`inline-block px-2.5 py-0.5 rounded font-semibold text-[10px] mt-1 uppercase ${
                  tenantStatus === "active"
                    ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                    : "bg-red-500/10 border border-red-500/20 text-red-300"
                }`}>
                  {tenantStatus}
                </span>
              </div>
            </div>
          </div>

          {isOwner && (
            <div className="border-t border-[#E6E9F0] pt-5 max-w-2xl">
              <div className="rounded-xl border border-red-900/40 bg-red-950/10 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h4 className="text-sm font-bold text-red-200 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4" />
                      Tenant Lifecycle
                    </h4>
                    <p className="text-xs text-red-200/70 mt-1">
                      Disable suspends most access without deleting audit evidence. Reactivate restores normal use.
                    </p>
                    {tenantActionError && <p className="text-xs text-red-300 mt-2">{tenantActionError}</p>}
                  </div>
                  <button
                    onClick={() => handleTenantStatusChange(tenantStatus === "active" ? "disabled" : "active")}
                    disabled={tenantActionBusy}
                    className="shrink-0 rounded-lg border border-red-800 bg-red-950/40 px-3 py-2 text-xs font-semibold text-red-200 hover:bg-red-900/40 disabled:opacity-50"
                  >
                    {tenantActionBusy ? "Updating..." : tenantStatus === "active" ? "Disable" : "Reactivate"}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
      </div>

      {/* Add User Modal */}
      {isUserModalOpen && (
        <SettingsModal
          title="Invite Tenant Member"
          onClose={() => { setInviteResult(null); setIsUserModalOpen(false); }}
          onBackdropClose={() => setIsUserModalOpen(false)}
          error={userError}
        >
            {inviteResult ? (
              <div className="space-y-4">
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-xs text-emerald-100">
                  Invite sent to <span className="font-semibold">{inviteResult.email}</span> as{" "}
                  <span className="font-semibold capitalize">{inviteResult.invited_role}</span>.
                </div>
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
                    Invite Verification Link
                  </label>
                  <div className="flex gap-2 rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-2">
                    <input
                      readOnly
                      value={inviteLink}
                      onFocus={(event) => event.currentTarget.select()}
                      className="min-w-0 flex-1 bg-transparent font-mono text-xs text-[#475069] outline-none"
                    />
                    <button
                      type="button"
                      onClick={copyInviteLink}
                      className="rounded bg-[#F5F7FA] px-2 py-1 text-xs font-semibold text-[#0E1726] hover:bg-[#F5F7FA]"
                    >
                      {inviteCopied ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => { setInviteResult(null); setIsUserModalOpen(false); }}
                    className="px-4 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] font-semibold text-xs transition"
                  >
                    Done
                  </button>
                </div>
              </div>
            ) : (
            <form onSubmit={handleAddUser} className="space-y-4">
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#6B7488]">
                    <Mail className="w-4 h-4" />
                  </span>
                  <input
                    type="email"
                    required
                    value={userEmail}
                    onChange={(e) => setUserEmail(e.target.value)}
                    placeholder="developer@authclaw.com"
                    className="w-full pl-10 pr-4 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
                  Role Permission
                </label>
                <select
                  value={userRole}
                  onChange={(e) => setUserRole(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
                >
                  <option value="viewer">Viewer (Overview & audit)</option>
                  <option value="developer">Developer (Read-only technical view)</option>
                  <option value="operator">Operator (Read-only operational view)</option>
                  <option value="admin">Admin (Policies & provider keys)</option>
                  <option value="owner">Owner (Tenant control)</option>
                </select>
              </div>

              <div className="pt-4 border-t border-[#E6E9F0] flex justify-end gap-2.5">
                <button
                  type="button"
                  onClick={() => setIsUserModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#F5F7FA] border border-[#E6E9F0] text-[#475069] font-semibold text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={userSubmitting}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs shadow-lg transition active:scale-[0.98] disabled:opacity-50"
                >
                  {userSubmitting ? "Sending..." : "Send Invite"}
                </button>
              </div>
            </form>
            )}
        </SettingsModal>
      )}

      {/* Generate API Key Modal */}
      {isKeyModalOpen && (
        <SettingsModal
          title="Generate Integration Token"
          onClose={() => setIsKeyModalOpen(false)}
          error={keyError}
          maxWidthClass="max-w-[450px]"
        >
            {generatedKey ? (
              /* Success view displaying the raw secret key EXACTLY ONCE */
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-xs flex gap-2.5">
                  <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                  <div>
                    <h4 className="font-bold">Credential Issued Successfully</h4>
                    <p className="mt-0.5">Make sure to copy your API key now. It will not be shown again.</p>
                  </div>
                </div>

                <div className="flex gap-2 p-3.5 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0]">
                  <span className="flex-1 font-mono text-xs text-indigo-400 truncate tracking-wide select-all">
                    {generatedKey}
                  </span>
                  <button
                    onClick={copyToClipboard}
                    className="p-1 rounded bg-[#F5F7FA] hover:bg-[#F5F7FA] text-[#475069] hover:text-[#0E1726] border border-[#E6E9F0] transition"
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => setIsKeyModalOpen(false)}
                    className="px-4 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] font-semibold text-xs transition"
                  >
                    Close
                  </button>
                </div>
              </div>
            ) : (
              /* Configuration view */
              <form onSubmit={handleGenerateKey} className="space-y-4">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
                    Token Name / Label
                  </label>
                  <input
                    type="text"
                    required
                    value={keyName}
                    onChange={(e) => setKeyName(e.target.value)}
                    placeholder="e.g. CI/CD Deployment Runner"
                    className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
                    Assigned Scopes
                  </label>
                  <div className="space-y-2 mt-1.5">
                    {["read", "write", "admin"].map((scope) => (
                      <label key={scope} className="flex items-center gap-2 text-xs text-[#475069] capitalize cursor-pointer">
                        <input
                          type="checkbox"
                          checked={keyScopes.includes(scope)}
                          onChange={() => toggleScope(scope)}
                          className="rounded bg-[#F5F7FA] border-[#E6E9F0] text-indigo-500 focus:ring-0 focus:ring-offset-0"
                        />
                        {scope} access
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-[#6B7488] mb-1.5">
                    Expires In
                  </label>
                  <select
                    value={keyExpiresInDays}
                    onChange={(e) => setKeyExpiresInDays(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-lg bg-[#F5F7FA] border border-[#E6E9F0] text-[#0E1726] text-xs focus:outline-none focus:border-indigo-500/80 transition"
                  >
                    <option value={30}>30 days</option>
                    <option value={90}>90 days</option>
                    <option value={180}>180 days</option>
                    <option value={365}>365 days</option>
                  </select>
                </div>

                <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200 text-[10px] leading-normal flex gap-2">
                  <AlertTriangle className="w-4.5 h-4.5 text-amber-500 flex-shrink-0" />
                  <span>
                    API Keys have complete access to prompt gateway operations under their assigned scope. Ensure the secret is handled securely.
                  </span>
                </div>

                <div className="pt-4 border-t border-[#E6E9F0] flex justify-end gap-2.5">
                  <button
                    type="button"
                    onClick={() => setIsKeyModalOpen(false)}
                    className="px-4 py-2 rounded-lg bg-[#F5F7FA] hover:bg-[#F5F7FA] border border-[#E6E9F0] text-[#475069] font-semibold text-xs transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={keySubmitting}
                    className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs shadow-lg transition active:scale-[0.98] disabled:opacity-50"
                  >
                    {keySubmitting ? "Generating..." : "Generate Token"}
                  </button>
                </div>
              </form>
            )}
        </SettingsModal>
      )}
    </div>
  );
}
