/** Map the imported console's legacy paths to canonical AuthClaw control-plane paths. */
export function mapCanonicalPath(path: string): string {
  const direct: Record<string, string> = {
    '/audit/logs': '/audit-logs',
    '/audit/verify': '/audit-logs?integrity_check=true&limit=100',
    '/compliance/dashboard': '/compliance-scores',
    '/compliance/scores': '/compliance-scores',
    '/compliance/scores/history': '/compliance-scores/history/trend',
    '/gateway-routes': '/gateways',
    '/providers': '/provider-credentials',
    '/tenants': '/tenants/current',
  };
  if (direct[path]) return direct[path];
  if (path.startsWith('/providers/')) {
    return path.replace('/providers/', '/provider-credentials/');
  }
  if (path.startsWith('/gateway-routes/')) {
    return path.replace('/gateway-routes/', '/gateways/');
  }
  if (path === '/approvals' || path.startsWith('/approvals?')) {
    return path.replace('/approvals', '/workflows/approvals');
  }
  if (path.startsWith('/approvals/')) {
    return path.replace('/approvals/', '/workflows/approvals/');
  }
  return path;
}

export function mapCanonicalRequest(method: string, path: string) {
  const normalizedMethod = method.toUpperCase();
  const revokeMatch = path.match(/^\/api-keys\/([^/]+)\/revoke$/);
  if (normalizedMethod === 'POST' && revokeMatch) {
    return { method: 'DELETE', path: `/api-keys/${revokeMatch[1]}` };
  }
  if (normalizedMethod === 'PATCH' && path.startsWith('/gateway-routes/')) {
    return { method: 'PUT', path: mapCanonicalPath(path) };
  }
  if (normalizedMethod === 'POST' && path === '/compliance/scores/calculate') {
    return { method: 'GET', path: '/compliance-scores?persist_snapshot=true' };
  }
  return { method: normalizedMethod, path: mapCanonicalPath(path) };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Normalize the small set of response-shape differences used by launch-critical pages. */
export function normalizeCanonicalResponse(originalPath: string, data: unknown): unknown {
  if (!isRecord(data)) return data;
  if (originalPath.startsWith('/audit/logs') && Array.isArray(data.records)) {
    return { ...data, items: data.records };
  }
  if (originalPath === '/audit/verify' && Array.isArray(data.records)) {
    const invalid = data.records.filter(
      (record) => isRecord(record) && record.chain_valid === false,
    ).length;
    return {
      status: invalid === 0 ? 'intact' : 'tampered',
      scanned_records: data.records.length,
      missing_records: 0,
      tampered_records: invalid,
      chain_breaks: invalid,
    };
  }
  if (
    (originalPath === '/compliance/dashboard' || originalPath === '/compliance/scores') &&
    Array.isArray(data.frameworks)
  ) {
    const summaries: Record<string, unknown> = {};
    for (const framework of data.frameworks) {
      if (!isRecord(framework) || typeof framework.framework !== 'string') continue;
      const key = framework.framework.toLowerCase().replace(/[^a-z0-9]+/g, '');
      summaries[key] = { ...framework, status: 'calculated' };
    }
    return { ...data, ...summaries };
  }
  return data;
}
