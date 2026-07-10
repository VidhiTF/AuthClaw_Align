type SharedPosture = {
  posture: string;
  counts?: Record<string, unknown>;
  status_counts?: Record<string, number>;
  severity_counts?: Record<string, number>;
};

type SharedTrustPage = {
  organization: string;
  generated_at: string;
  language: string;
  expires_at: string;
  artifact: {
    artifact_type: string;
    content_hash: string;
    manifest_hash?: string | null;
    created_at: string;
  };
  security_posture: SharedPosture;
  compliance_posture: SharedPosture;
  remediation_posture: SharedPosture;
  integration_health: SharedPosture;
};

const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

async function loadSharedTrust(token: string): Promise<{ data?: SharedTrustPage; error?: string }> {
  const response = await fetch(`${apiBase}/trust/shared/${encodeURIComponent(token)}`, { cache: 'no-store' });
  if (!response.ok) {
    return { error: response.status === 404 ? 'This share link is invalid, expired, or revoked.' : 'Shared Trust Center is unavailable.' };
  }
  return { data: await response.json() };
}

function postureCard(title: string, posture: SharedPosture) {
  const counts = Object.entries(posture.counts || {});
  const severity = Object.entries(posture.severity_counts || {});
  const valueText = (value: unknown) => typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value);
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.03] p-5">
      <p className="text-xs uppercase tracking-wider text-neutral-500">{title}</p>
      <h2 className="mt-2 text-xl font-semibold text-neutral-100">{posture.posture}</h2>
      <div className="mt-4 grid gap-2 text-sm text-neutral-300">
        {counts.map(([key, value]) => <div key={key} className="flex justify-between gap-4"><span>{key}</span><span>{valueText(value)}</span></div>)}
        {severity.map(([key, value]) => <div key={key} className="flex justify-between gap-4"><span>{key}</span><span>{value}</span></div>)}
        {counts.length === 0 && severity.length === 0 && <span className="text-neutral-500">No public count metadata available.</span>}
      </div>
    </section>
  );
}

export default async function SharedTrustPageRoute({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const { data, error } = await loadSharedTrust(token);

  if (error || !data) {
    return (
      <main className="min-h-screen bg-[#050505] px-6 py-16 text-neutral-100">
        <div className="mx-auto max-w-2xl rounded-lg border border-amber-500/20 bg-amber-500/10 p-6">
          <h1 className="text-2xl font-semibold">Shared Trust Center unavailable</h1>
          <p className="mt-3 text-sm text-amber-100">{error}</p>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#050505] px-6 py-10 text-neutral-100">
      <div className="mx-auto max-w-6xl space-y-8">
        <header className="border-b border-white/10 pb-6">
          <p className="text-xs uppercase tracking-wider text-blue-300">Shared Trust Center</p>
          <h1 className="mt-2 text-3xl font-bold">{data.organization}</h1>
          <p className="mt-3 max-w-3xl text-sm text-neutral-400">{data.language}</p>
          <div className="mt-4 grid gap-2 text-xs text-neutral-500 md:grid-cols-2">
            <span>Generated {new Date(data.generated_at).toLocaleString()}</span>
            <span>Share expires {new Date(data.expires_at).toLocaleString()}</span>
          </div>
        </header>

        <div className="grid gap-4 md:grid-cols-2">
          {postureCard('Security posture', data.security_posture)}
          {postureCard('Compliance posture', data.compliance_posture)}
          {postureCard('Remediation posture', data.remediation_posture)}
          {postureCard('Integration health', data.integration_health)}
        </div>

        <section className="rounded-lg border border-white/10 bg-white/[0.03] p-5">
          <p className="text-xs uppercase tracking-wider text-neutral-500">Shared artifact metadata</p>
          <div className="mt-4 grid gap-3 text-sm text-neutral-300 md:grid-cols-2">
            <div>Type: {data.artifact.artifact_type}</div>
            <div>Created: {new Date(data.artifact.created_at).toLocaleString()}</div>
            <div className="break-all">Content hash: {data.artifact.content_hash}</div>
            <div className="break-all">Manifest hash: {data.artifact.manifest_hash || 'not available'}</div>
          </div>
        </section>
      </div>
    </main>
  );
}
