import { RemediationConsole } from '@/components/remediation/remediation-console';

export default async function RemediationPlanDetailPage({
  params,
}: {
  params: Promise<{ planId: string }>;
}) {
  const { planId } = await params;
  return <RemediationConsole view="plan-detail" planId={planId} />;
}
