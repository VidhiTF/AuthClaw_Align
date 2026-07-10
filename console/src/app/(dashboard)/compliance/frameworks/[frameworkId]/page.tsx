import { ComplianceConsole } from '@/components/compliance/compliance-console';

export default async function ComplianceFrameworkDetailPage({
  params,
}: {
  params: Promise<{ frameworkId: string }>;
}) {
  const { frameworkId } = await params;
  return <ComplianceConsole view="framework-detail" frameworkId={frameworkId} />;
}
