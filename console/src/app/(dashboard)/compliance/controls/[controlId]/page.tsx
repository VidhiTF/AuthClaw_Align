import { ComplianceConsole } from '@/components/compliance/compliance-console';

export default async function ComplianceControlDetailPage({
  params,
}: {
  params: Promise<{ controlId: string }>;
}) {
  const { controlId } = await params;
  return <ComplianceConsole view="control-detail" controlId={controlId} />;
}
