import { handleApiError, proxyBackend, type RouteContext } from "@/lib/api-client";

export async function PATCH(
  request: Request,
  context: RouteContext<{ reference: string }>,
) {
  const { reference } = await context.params;
  try {
    const body = await request.json();
    const newStatus = String(body.new_status || "");
    return proxyBackend(
      `/api/public/v1/access-requests/${encodeURIComponent(reference)}/status`,
      { method: "PATCH", params: { new_status: newStatus } },
      204,
    );
  } catch (error: unknown) {
    return handleApiError(error);
  }
}
