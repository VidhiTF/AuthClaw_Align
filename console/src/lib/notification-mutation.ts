type NotificationRequest = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Pick<Response, "ok">>;

export async function performNotificationMutation(
  input: RequestInfo | URL,
  request: NotificationRequest = fetch,
): Promise<void> {
  const response = await request(input, { method: "POST" });
  if (!response.ok) {
    throw new Error("notification update failed");
  }
}
