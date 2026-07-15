import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { authenticateSessionCookie } from "@/lib/session-auth";

export async function GET() {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get("authclaw_session")?.value;
    if (!sessionToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const payload = JSON.parse(sessionToken);
    const session = authenticateSessionCookie(sessionToken);
    if (!session) {
      const response = NextResponse.json({ error: "Unauthorized: Session expired or invalid" }, { status: 401 });
      response.cookies.delete("authclaw_session");
      return response;
    }
    return NextResponse.json({
      ...payload,
      userId: session.userId,
      tenantId: session.tenantId,
      scopes: session.scopes,
      role: session.role,
    });
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}
