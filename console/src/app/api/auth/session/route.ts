import { NextResponse } from "next/server";
import { cookies } from "next/headers";

export async function GET() {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get("authclaw_session")?.value;
    if (!sessionToken) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const payload = JSON.parse(sessionToken);
    return NextResponse.json(payload);
  } catch (error: unknown) {
    return NextResponse.json({ error: (error instanceof Error ? error.message : "Request failed") }, { status: 500 });
  }
}
