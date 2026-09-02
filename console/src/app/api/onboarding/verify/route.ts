import { NextResponse } from "next/server";
import { sessionCookieOptions } from "@/lib/cookie-options";

const BACKEND_URL = process.env.API_URL || "http://localhost:8000";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const response = await fetch(`${BACKEND_URL}/v1/onboarding/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status });
    }

    const nextResponse = NextResponse.json(data);
    nextResponse.cookies.set("authclaw_session", data.session_token, {
      ...sessionCookieOptions(60 * 60 * 24),
    });
    return nextResponse;
  } catch (error: unknown) {
    console.error("Onboarding verification failed:", error);
    return NextResponse.json({ detail: "Authentication failed" }, { status: 500 });
  }
}
