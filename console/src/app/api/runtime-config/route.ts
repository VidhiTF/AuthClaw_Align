import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

function publicUrl(name: "PUBLIC_API_URL" | "PUBLIC_GATEWAY_URL", fallback: string) {
  const value = process.env[name] || fallback;
  if (process.env.AUTHCLAW_ENV === "production" && !value.startsWith("https://")) {
    throw new Error(`${name} must use https:// in production`);
  }
  return value.replace(/\/$/, "");
}

export async function GET() {
  return NextResponse.json(
    {
      api_url: publicUrl("PUBLIC_API_URL", process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1"),
      gateway_url: publicUrl("PUBLIC_GATEWAY_URL", process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:18080"),
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
