import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { authenticateSessionCookie } from "@/lib/session-auth";

export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  const publicMarketingFiles = new Set([
    "/",
    "/product",
    "/pricing",
    "/security",
    "/company",
    "/demo",
    "/early-access",
    "/index.html",
    "/product.html",
    "/pricing.html",
    "/security.html",
    "/company.html",
    "/styles.css",
    "/app.js",
    "/robots.txt",
    "/sitemap.xml",
    "/opengraph-image",
  ]);

  // 1. Define public and asset paths
  const isPublicPath =
    publicMarketingFiles.has(path) ||
    path.startsWith("/opengraph-image") ||
    path.startsWith("/twitter-image") ||
    path === "/login" ||
    path === "/signup" ||
    path.startsWith("/trust/shared") ||
    path.startsWith("/trust-center") ||
    path.startsWith("/api/auth");
  const isAssetPath =
    path.startsWith("/_next") ||
    path.startsWith("/favicon.ico") ||
    path.startsWith("/api/"); // skip standard middleware for internal APIs (handled in routes)

  if (isAssetPath) {
    return NextResponse.next();
  }

  // 2. Extract session cookie
  const sessionCookie = request.cookies.get("authclaw_session")?.value;
  const session = authenticateSessionCookie(sessionCookie);
  const sessionRole = session?.role.toLowerCase() || "viewer";

  // 3. Handle redirects
  if (!session && !isPublicPath) {
    return new NextResponse("Unauthorized", { status: 401 });
  }

  if (session && path === "/login") {
    // Redirect authenticated user away from login to the demo onboarding flow
    return NextResponse.redirect(new URL("/connect", request.url));
  }

  if (session && path === "/signup") {
    return NextResponse.redirect(new URL("/connect", request.url));
  }

  const readOnlyRoles = new Set(["viewer", "developer", "operator"]);
  const readOnlyBlockedPaths = ["/connect", "/gateway", "/policies", "/aws", "/settings"];
  if (
    session &&
    readOnlyRoles.has(sessionRole) &&
    readOnlyBlockedPaths.some(
      (blockedPath) => path === blockedPath || path.startsWith(`${blockedPath}/`),
    )
  ) {
    return NextResponse.redirect(new URL("/overview", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};
