import type { Metadata } from "next";
import { marketingSiteUrl } from "@/marketing/config";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: marketingSiteUrl,
  title: "AuthClaw",
  description: "AI governance and compliance console",
  icons: { icon: "/favicon.ico" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
