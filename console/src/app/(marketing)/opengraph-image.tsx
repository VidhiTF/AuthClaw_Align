import { ImageResponse } from "next/og";

export const alt = "AuthClaw — The runtime layer for AI compliance";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          alignItems: "center",
          background: "linear-gradient(135deg, #08152b, #12294b 62%, #6d28d9)",
          color: "white",
          display: "flex",
          height: "100%",
          justifyContent: "center",
          width: "100%",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", width: 960 }}>
          <div style={{ color: "#e9a93c", fontSize: 28, letterSpacing: 4 }}>
            AUTHCLAW
          </div>
          <div style={{ fontSize: 72, fontWeight: 700, marginTop: 28 }}>
            The runtime layer for AI compliance
          </div>
          <div style={{ color: "#d7e0f2", fontSize: 30, marginTop: 28 }}>
            In-line enforcement, human-approved remediation, and
            tamper-evident audit records.
          </div>
        </div>
      </div>
    ),
    size
  );
}
