import type { ReactNode } from "react";

export function LegalNotice({
  title,
  summary,
  version,
  children,
}: {
  title: string;
  summary: string;
  version: string;
  children: ReactNode;
}) {
  return (
    <main className="legal-notice">
      <section className="pagehead">
        <div className="wrap">
          <span className="eyebrow">Controlled-beta legal notice</span>
          <h1>{title}</h1>
          <p className="sub">{summary}</p>
          <dl className="legal-meta" aria-label="Notice version">
            <div>
              <dt>Version</dt>
              <dd>{version}</dd>
            </div>
            <div>
              <dt>Effective date</dt>
              <dd>20 July 2026</dd>
            </div>
          </dl>
        </div>
      </section>
      <article className="wrap legal-body">{children}</article>
    </main>
  );
}
