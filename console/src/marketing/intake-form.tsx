"use client";

import type { FormEvent } from "react";
import { useRef, useState } from "react";
import { jsonRequest, responseJsonOr } from "@/lib/client-fetch";

type IntakeFormProps = {
  requestedAccess: "DEMO" | "EARLY_ACCESS";
  sourcePage: "/demo" | "/early-access";
  title: string;
  description: string;
};

type AccessRequestResponse = {
  reference: string;
  status: "PENDING";
  created_at: string;
};

const errors = {
  validation: "Please check the form and try again.",
  rateLimit: "Too many requests. Please try again later.",
  generic: "We could not submit your request. Please try again later.",
} as const;

export function IntakeForm({
  requestedAccess,
  sourcePage,
  title,
  description,
}: IntakeFormProps) {
  const [consent, setConsent] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [reference, setReference] = useState("");
  const errorRef = useRef<HTMLDivElement>(null);
  const successRef = useRef<HTMLHeadingElement>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!consent) return;

    setSubmitting(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch(
        "/api/access-requests",
        jsonRequest("POST", {
          name: form.get("name"),
          business_email: form.get("business_email"),
          company: form.get("company"),
          role: form.get("role"),
          use_case: form.get("use_case"),
          requested_access: requestedAccess,
          consent: true,
          source_page: sourcePage,
        })
      );
      const body = await responseJsonOr<AccessRequestResponse | Record<string, never>>(
        response,
        {}
      );
      if (!response.ok) {
        setError(
          response.status === 422
            ? errors.validation
            : response.status === 429
              ? errors.rateLimit
              : errors.generic
        );
        return;
      }
      setReference((body as AccessRequestResponse).reference);
    } catch {
      setError(errors.generic);
    } finally {
      setSubmitting(false);
      requestAnimationFrame(() => {
        (successRef.current || errorRef.current)?.focus();
      });
    }
  }

  if (reference) {
    return (
      <section className="intake-card intake-success" aria-labelledby="intake-success-title">
        <div>
          <span className="eyebrow">Request received</span>
          <h1 ref={successRef} id="intake-success-title" tabIndex={-1}>
            Thank you
          </h1>
          <p>We received your request and will follow up using your business email.</p>
          <p className="intake-reference">Reference: {reference}</p>
        </div>
      </section>
    );
  }

  return (
    <section className="intake-card" aria-labelledby="intake-title">
      <span className="eyebrow">{requestedAccess === "DEMO" ? "Product demo" : "Controlled access"}</span>
      <h1 id="intake-title">{title}</h1>
      <p className="intake-description">{description}</p>
      <form onSubmit={submit}>
        <div className="intake-grid">
          <label>
            Name
            <input name="name" autoComplete="name" maxLength={255} required />
          </label>
          <label>
            Business email
            <input
              name="business_email"
              type="email"
              autoComplete="email"
              maxLength={320}
              required
            />
          </label>
          <label>
            Company
            <input name="company" autoComplete="organization" maxLength={255} required />
          </label>
          <label>
            Role
            <input name="role" autoComplete="organization-title" maxLength={100} required />
          </label>
        </div>
        <label>
          Use case
          <textarea name="use_case" rows={5} maxLength={4000} required />
        </label>
        <label>
          Requested access
          <input
            value={requestedAccess === "DEMO" ? "Product demo" : "Early access"}
            readOnly
            aria-readonly="true"
          />
        </label>
        <div className="privacy-notice">
          <p>
            AuthClaw will use the information provided only to evaluate and respond to
            this request.
          </p>
          <label className="consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
              required
            />
            I consent to AuthClaw processing this information for this request.
          </label>
        </div>
        {error && (
          <div ref={errorRef} className="intake-error" role="alert" tabIndex={-1}>
            {error}
          </div>
        )}
        <button className="btn btn-primary" type="submit" disabled={!consent || submitting}>
          {submitting ? "Submitting…" : "Submit request"}
        </button>
      </form>
    </section>
  );
}
