import Link from "next/link";
import { ClipboardCheck, PlusCircle, ShieldCheck } from "lucide-react";

export default function DeveloperHomePage() {
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div>
        <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#6D28D9]">
          <ShieldCheck className="h-4 w-4" />
          AuthClaw developers only
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-[#0E1726]">Developer Console</h1>
        <p className="mt-2 max-w-3xl text-sm text-[#475069]">
          Platform operations for intake review, tenant provisioning, and AuthClaw activity oversight.
        </p>
      </div>

      <section className="grid gap-4 md:grid-cols-2">
        <Link
          href="/developer/access-requests"
          className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-[0_1px_2px_rgba(11,31,63,.05)] transition hover:border-[#A78BFA]"
        >
          <ClipboardCheck className="h-5 w-5 text-[#6D28D9]" />
          <h2 className="mt-4 text-lg font-bold text-[#0E1726]">Access Requests</h2>
          <p className="mt-2 text-sm leading-6 text-[#475069]">Review demo and early-access submissions.</p>
        </Link>
        <Link
          href="/developer/tenants"
          className="rounded-[20px] border border-[#E6E9F0] bg-white p-6 shadow-[0_1px_2px_rgba(11,31,63,.05)] transition hover:border-[#A78BFA]"
        >
          <PlusCircle className="h-5 w-5 text-[#0F766E]" />
          <h2 className="mt-4 text-lg font-bold text-[#0E1726]">New Tenant</h2>
          <p className="mt-2 text-sm leading-6 text-[#475069]">Create approved customer tenants.</p>
        </Link>
      </section>
    </div>
  );
}
