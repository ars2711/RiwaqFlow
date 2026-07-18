import BackButton from "@/app/back-button";
import { ShieldCheck } from "lucide-react";

export default function PrivacyPolicyPage() {
  return (
    <div className="app-shell p-6">
      <div className="max-w-3xl mx-auto space-y-4">
        <div className="block-card p-6 border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)]">
          <BackButton href="/" label="Back" />

          <div className="mt-4 flex items-center gap-3 mb-4">
            <div className="p-3 bg-[var(--surface-2)] border border-[var(--border)]">
              <ShieldCheck className="w-7 h-7 text-[var(--verified)]" />
            </div>
            <div>
              <h1 className="text-2xl font-display font-medium text-[var(--text)]">
                Privacy Policy
              </h1>
              <p className="text-xs text-[var(--muted)] font-mono uppercase tracking-wider mt-0.5">
                Riwaq — NUST Events Platform
              </p>
            </div>
          </div>

          <p className="section-subtitle text-sm">
            We store ticket details, scan history, and anti-fraud metadata only
            to operate event validation and safety for NUST societies and
            departments.
          </p>
        </div>

        <div className="block-card p-6 border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)] space-y-4">
          <ul className="space-y-3">
            {[
              {
                label: "Collected data",
                detail:
                  "Holder name, role/department, ticket status, scan timestamps.",
              },
              {
                label: "Anti-fraud",
                detail:
                  "Device fingerprint and short-lived QR token validation. Screenshots expire within 30 seconds.",
              },
              {
                label: "Access control",
                detail: "Only authorized event admins and gate staff.",
              },
              {
                label: "Retention",
                detail:
                  "Logs retained only as needed for event operations and then purged.",
              },
            ].map(({ label, detail }) => (
              <li
                key={label}
                className="border border-[var(--border)] bg-[var(--surface-2)] p-4 flex gap-3"
              >
                <div className="w-1.5 bg-[var(--verified)] shrink-0 mt-1" />
                <div>
                  <p className="text-xs font-mono uppercase tracking-widest text-[var(--muted)] mb-1">
                    {label}
                  </p>
                  <p className="text-sm text-[var(--text)]">{detail}</p>
                </div>
              </li>
            ))}
          </ul>

          <p className="text-xs text-[var(--muted)] font-mono border-t border-[var(--border)] pt-4">
            Contact{" "}
            <a
              href="mailto:privacy@riwaq.pk"
              className="text-[var(--verified)] underline underline-offset-2"
            >
              privacy@Riwaq.pk
            </a>{" "}
            for data requests or removal enquiries.
          </p>
        </div>
      </div>
    </div>
  );
}
