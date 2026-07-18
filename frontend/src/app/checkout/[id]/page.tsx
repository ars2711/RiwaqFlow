"use client";

import { useMemo, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import BackButton from "@/app/back-button";
import { API_BASE } from "@/lib/api";
import { CreditCard, ShieldCheck, CheckCircle2, XCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function CheckoutPage() {
  const params = useParams<{ id: string }>();
  const search = useSearchParams();
  const paymentId = params.id;
  const provider = search.get("provider") ?? "mock";
  const [status, setStatus] = useState<"idle" | "done" | "failed">("idle");

  const title = useMemo(
    () => `Mock ${provider.toUpperCase()} Checkout`,
    [provider],
  );

  const submit = async (nextStatus: "paid" | "failed") => {
    const res = await fetch(`${API_BASE}/payments/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        payment_id: paymentId,
        status: nextStatus,
        transaction_ref: `${provider.toUpperCase()}-${paymentId.slice(0, 8)}`,
      }),
    });
    if (!res.ok) {
      setStatus("failed");
      return;
    }
    setStatus("done");
  };

  return (
    <div className="app-shell flex items-center justify-center p-6 min-h-screen">
      <div className="max-w-md w-full relative z-10 space-y-4">
        <BackButton href="/admin" label="Back to Dashboard" />

        <div className="block-card p-8 space-y-6 border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow)] text-center">
          {/* Header */}
          <div className="flex flex-col items-center space-y-3">
            <div className="w-12 h-12 bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center mb-2">
              <CreditCard className="w-6 h-6 text-[var(--verified)]" />
            </div>
            <h1 className="text-2xl font-display font-medium text-[var(--text)]">
              {title}
            </h1>
            <p className="text-xs text-[var(--muted)] font-mono uppercase tracking-wider">
              Local Checkout Simulator &middot; Webhook Test
            </p>
          </div>

          {/* Secure strip */}
          <div className="flex items-center justify-center gap-2 text-xs font-mono text-[var(--verified)] bg-[var(--verified)]/10 py-2 border border-[var(--verified)]/20">
            <ShieldCheck className="w-4 h-4" />
            <span>TEST ENVIRONMENT SECURED</span>
          </div>

          <div className="space-y-3 pt-2">
            <button
              className="w-full flex items-center justify-center gap-2 py-4 border border-[var(--verified)]/30 bg-[var(--verified)]/10 text-[var(--verified)] font-mono text-sm hover:bg-[var(--verified)]/20 transition-all cursor-pointer"
              onClick={() => void submit("paid")}
            >
              <CheckCircle2 className="w-5 h-5" />
              SIMULATE SUCCESS
            </button>
            <button
              className="w-full flex items-center justify-center gap-2 py-4 border border-[var(--alert)]/30 bg-[var(--alert)]/10 text-[var(--alert)] font-mono text-sm hover:bg-[var(--alert)]/20 transition-all cursor-pointer"
              onClick={() => void submit("failed")}
            >
              <XCircle className="w-5 h-5" />
              SIMULATE FAILURE
            </button>
          </div>

          {/* Status Feedback */}
          <div className="h-10 flex items-center justify-center">
            <AnimatePresence mode="wait">
              {status === "done" && (
                <motion.p
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -5 }}
                  className="text-xs text-[var(--verified)] font-mono uppercase tracking-wider flex items-center gap-2"
                >
                  <CheckCircle2 className="w-4 h-4" /> Webhook sent successfully!
                </motion.p>
              )}
              {status === "failed" && (
                <motion.p
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -5 }}
                  className="text-xs text-[var(--alert)] font-mono uppercase tracking-wider flex items-center gap-2"
                >
                  <XCircle className="w-4 h-4" /> Update failed (Server Error)
                </motion.p>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
