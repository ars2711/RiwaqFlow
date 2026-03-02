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
      {/* Ambience */}
      <div className="absolute top-[20%] left-[30%] w-72 h-72 bg-blue-500/10 rounded-full blur-[100px] pointer-events-none" />

      <div className="max-w-md w-full relative z-10">
        <div className="mb-6 ml-2">
          <BackButton href="/admin" label="Back to Dashboard" />
        </div>

        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.3 }}
          className="glass-panel p-8 space-y-8 rounded-3xl border border-[var(--border)] shadow-2xl relative overflow-hidden"
        >
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="flex flex-col items-center text-center space-y-3"
          >
            <motion.div
              whileHover={{ scale: 1.1, rotate: 5 }}
              whileTap={{ scale: 0.95 }}
              className="w-16 h-16 rounded-full bg-[var(--primary)]/10 flex items-center justify-center mb-2 ring-1 ring-[var(--primary)]/30 cursor-pointer"
            >
              <CreditCard className="w-8 h-8 text-[var(--primary)]" />
            </motion.div>
            <h1 className="text-2xl font-black bg-clip-text text-transparent bg-gradient-to-r from-[var(--primary)] to-cyan-500">
              {title}
            </h1>
            <p className="text-sm text-[var(--fg-muted)] leading-relaxed">
              This local checkout simulator triggers payment webhook lifecycle
              updates for testing.
            </p>
          </motion.div>

          {/* Secure strip */}
          <div className="flex items-center justify-center gap-2 text-xs font-semibold text-[var(--primary)]/80 bg-[var(--primary)]/5 py-2 rounded-lg">
            <ShieldCheck className="w-4 h-4" />
            <span>Test Environment Secured</span>
          </div>

          <div className="space-y-3 pt-4">
            <button
              className="w-full flex items-center justify-center gap-2 py-4 rounded-xl font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/20 active:scale-[0.98] transition-all border border-emerald-500/20"
              onClick={() => void submit("paid")}
            >
              <CheckCircle2 className="w-5 h-5" />
              Simulate Success
            </button>
            <button
              className="w-full flex items-center justify-center gap-2 py-4 rounded-xl font-bold bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 active:scale-[0.98] transition-all border border-rose-500/20"
              onClick={() => void submit("failed")}
            >
              <XCircle className="w-5 h-5" />
              Simulate Failure
            </button>
          </div>

          {/* Status Feedback */}
          <div className="h-10 flex items-center justify-center">
            <AnimatePresence mode="wait">
              {status === "done" && (
                <motion.p
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="text-sm text-emerald-500 font-semibold flex items-center gap-2"
                >
                  <CheckCircle2 className="w-4 h-4" /> Webhook sent
                  successfully!
                </motion.p>
              )}
              {status === "failed" && (
                <motion.p
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="text-sm text-rose-500 font-semibold flex items-center gap-2"
                >
                  <XCircle className="w-4 h-4" /> Update failed (Server Error)
                </motion.p>
              )}
            </AnimatePresence>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
