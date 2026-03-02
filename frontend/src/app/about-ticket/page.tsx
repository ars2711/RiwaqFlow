import BackButton from "@/app/back-button";
import {
  BadgeCheck,
  Lock,
  QrCode,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Wallet,
} from "lucide-react";

export default function AboutTicketPage() {
  return (
    <div className="app-shell p-6">
      <div className="max-w-3xl mx-auto space-y-5">
        <div className="glass-panel p-6 rounded-2xl">
          <BackButton href="/" label="Back" />
          <div className="mt-4 flex items-center gap-3">
            <div className="rounded-2xl p-3 bg-[var(--primary-soft)] border border-[var(--border)]">
              <ShieldCheck className="w-8 h-8 text-[var(--primary)]" />
            </div>
            <div>
              <h1 className="text-2xl font-black">About This Ticket</h1>
              <p className="section-subtitle text-sm mt-0.5">
                Riwaq secure digital access pass
              </p>
            </div>
          </div>
          <p className="section-subtitle mt-3">
            Every Riwaq ticket is a verified digital pass checked against
            server-side rules at the gate. Your QR code is dynamic — it
            refreshes every 30 seconds so screenshots cannot be reused.
          </p>
        </div>

        {/* Feature breakdown */}
        <div className="grid md:grid-cols-2 gap-4">
          <div className="glass-panel p-5 rounded-2xl flex gap-3">
            <QrCode className="w-6 h-6 text-[var(--primary)] shrink-0 mt-0.5" />
            <div>
              <h2 className="font-bold">Rotating QR token</h2>
              <p className="section-subtitle text-sm mt-1">
                Your QR code changes every 30 seconds. The token is signed
                server-side with HMAC-SHA256 and carries an expiry claim inside
                a short-lived JWT. Taking a screenshot will produce an expired,
                invalid code almost immediately.
              </p>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl flex gap-3">
            <Lock className="w-6 h-6 text-violet-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-bold">Device-locked pass</h2>
              <p className="section-subtitle text-sm mt-1">
                On first open, a browser fingerprint is recorded server-side.
                Subsequent opens on a different device will be flagged. This
                prevents ticket sharing after purchase.
              </p>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl flex gap-3">
            <BadgeCheck className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-bold">Entry / exit enforcement</h2>
              <p className="section-subtitle text-sm mt-1">
                Tickets track entry and exit counts server-side. Standard
                tickets allow up to 2 entries + 2 exits (re-entry policy). OC
                (organiser) tickets are exempt from entry limits. Revoked
                tickets are blocked at the gate.
              </p>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl flex gap-3">
            <RefreshCw className="w-6 h-6 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-bold">Offline support</h2>
              <p className="section-subtitle text-sm mt-1">
                Your ticket is cached in the browser&apos;s local storage on
                first load. If you go offline before the event, you can still
                display your cached ticket. The gate scanner also has an offline
                queue that syncs automatically when back online.
              </p>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl flex gap-3">
            <Wallet className="w-6 h-6 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-bold">Wallet passes</h2>
              <p className="section-subtitle text-sm mt-1">
                The ticket page includes Apple Wallet, Google Wallet, and
                Samsung Wallet action buttons. Production issuer signing (for
                real .pkpass / Google JWT) requires a paid provider credential
                setup — the API endpoints are in place.
              </p>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl flex gap-3">
            <Smartphone className="w-6 h-6 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-bold">Screen-awake mode</h2>
              <p className="section-subtitle text-sm mt-1">
                The ticket page can request a Wake Lock to prevent your screen
                from dimming while showing the QR at the gate. Tap the battery
                icon on your ticket page to enable it.
              </p>
            </div>
          </div>
        </div>

        {/* Organiser & verification */}
        <div className="glass-panel p-5 rounded-2xl grid md:grid-cols-2 gap-4 text-sm">
          <div>
            <h2 className="font-semibold mb-1">Organiser</h2>
            <p className="section-subtitle">Riwaq — NUST Events Platform</p>
            <p className="section-subtitle mt-0.5">
              Contact: support@Riwaq.pk
            </p>
          </div>
          <div>
            <h2 className="font-semibold mb-1">Verification</h2>
            <p className="section-subtitle">
              Dynamic QR updates every 30 seconds. Screenshots are expected to
              expire quickly. Gate validity is always confirmed server-side over
              HTTPS.
            </p>
          </div>
        </div>

        <p className="text-xs section-subtitle text-center">
          For support, contact the event organiser listed on your ticket. Ticket
          validity is always confirmed at gate scan regardless of on-screen
          status.
        </p>
      </div>
    </div>
  );
}
