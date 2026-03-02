"use client";

import { useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  Maximize2,
  Printer,
  ShieldCheck,
  Sun,
  Zap,
  CheckCircle2,
  Clock,
  XCircle,
  MapPin,
  User,
  Hash,
  Tag,
  UserCheck,
  BookOpen,
  LogIn,
  LogOut,
  Lock,
  RefreshCw,
  Wifi,
  WifiOff,
  Fingerprint,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import BackButton from "@/app/back-button";
import {
  UniversalWalletGroup,
  WalletPassData,
} from "@/components/wallet/WalletButtons";

// ── Mock data ──────────────────────────────────────────────────────────────────
const MOCK_STATUSES = ["valid", "used", "revoked"] as const;
type Status = (typeof MOCK_STATUSES)[number];

const MOCK = {
  event: {
    name: "TechFest '26",
    venue: "NUST Sports Complex, H-12",
    starts_at: "2026-03-15T14:00:00",
    society_name: "IEEE NUST",
    organizer_name: "IEEE Student Branch",
    logo_url: null as null | string,
  },
  ticket: {
    id: "tf26-0a1b2c3d4e5f",
    holder_name: "Arsal Ahmed",
    ticket_type: "General",
    seat: "G-47",
    role: "Attendee",
    department: "CS",
    year: "3rd",
    attendee_type: "Student",
    interests: "AI, Robotics, Web Dev",
    entry_count: 1,
    exit_count: 0,
    signature: "sha256:7f3c9b1a…",
    status: "valid" as Status,
  },
};

// Static print token — generated once, never rotates
const PRINT_TOKEN = `RF_PRINT_STATIC_${MOCK.ticket.id.toUpperCase()}`;

const RING_R = 20;
const RING_C = 2 * Math.PI * RING_R;

const statusConfig = {
  valid: {
    gradient: "from-emerald-500 via-emerald-600 to-teal-700",
    badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    icon: <CheckCircle2 className="w-4 h-4" />,
    label: "VALID",
    glow: "rgba(16,185,129,0.35)",
  },
  used: {
    gradient: "from-amber-500 via-amber-600 to-orange-700",
    badge: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    icon: <Clock className="w-4 h-4" />,
    label: "USED",
    glow: "rgba(245,158,11,0.30)",
  },
  revoked: {
    gradient: "from-red-600 via-red-700 to-rose-900",
    badge: "bg-red-500/15 text-red-400 border-red-500/30",
    icon: <XCircle className="w-4 h-4" />,
    label: "REVOKED",
    glow: "rgba(239,68,68,0.35)",
  },
};

// ── Decorative 1D barcode ──────────────────────────────────────────────────────
function Barcode({ value }: { value: string }) {
  const bars = Array.from({ length: 52 }, (_, i) => {
    const code = value.charCodeAt(i % value.length);
    return ((code * (i + 7) * 13) % 3) + 1;
  });
  return (
    <div className="flex items-stretch h-8 gap-[1px] opacity-60">
      {bars.map((w, i) => (
        <div
          key={i}
          className="bg-current rounded-[0.5px]"
          style={{ width: w * 1.6, minWidth: 1.5 }}
        />
      ))}
    </div>
  );
}

// ── Hole punch marks for "used" state ─────────────────────────────────────────
function HolePunches({ show }: { show: boolean }) {
  const positions = [22, 50, 78]; // % from top
  return (
    <AnimatePresence>
      {show &&
        positions.map((top, i) => (
          <motion.div
            key={top}
            className="absolute z-30 pointer-events-none"
            style={{ top: `${top}%`, left: -14, transform: "translateY(-50%)" }}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{
              type: "spring",
              stiffness: 700,
              damping: 18,
              delay: i * 0.09 + 0.05,
            }}
          >
            {/* Outer ring */}
            <div className="w-7 h-7 rounded-full bg-[var(--bg)] border-2 border-amber-400/50 shadow-[0_2px_8px_rgba(0,0,0,0.6)] flex items-center justify-center">
              {/* Inner punch shadow */}
              <div className="w-4 h-4 rounded-full bg-[var(--bg)] shadow-[inset_0_1px_5px_rgba(0,0,0,0.9),inset_0_0_2px_rgba(0,0,0,0.6)]" />
            </div>
            {/* Shadow cast on ticket face */}
            <div className="absolute left-full top-1/2 -translate-y-1/2 w-4 h-7 rounded-r-full bg-black/15" />
          </motion.div>
        ))}
    </AnimatePresence>
  );
}

// ── Tear overlay for "revoked" state ──────────────────────────────────────────
function TearOverlay({ show }: { show: boolean }) {
  return (
    <AnimatePresence>
      {show && (
        <>
          {/* Jagged tear seam */}
          <motion.div
            key="tear-seam"
            className="absolute left-0 right-0 z-30 pointer-events-none"
            style={{ top: "47%" }}
            initial={{ opacity: 0, scaleX: 0 }}
            animate={{ opacity: 1, scaleX: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.22, ease: "easeOut" }}
          >
            <svg viewBox="0 0 400 32" className="w-full h-8 drop-shadow-2xl">
              <defs>
                <linearGradient id="tg" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="rgba(255,255,255,0)" />
                  <stop offset="8%" stopColor="rgba(255,255,255,0.7)" />
                  <stop offset="92%" stopColor="rgba(255,255,255,0.7)" />
                  <stop offset="100%" stopColor="rgba(255,255,255,0)" />
                </linearGradient>
              </defs>
              {/* Shadow fill below tear */}
              <path
                d="M0,16 L14,7 L28,22 L44,5 L60,19 L76,4 L93,18 L110,6 L126,20 L143,5 L159,19 L176,4 L193,17 L210,5 L226,20 L243,6 L259,18 L276,4 L292,19 L309,5 L325,20 L342,6 L358,19 L375,5 L400,14 L400,32 L0,32 Z"
                fill="rgba(0,0,0,0.3)"
              />
              {/* Torn edge highlight line */}
              <path
                d="M0,16 L14,7 L28,22 L44,5 L60,19 L76,4 L93,18 L110,6 L126,20 L143,5 L159,19 L176,4 L193,17 L210,5 L226,20 L243,6 L259,18 L276,4 L292,19 L309,5 L325,20 L342,6 L358,19 L375,5 L400,14"
                fill="none"
                stroke="url(#tg)"
                strokeWidth="1.5"
              />
            </svg>
          </motion.div>

          {/* VOID diagonal stamp */}
          <motion.div
            key="void-stamp"
            className="absolute inset-0 z-25 pointer-events-none flex items-center justify-center"
            initial={{ scale: 2.8, opacity: 0, rotate: -35 }}
            animate={{ scale: 1, opacity: 1, rotate: -14 }}
            exit={{ scale: 0.5, opacity: 0 }}
            transition={{
              type: "spring",
              stiffness: 220,
              damping: 18,
              delay: 0.12,
            }}
          >
            <div
              className="border-[3px] border-red-500/75 rounded-lg px-7 py-2.5"
              style={{
                boxShadow:
                  "0 0 24px rgba(239,68,68,0.45), inset 0 0 8px rgba(239,68,68,0.1)",
              }}
            >
              <span
                className="text-[2.6rem] font-black tracking-[0.35em] text-red-500/85 uppercase select-none"
                style={{ textShadow: "0 0 16px rgba(239,68,68,0.55)" }}
              >
                VOID
              </span>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

// ── "ISSUED" stamp for valid state ────────────────────────────────────────────
function IssuedStamp({ show }: { show: boolean }) {
  return (
    <AnimatePresence>
      {show && (
        <motion.div
          className="absolute inset-0 z-25 pointer-events-none flex items-center justify-center"
          initial={{ scale: 3, opacity: 0, rotate: 22 }}
          animate={{ scale: 1, opacity: 1, rotate: -8 }}
          exit={{ scale: 0.5, opacity: 0 }}
          transition={{ type: "spring", stiffness: 280, damping: 18 }}
        >
          <div
            className="flex flex-col items-center justify-center rounded-full w-36 h-36 border-[3.5px] border-emerald-400/65 gap-0.5"
            style={{
              boxShadow:
                "0 0 32px rgba(16,185,129,0.45), inset 0 0 10px rgba(16,185,129,0.1)",
              background: "rgba(16,185,129,0.07)",
            }}
          >
            <CheckCircle2 className="w-9 h-9 text-emerald-400/85" />
            <span className="text-[10px] font-black tracking-[0.22em] text-emerald-400/80 uppercase">
              Issued
            </span>
            <span className="text-[7.5px] font-semibold text-emerald-400/45 tracking-widest">
              Riwaq
            </span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// ── Perforation row ────────────────────────────────────────────────────────────
function Perforation() {
  return (
    <div className="relative flex items-center bg-[var(--surface-strong)] z-10">
      <div className="absolute -left-4 h-8 w-8 rounded-full bg-[var(--bg)]" />
      <div className="absolute -right-4 h-8 w-8 rounded-full bg-[var(--bg)]" />
      <div className="mx-6 w-full border-t-2 border-dashed border-[var(--border)]" />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
export default function TicketPreviewPage() {
  const [status, setStatus] = useState<Status>("valid");
  const [timeLeft, setTimeLeft] = useState(30);
  const [qrToken, setQrToken] = useState("Riwaq_DEMO_PREVIEW");
  const [fullQr, setFullQr] = useState(false);
  const [bright, setBright] = useState(false);
  const [showStamp, setShowStamp] = useState(false);
  const stampTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Real TOTP-window QR rotation ──────────────────────────────────────────
  useEffect(() => {
    const sync = () => {
      const now = Date.now();
      const win = Math.floor(now / 30000);
      const secondInWin = Math.floor(now / 1000) % 30;
      setTimeLeft(30 - secondInWin);
      setQrToken(`RF_DEMO_${win.toString(36).toUpperCase()}`);
    };
    sync();
    const iv = setInterval(sync, 1000);
    return () => clearInterval(iv);
  }, []);

  const handleStatusChange = (next: Status) => {
    if (next === status) return;
    setStatus(next);
    if (next === "valid") {
      if (stampTimerRef.current) clearTimeout(stampTimerRef.current);
      setShowStamp(true);
      stampTimerRef.current = setTimeout(() => setShowStamp(false), 2300);
    } else {
      setShowStamp(false);
    }
  };

  const sc = statusConfig[status];
  const timerOffset = RING_C - (timeLeft / 30) * RING_C;
  const maxEntries = 2;
  const entryPct = Math.min((MOCK.ticket.entry_count / maxEntries) * 100, 100);
  const isRevoked = status === "revoked";
  const isUsed = status === "used";

  return (
    <>
      {/* ── Print-only layout (hidden on screen, shown when printing) ── */}
      <div className="hidden print:flex fixed inset-0 bg-white z-50 flex-col items-center justify-center gap-6 p-10 text-black">
        <div className="text-center">
          <p className="text-xs font-bold tracking-widest uppercase text-gray-400 mb-1">
            {MOCK.event.society_name}
          </p>
          <h1 className="text-3xl font-black">{MOCK.event.name}</h1>
          <p className="text-sm text-gray-500 mt-1">{MOCK.event.venue}</p>
        </div>
        <div className="border-4 border-black p-4 rounded-2xl shadow-2xl">
          <QRCodeSVG value={PRINT_TOKEN} size={220} level="H" />
        </div>
        <div className="text-center space-y-1">
          <p className="font-bold text-xl">{MOCK.ticket.holder_name}</p>
          <p className="text-sm text-gray-600">
            {MOCK.ticket.ticket_type} &middot; Seat {MOCK.ticket.seat} &middot;{" "}
            {MOCK.ticket.role}
          </p>
          <p className="font-mono text-xs text-gray-400 mt-2">
            #{MOCK.ticket.id.toUpperCase()}
          </p>
        </div>
        <div className="border border-amber-300 bg-amber-50 text-amber-800 rounded-xl px-5 py-3 text-xs max-w-sm text-center leading-relaxed">
          <strong>Printed backup ticket.</strong> This static QR can be used
          once only. Your e-ticket QR rotates every 30 s for stronger security.
          Both share the same entry counter — only one way in.
        </div>
      </div>

      {/* ── Main screen layout ─────────────────────────────────────────────── */}
      <div
        className={`app-shell print:hidden flex flex-col items-center px-4 py-6 sm:py-10 relative overflow-hidden min-h-screen transition-[filter] duration-300 ${bright ? "[filter:brightness(1.28)]" : ""}`}
      >
        {/* Ambient glow orbs that change colour with status */}
        <motion.div
          className="pulse-orb h-72 w-72 -left-12 top-10 pointer-events-none"
          animate={{ background: sc.glow }}
          transition={{ duration: 0.9 }}
        />
        <motion.div
          className="pulse-orb h-56 w-56 -right-10 bottom-32 pointer-events-none"
          animate={{ background: sc.glow }}
          transition={{ duration: 0.9, delay: 0.15 }}
        />

        {/* Back */}
        <div className="w-full portrait:max-w-sm landscape:max-w-3xl mb-3">
          <BackButton href="/" label="Back" />
        </div>

        {/* Demo notice banner */}
        <div className="w-full portrait:max-w-sm landscape:max-w-3xl mb-4 rounded-2xl border border-[var(--primary)]/30 bg-[var(--primary-soft)] px-4 py-3 text-sm text-[var(--primary)]">
          <p className="font-bold flex items-center gap-2">
            <Zap className="w-4 h-4" />
            Design preview
          </p>
          <p className="opacity-75 text-xs mt-0.5">
            Real tickets at{" "}
            <code className="font-mono bg-black/10 px-1 rounded">
              /ticket/[id]
            </code>
          </p>
          <div className="flex gap-2 mt-2.5">
            {MOCK_STATUSES.map((s) => (
              <button
                key={s}
                onClick={() => handleStatusChange(s)}
                className={`flex-1 rounded-lg py-1.5 text-xs font-bold capitalize border transition-all duration-200 ${
                  status === s
                    ? "bg-[var(--primary)] text-white border-[var(--primary)] shadow-md"
                    : "border-[var(--border)] section-subtitle hover:border-[var(--primary)]/50"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* ── TICKET CARD ─────────────────────────────────────────────────── */}
        <motion.div
          className="w-full portrait:max-w-sm landscape:max-w-3xl rounded-3xl overflow-visible shadow-2xl border border-white/10 relative bg-[var(--surface-strong)]"
          style={{
            boxShadow: `0 28px 90px ${sc.glow}, 0 4px 24px rgba(0,0,0,0.45)`,
          }}
          animate={
            isRevoked ? { rotate: [0, -1.5, 1.5, -1, 0.5, 0] } : { rotate: 0 }
          }
          transition={{ duration: 0.55, times: [0, 0.15, 0.4, 0.65, 0.85, 1] }}
        >
          {/* Watermark behind everything */}
          <div className="pointer-events-none select-none absolute inset-0 flex items-center justify-center overflow-hidden z-0 rounded-3xl">
            <span className="text-[5.5rem] font-black tracking-widest opacity-[0.025] -rotate-[20deg] whitespace-nowrap">
              Riwaq
            </span>
          </div>

          {/* ── Overlaid animations ── */}
          <div className="absolute inset-0 z-20 pointer-events-none rounded-3xl overflow-visible">
            <HolePunches show={isUsed} />
            <TearOverlay show={isRevoked} />
            <IssuedStamp show={showStamp} />
          </div>

          {/* ── Orientation-aware inner flex container ── */}
          <div className="flex portrait:flex-col landscape:flex-row">
            {/* ══ LEFT COL (or full-width portrait) ══════════════════════════ */}
            <div className="portrait:w-full landscape:flex-1 landscape:min-w-0 flex flex-col">
              {/* ── Header gradient band ── */}
              <motion.div
                className={`relative bg-gradient-to-br ${sc.gradient} p-6 text-white overflow-hidden portrait:rounded-t-3xl landscape:rounded-tl-3xl`}
                layout
              >
                {/* Radial highlight */}
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_15%_25%,rgba(255,255,255,0.22),transparent_55%)] pointer-events-none" />
                {/* Micro-grid pattern */}
                <div
                  className="absolute inset-0 pointer-events-none opacity-[0.06]"
                  style={{
                    background:
                      "repeating-linear-gradient(0deg,rgba(255,255,255,0.5) 0,rgba(255,255,255,0.5) 1px,transparent 1px,transparent 24px),repeating-linear-gradient(90deg,rgba(255,255,255,0.5) 0,rgba(255,255,255,0.5) 1px,transparent 1px,transparent 24px)",
                  }}
                />

                <div className="relative z-10 flex items-start justify-between mb-4">
                  <div className="h-11 w-11 rounded-2xl bg-white/20 border-2 border-white/35 flex items-center justify-center shadow-inner">
                    <Zap className="w-6 h-6 text-white" />
                  </div>
                  <motion.span
                    key={status}
                    initial={{ scale: 0.75, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ type: "spring", stiffness: 320, damping: 20 }}
                    className={`inline-flex items-center gap-1.5 text-xs font-bold px-3 py-1.5 rounded-full border backdrop-blur-sm ${sc.badge}`}
                  >
                    {sc.icon}
                    {sc.label}
                  </motion.span>
                </div>

                <div className="relative z-10">
                  <p className="text-xs font-semibold uppercase tracking-widest text-white/70 mb-1">
                    {MOCK.event.society_name}
                  </p>
                  <h1 className="text-2xl font-black leading-tight tracking-tight">
                    {MOCK.event.name}
                  </h1>
                  <div className="mt-2 flex flex-wrap gap-3 text-sm text-white/80">
                    <span className="flex items-center gap-1">
                      <MapPin className="w-3.5 h-3.5" />
                      {MOCK.event.venue}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      {new Date(MOCK.event.starts_at).toLocaleString("en-PK", {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                  </div>
                </div>
              </motion.div>

              <Perforation />

              {/* ── Holder info grid ── */}
              <div className="px-6 pt-4 pb-5 grid grid-cols-2 gap-x-4 gap-y-3 text-sm relative z-10">
                {[
                  {
                    icon: <User className="w-3.5 h-3.5" />,
                    label: "Holder",
                    value: MOCK.ticket.holder_name,
                  },
                  {
                    icon: <Tag className="w-3.5 h-3.5" />,
                    label: "Type",
                    value: MOCK.ticket.ticket_type,
                  },
                  {
                    icon: <Hash className="w-3.5 h-3.5" />,
                    label: "Seat",
                    value: MOCK.ticket.seat,
                  },
                  {
                    icon: <UserCheck className="w-3.5 h-3.5" />,
                    label: "Role",
                    value: MOCK.ticket.role,
                  },
                  {
                    icon: <BookOpen className="w-3.5 h-3.5" />,
                    label: "Dept",
                    value: MOCK.ticket.department,
                  },
                  {
                    icon: <BookOpen className="w-3.5 h-3.5" />,
                    label: "Year",
                    value: MOCK.ticket.year,
                  },
                ].map(({ icon, label, value }) => (
                  <div key={label}>
                    <p className="flex items-center gap-1 text-[10px] uppercase tracking-wider section-subtitle font-bold mb-0.5">
                      {icon}
                      {label}
                    </p>
                    <p className="font-semibold truncate">{value}</p>
                  </div>
                ))}
                <div className="col-span-2">
                  <p className="text-[10px] uppercase tracking-wider section-subtitle font-bold mb-1">
                    Interests
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {MOCK.ticket.interests.split(",").map((t) => (
                      <span key={t} className="chip text-xs px-2 py-0.5">
                        {t.trim()}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* ── LANDSCAPE-only: counters + barcode in left col ── */}
              {/* Spacer pushes counters to bottom in landscape */}
              <div className="portrait:hidden landscape:flex-1" />
              <div className="portrait:hidden landscape:flex landscape:flex-col">
                <div className="px-6 py-4 border-t border-[var(--border)] grid grid-cols-2 gap-4 relative z-10 bg-[var(--surface-strong)]">
                  <div>
                    <div className="flex items-center gap-1.5 mb-1 text-xs section-subtitle font-bold uppercase tracking-wider">
                      <LogIn className="w-3.5 h-3.5 text-[var(--primary)]" />
                      Entries
                    </div>
                    <span className="text-2xl font-black">
                      {MOCK.ticket.entry_count}
                      <span className="text-sm font-normal opacity-60">
                        /{maxEntries}
                      </span>
                    </span>
                    <div className="mt-1.5 h-1.5 rounded-full bg-[var(--border)] overflow-hidden">
                      <div
                        style={{ width: `${entryPct}%` }}
                        className={`h-full rounded-full transition-all duration-500 ${
                          entryPct >= 100
                            ? "bg-amber-400"
                            : "bg-[var(--primary)]"
                        }`}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center gap-1.5 mb-1 text-xs section-subtitle font-bold uppercase tracking-wider">
                      <LogOut className="w-3.5 h-3.5 text-[var(--primary)]" />
                      Exits
                    </div>
                    <span className="text-2xl font-black">
                      {MOCK.ticket.exit_count}
                    </span>
                  </div>
                </div>
                <div className="px-6 pt-3 pb-4 border-t border-[var(--border)] relative z-10 bg-[var(--surface-strong)] landscape:rounded-bl-3xl">
                  <div className="section-subtitle mb-2">
                    <Barcode value={MOCK.ticket.id} />
                  </div>
                  <p className="text-[10px] section-subtitle font-mono tracking-widest">
                    #{MOCK.ticket.id.slice(0, 16).toUpperCase()}
                  </p>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Fingerprint className="w-3 h-3 opacity-30 section-subtitle" />
                    <p className="text-[9px] section-subtitle break-all opacity-40">
                      {MOCK.ticket.signature}
                    </p>
                  </div>
                </div>
              </div>

              {/* ── End LEFT COL ── */}
            </div>

            {/* ══ VERTICAL PERFORATION (landscape only) ══════════════════════ */}
            <div className="portrait:hidden landscape:block relative w-10 flex-shrink-0 bg-[var(--surface-strong)]">
              <div className="absolute -top-4 left-1/2 -translate-x-1/2 h-8 w-8 rounded-full bg-[var(--bg)] z-10" />
              <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 h-8 w-8 rounded-full bg-[var(--bg)] z-10" />
              <div className="absolute top-8 bottom-8 left-1/2 -translate-x-1/2 border-l-2 border-dashed border-[var(--border)]" />
            </div>

            {/* ══ RIGHT COL (or portrait bottom) ═════════════════════════════ */}
            <div className="portrait:w-full landscape:w-80 landscape:flex-shrink-0 flex flex-col">
              {/* Portrait-only: second horizontal perforation before QR */}
              <div className="portrait:block landscape:hidden">
                <Perforation />
              </div>

              {/* ── QR zone ── */}
              <div className="px-6 py-6 flex flex-col items-center gap-4 relative z-10 bg-[var(--surface)] landscape:rounded-tr-3xl landscape:rounded-br-3xl landscape:flex-1">
                {/* Security type pills */}
                <div className="flex gap-2 w-full">
                  <div className="flex-1 flex items-center justify-center gap-1.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 py-1.5 text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                    <RefreshCw className="w-3 h-3" />
                    E-Ticket · Live QR
                  </div>
                  <div className="flex-1 flex items-center justify-center gap-1.5 rounded-xl border border-[var(--border)] bg-[var(--surface-strong)] py-1.5 text-[10px] font-bold section-subtitle uppercase tracking-wider">
                    <Printer className="w-3 h-3" />
                    Print · Static QR
                  </div>
                </div>

                {/* QR Code */}
                <div className="relative">
                  <div className="rounded-2xl border-2 border-[var(--border)] bg-white p-3 shadow-xl relative overflow-hidden">
                    <QRCodeSVG
                      value={
                        status === "valid"
                          ? qrToken
                          : status === "used"
                            ? `USED_${MOCK.ticket.id}`
                            : `REVOKED_${MOCK.ticket.id}`
                      }
                      size={180}
                      level="H"
                      includeMargin={false}
                    />

                    {/* Scanning line — valid only */}
                    {status === "valid" && (
                      <div className="absolute inset-2 overflow-hidden rounded-xl pointer-events-none">
                        <motion.div
                          className="absolute left-0 right-0 h-0.5 bg-emerald-400/70"
                          animate={{ y: [0, 180, 0] }}
                          transition={{
                            duration: 2.5,
                            repeat: Infinity,
                            ease: "easeInOut",
                          }}
                        />
                      </div>
                    )}

                    {/* Used dimmer */}
                    {status === "used" && (
                      <div className="absolute inset-0 bg-amber-400/18 flex items-center justify-center rounded-xl">
                        <div className="bg-amber-500/90 rounded-full px-3 py-1 text-white text-[11px] font-black tracking-widest">
                          USED
                        </div>
                      </div>
                    )}

                    {/* Revoked dimmer */}
                    {status === "revoked" && (
                      <div className="absolute inset-0 bg-red-500/22 flex items-center justify-center rounded-xl backdrop-blur-[1.5px]">
                        <XCircle className="w-12 h-12 text-red-500/80" />
                      </div>
                    )}
                  </div>

                  {/* Countdown ring — valid only */}
                  {status === "valid" && (
                    <div className="absolute -bottom-3 -right-3 bg-[var(--surface-strong)] rounded-full border border-[var(--border)] p-0.5 shadow-md">
                      <svg width="48" height="48" className="-rotate-90">
                        <circle
                          cx="24"
                          cy="24"
                          r={RING_R}
                          fill="none"
                          stroke="var(--border)"
                          strokeWidth="3"
                        />
                        <circle
                          cx="24"
                          cy="24"
                          r={RING_R}
                          fill="none"
                          stroke={timeLeft <= 8 ? "#f59e0b" : "var(--primary)"}
                          strokeWidth="3"
                          strokeDasharray={RING_C}
                          strokeDashoffset={timerOffset}
                          strokeLinecap="round"
                          style={{
                            transition:
                              "stroke-dashoffset 0.85s linear, stroke 0.3s",
                          }}
                        />
                      </svg>
                      <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold tabular-nums">
                        {timeLeft}s
                      </span>
                    </div>
                  )}
                </div>

                {/* Security note */}
                <p className="text-xs section-subtitle flex items-center gap-1.5 text-center leading-snug">
                  {status === "valid" ? (
                    <>
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                      Live rotating QR · screenshots expire instantly
                    </>
                  ) : status === "used" ? (
                    <>
                      <Lock className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                      Entry recorded · QR invalidated after scan
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                      Ticket revoked · QR permanently blocked
                    </>
                  )}
                </p>

                {/* Action buttons */}
                <div className="grid grid-cols-2 gap-2 w-full">
                  <button
                    onClick={() => setFullQr(true)}
                    disabled={status !== "valid"}
                    className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5 disabled:opacity-35 disabled:cursor-not-allowed"
                  >
                    <Maximize2 className="w-3.5 h-3.5" />
                    Full Screen
                  </button>
                  <button
                    onClick={() => window.print()}
                    className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    Print Backup
                  </button>
                  <button
                    onClick={() => setBright((p) => !p)}
                    className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
                  >
                    <Sun className="w-3.5 h-3.5" />
                    {bright ? "Normal" : "Brighten"}
                  </button>
                  <button
                    className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
                    onClick={() => {
                      if ("wakeLock" in navigator) {
                        // eslint-disable-next-line @typescript-eslint/no-explicit-any
                        (navigator as any).wakeLock
                          .request("screen")
                          .catch(() => null);
                      }
                    }}
                  >
                    <Zap className="w-3.5 h-3.5" />
                    Keep Awake
                  </button>
                </div>

                {/* Wallet buttons with real brand logos */}
                <UniversalWalletGroup
                  passData={
                    {
                      ticketId: MOCK.ticket.id,
                      eventName: MOCK.event.name,
                      venueName: MOCK.event.venue,
                      eventDate: MOCK.event.starts_at,
                      holderName: MOCK.ticket.holder_name,
                      ticketType: MOCK.ticket.ticket_type,
                      seat: MOCK.ticket.seat,
                      societyName: MOCK.event.society_name,
                      qrValue: qrToken,
                      backgroundColor: "#10b981",
                    } satisfies WalletPassData
                  }
                />
              </div>

              {/* ── PORTRAIT-only: Entry / Exit counters + barcode below QR ── */}
              <div className="portrait:block landscape:hidden">
                {/* Entry / Exit counters */}
                <div className="px-6 py-4 border-t border-[var(--border)] grid grid-cols-2 gap-4 relative z-10 bg-[var(--surface-strong)]">
                  <div>
                    <div className="flex items-center gap-1.5 mb-1 text-xs section-subtitle font-bold uppercase tracking-wider">
                      <LogIn className="w-3.5 h-3.5 text-[var(--primary)]" />
                      Entries
                    </div>
                    <span className="text-2xl font-black">
                      {MOCK.ticket.entry_count}
                      <span className="text-sm font-normal opacity-60">
                        /{maxEntries}
                      </span>
                    </span>
                    <div className="mt-1.5 h-1.5 rounded-full bg-[var(--border)] overflow-hidden">
                      <div
                        style={{ width: `${entryPct}%` }}
                        className={`h-full rounded-full transition-all duration-500 ${entryPct >= 100 ? "bg-amber-400" : "bg-[var(--primary)]"}`}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center gap-1.5 mb-1 text-xs section-subtitle font-bold uppercase tracking-wider">
                      <LogOut className="w-3.5 h-3.5 text-[var(--primary)]" />
                      Exits
                    </div>
                    <span className="text-2xl font-black">
                      {MOCK.ticket.exit_count}
                    </span>
                  </div>
                </div>

                {/* ── Barcode + Serial ── */}
                <div className="px-6 pt-3 pb-4 border-t border-[var(--border)] relative z-10 bg-[var(--surface-strong)] portrait:rounded-b-3xl">
                  <div className="section-subtitle mb-2">
                    <Barcode value={MOCK.ticket.id} />
                  </div>
                  <p className="text-[10px] section-subtitle font-mono tracking-widest">
                    #{MOCK.ticket.id.slice(0, 16).toUpperCase()}
                  </p>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Fingerprint className="w-3 h-3 opacity-30 section-subtitle" />
                    <p className="text-[9px] section-subtitle break-all opacity-40">
                      {MOCK.ticket.signature}
                    </p>
                  </div>
                </div>

                {/* ── End portrait-only counters/barcode wrapper ── */}
              </div>

              {/* ── End RIGHT COL ── */}
            </div>

            {/* ── End orientation flex container ── */}
          </div>
        </motion.div>

        {/* ── Security model explanation card ── */}
        <div className="w-full portrait:max-w-sm landscape:max-w-3xl mt-5 rounded-2xl border border-[var(--border)] bg-[var(--surface)] px-4 py-4 text-xs">
          <p className="font-bold mb-2.5 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[var(--primary)]" />
            How ticket security works
          </p>
          <div className="space-y-2.5 section-subtitle leading-relaxed">
            <div className="flex gap-2">
              <Wifi className="w-3.5 h-3.5 mt-0.5 flex-shrink-0 text-emerald-400" />
              <span>
                <strong className="text-[var(--fg)]">E-ticket QR</strong>{" "}
                rotates every 30 s using a time-based token window (TOTP-style).
                Screenshots expire immediately. Each scan logs the entry; the
                token is invalidated after max-entry count is reached.
              </span>
            </div>
            <div className="flex gap-2">
              <WifiOff className="w-3.5 h-3.5 mt-0.5 flex-shrink-0 text-amber-400" />
              <span>
                <strong className="text-[var(--fg)]">Printed backup</strong> —
                generates a single-use static QR at print time, marked as
                print-type. The scanner permanently revokes it on first scan.
                Both methods share the same entry counter — only one entry
                allowed per method.
              </span>
            </div>
          </div>
        </div>

        <p className="mt-4 text-xs section-subtitle text-center max-w-xs">
          Switch <strong>Valid / Used / Revoked</strong> above to preview all
          states and animations.{" "}
          <Link href="/buy/1" className="underline underline-offset-2">
            Buy a real ticket →
          </Link>
        </p>

        {/* ── Full-screen QR overlay ── */}
        <AnimatePresence>
          {fullQr && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/95 z-50 flex flex-col items-center justify-center p-6"
              onClick={() => setFullQr(false)}
            >
              <motion.div
                initial={{ scale: 0.8, y: 24 }}
                animate={{ scale: 1, y: 0 }}
                exit={{ scale: 0.8, y: 24 }}
                transition={{ type: "spring", stiffness: 300, damping: 24 }}
                className="bg-white p-6 rounded-3xl shadow-2xl relative"
                onClick={(e) => e.stopPropagation()}
              >
                <QRCodeSVG value={qrToken} size={290} level="H" />
                {/* Scan line */}
                <div className="absolute inset-6 overflow-hidden rounded-xl pointer-events-none">
                  <motion.div
                    className="absolute left-0 right-0 h-0.5 bg-emerald-500/80"
                    animate={{ y: [0, 290, 0] }}
                    transition={{
                      duration: 2.5,
                      repeat: Infinity,
                      ease: "easeInOut",
                    }}
                  />
                </div>
                {/* Countdown ring */}
                <div className="absolute -bottom-5 left-1/2 -translate-x-1/2 bg-zinc-900 rounded-full border border-white/20 p-1 shadow-2xl">
                  <svg width="54" height="54" className="-rotate-90">
                    <circle
                      cx="27"
                      cy="27"
                      r="22"
                      fill="none"
                      stroke="rgba(255,255,255,0.12)"
                      strokeWidth="3"
                    />
                    <circle
                      cx="27"
                      cy="27"
                      r="22"
                      fill="none"
                      stroke={timeLeft <= 8 ? "#f59e0b" : "#10b981"}
                      strokeWidth="3"
                      strokeDasharray={2 * Math.PI * 22}
                      strokeDashoffset={
                        2 * Math.PI * 22 - (timeLeft / 30) * (2 * Math.PI * 22)
                      }
                      strokeLinecap="round"
                      style={{
                        transition:
                          "stroke-dashoffset 0.85s linear, stroke 0.3s",
                      }}
                    />
                  </svg>
                  <span className="absolute inset-0 flex items-center justify-center text-white text-xs font-bold tabular-nums">
                    {timeLeft}s
                  </span>
                </div>
              </motion.div>
              <p className="text-white/40 mt-10 text-sm">
                Tap anywhere to close
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
}
