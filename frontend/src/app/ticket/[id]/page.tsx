"use client";

import { useEffect, useMemo, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  BatteryCharging,
  AlertCircle,
  Maximize2,
  Printer,
  RefreshCw,
  ShieldCheck,
  Sun,
  Zap,
  CheckCircle2,
  XCircle,
  Clock,
  MapPin,
  User,
  Hash,
  Tag,
  UserCheck,
  BookOpen,
  LogIn,
  LogOut,
} from "lucide-react";
import { useParams } from "next/navigation";
import Image from "next/image";
import { motion, AnimatePresence } from "framer-motion";
import { API_BASE } from "@/lib/api";
import { EventItem, TicketItem } from "@/lib/types";
import BackButton from "@/app/back-button";
import { UniversalWalletGroup } from "@/components/wallet/WalletButtons";

type TicketFull = {
  ticket: TicketItem;
  event: EventItem;
};

type WalletLinks = {
  apple_wallet_url: string | null;
  google_wallet_url: string | null;
  samsung_wallet_url: string | null;
  message: string;
};

type DeferredPrompt = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
};

const getErrorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message;
  return "Something went wrong";
};

export default function TicketPage() {
  const params = useParams<{ id: string }>();
  const ticketId = params.id;

  const [data, setData] = useState<TicketFull | null>(null);
  const [qrToken, setQrToken] = useState<string | null>(null);
  const [timeLeft, setTimeLeft] = useState(30);
  const [error, setError] = useState<string | null>(null);
  const [isOnline, setIsOnline] = useState(true);
  const [fullQr, setFullQr] = useState(false);
  const [bright, setBright] = useState(false);
  const [wakeLock, setWakeLock] = useState<WakeLockSentinel | null>(null);
  const [promptEvent, setPromptEvent] = useState<DeferredPrompt | null>(null);
  const [walletLinks, setWalletLinks] = useState<WalletLinks | null>(null);

  const statusLabel = useMemo(() => {
    if (!data) return "valid";
    if (data.ticket.status === "used") return "used";
    if (data.ticket.status === "revoked") return "revoked";
    if (
      data.ticket.ticket_type !== "OC" &&
      data.ticket.entry_count >= 2 &&
      data.ticket.exit_count >= 2
    )
      return "used";
    return "valid";
  }, [data]);

  useEffect(() => {
    if (!ticketId) return;

    const fetchTicket = async () => {
      try {
        const res = await fetch(`${API_BASE}/tickets/${ticketId}/full`);
        if (!res.ok) throw new Error("Ticket not found");
        const payload: TicketFull = await res.json();
        setData(payload);
        localStorage.setItem(
          `ticket_cache_${ticketId}`,
          JSON.stringify(payload),
        );
      } catch (err: unknown) {
        const cached = localStorage.getItem(`ticket_cache_${ticketId}`);
        if (cached) {
          setData(JSON.parse(cached) as TicketFull);
          setError("Offline mode: showing cached ticket");
          return;
        }
        setError(getErrorMessage(err));
      }
    };
    fetchTicket();
  }, [ticketId]);

  useEffect(() => {
    const online = () => setIsOnline(true);
    const offline = () => setIsOnline(false);
    setIsOnline(navigator.onLine);
    window.addEventListener("online", online);
    window.addEventListener("offline", offline);
    return () => {
      window.removeEventListener("online", online);
      window.removeEventListener("offline", offline);
    };
  }, []);

  useEffect(() => {
    if (!ticketId) return;
    const loadWalletLinks = async () => {
      const res = await fetch(`${API_BASE}/tickets/${ticketId}/wallet-links`);
      if (!res.ok) return;
      const payload: WalletLinks = await res.json();
      // Resolve relative URLs returned by the backend
      if (payload.apple_wallet_url?.startsWith("/")) {
        payload.apple_wallet_url = `${API_BASE}${payload.apple_wallet_url}`;
      }
      if (payload.google_wallet_url?.startsWith("/")) {
        payload.google_wallet_url = `${API_BASE}${payload.google_wallet_url}`;
      }
      if (payload.samsung_wallet_url?.startsWith("/")) {
        payload.samsung_wallet_url = `${API_BASE}${payload.samsung_wallet_url}`;
      }
      setWalletLinks(payload);
    };
    void loadWalletLinks();
  }, [ticketId]);

  useEffect(() => {
    const onBeforeInstallPrompt = (event: Event) => {
      event.preventDefault();
      setPromptEvent(event as DeferredPrompt);
    };
    window.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
    return () =>
      window.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
  }, []);

  useEffect(() => {
    if (!data || !ticketId || !isOnline) return;

    const fetchQrToken = async () => {
      try {
        let fingerprint = localStorage.getItem("device_fingerprint");
        if (!fingerprint) {
          fingerprint = crypto.randomUUID();
          localStorage.setItem("device_fingerprint", fingerprint);
        }

        const res = await fetch(`${API_BASE}/tickets/${ticketId}/qr-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_fingerprint: fingerprint }),
        });

        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.detail || "Failed to generate QR");
        }

        const tokenData: { token: string; expires_in: number } =
          await res.json();
        setQrToken(tokenData.token);
        setTimeLeft(tokenData.expires_in);
      } catch (err: unknown) {
        setError(getErrorMessage(err));
      }
    };

    fetchQrToken();
    const interval = setInterval(fetchQrToken, 30000);
    return () => clearInterval(interval);
  }, [data, ticketId, isOnline]);

  useEffect(() => {
    if (timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [timeLeft]);

  useEffect(() => {
    document.body.style.filter = bright ? "brightness(1.15)" : "none";
    return () => {
      document.body.style.filter = "none";
    };
  }, [bright]);

  if (error && !data) {
    return (
      <div className="app-shell flex flex-col items-center justify-center p-4">
        <div className="glass-panel w-full max-w-md p-8 text-center">
          <AlertCircle className="w-14 h-14 text-[var(--danger)] mx-auto mb-4" />
          <h1 className="text-2xl font-bold mb-2">Access Denied</h1>
          <p className="section-subtitle text-center">{error}</p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="app-shell flex items-center justify-center">
        <div className="glass-panel p-8">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[var(--primary)]" />
        </div>
      </div>
    );
  }

  const qrValue = qrToken ? `${window.location.origin}/scan?t=${qrToken}` : "";

  const statusConfig = {
    valid: {
      color: "from-emerald-500 to-emerald-700",
      badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
      icon: <CheckCircle2 className="w-4 h-4" />,
      label: "VALID",
    },
    used: {
      color: "from-amber-500 to-amber-700",
      badge: "bg-amber-500/15 text-amber-400 border-amber-500/30",
      icon: <Clock className="w-4 h-4" />,
      label: "USED",
    },
    revoked: {
      color: "from-red-600 to-red-800",
      badge: "bg-red-500/15 text-red-400 border-red-500/30",
      icon: <XCircle className="w-4 h-4" />,
      label: "REVOKED",
    },
  };
  const sc =
    statusConfig[statusLabel as keyof typeof statusConfig] ??
    statusConfig.valid;
  const maxEntries = data.ticket.ticket_type === "OC" ? null : 2;
  const entryPct = maxEntries
    ? Math.min((data.ticket.entry_count / maxEntries) * 100, 100)
    : 100;
  const getGoogleMapsLink = () => {
    if (!data?.event.venue_lat || !data?.event.venue_lng) {
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(data?.event.venue || "")}`;
    }
    return `https://www.google.com/maps/dir/?api=1&destination=${data.event.venue_lat},${data.event.venue_lng}`;
  };

  const getCalendarLink = () => {
    if (!data?.event) return "#";
    const start = new Date(data.event.starts_at)
      .toISOString()
      .replace(/-|:|\.\d+/g, "");
    const end = new Date(data.event.ends_at)
      .toISOString()
      .replace(/-|:|\.\d+/g, "");
    const url = new URL("https://calendar.google.com/calendar/render");
    url.searchParams.append("action", "TEMPLATE");
    url.searchParams.append("text", data.event.name);
    url.searchParams.append("dates", `${start}/${end}`);
    url.searchParams.append("details", data.event.description || "");
    url.searchParams.append("location", data.event.venue || "");
    return url.toString();
  };

  const circumference = 2 * Math.PI * 20; // r=20
  const timerOffset = circumference - (timeLeft / 30) * circumference;

  return (
    <div className="app-shell flex flex-col items-center px-4 py-6 sm:py-10 relative overflow-hidden min-h-screen">
      {/* Ambient orbs */}
      <div className="pulse-orb h-56 w-56 left-[-2rem] top-[4rem] bg-blue-500/60 pointer-events-none" />
      <div className="pulse-orb h-48 w-48 right-[-2rem] bottom-[10rem] bg-cyan-400/50 pointer-events-none" />

      <div className="w-full max-w-sm mb-3">
        <BackButton href="/" label="Back" />
      </div>

      {/* Offline / error banner */}
      <AnimatePresence>
        {(error || !isOnline) && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="w-full max-w-sm mb-3 flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-400"
          >
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error ?? "You're offline — showing cached ticket"}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── TICKET CARD ─────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 28 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.55, ease: "easeOut" }}
        className="w-full max-w-sm rounded-3xl overflow-hidden shadow-2xl border border-white/10 relative bg-[var(--surface-strong)]"
      >
        {/* Watermark */}
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden z-0 select-none">
          <span className="text-[6rem] font-black tracking-widest opacity-[0.03] rotate-[-20deg] whitespace-nowrap">
            RIWAQFLOW
          </span>
        </div>

        {/* ── Header gradient ── */}
        <div
          className={`relative bg-gradient-to-br ${sc.color} p-6 text-white overflow-hidden`}
        >
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_15%_25%,rgba(255,255,255,0.18),transparent_50%)] pointer-events-none" />

          {/* Society logo + status badge */}
          <div className="relative z-10 flex items-start justify-between mb-4">
            {data.event.logo_url ? (
              <Image
                src={data.event.logo_url}
                alt="Event logo"
                width={44}
                height={44}
                unoptimized
                className="h-11 w-11 rounded-2xl object-cover border-2 border-white/30 shadow-lg"
              />
            ) : (
              <div className="h-11 w-11 rounded-2xl bg-white/20 border-2 border-white/30 flex items-center justify-center">
                <Zap className="w-6 h-6 text-white" />
              </div>
            )}

            <span
              className={`inline-flex items-center gap-1.5 text-xs font-bold px-3 py-1.5 rounded-full border ${sc.badge}`}
            >
              {sc.icon}
              {sc.label}
            </span>
          </div>

          {/* Event title */}
          <div className="relative z-10">
            {data.event.society_name && (
              <p className="text-xs font-semibold uppercase tracking-widest text-white/70 mb-1">
                {data.event.society_name}
              </p>
            )}
            <h1 className="text-2xl font-black leading-tight tracking-tight">
              {data.event.name}
            </h1>
            <div className="mt-2 flex flex-wrap gap-3 text-sm text-white/80">
              <a
                href={getGoogleMapsLink()}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 hover:text-white transition-colors hover:underline decoration-white/50 underline-offset-4 cursor-pointer"
                title="Get Directions"
              >
                <MapPin className="w-3.5 h-3.5" />
                {data.event.venue}
              </a>
              <a
                href={getCalendarLink()}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 hover:text-white transition-colors hover:underline decoration-white/50 underline-offset-4 cursor-pointer"
                title="Add to Google Calendar"
              >
                <Clock className="w-3.5 h-3.5" />
                {new Date(data.event.starts_at).toLocaleString(undefined, {
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </a>
            </div>
          </div>
        </div>

        {/* ── Tear / perforation line ── */}
        <div className="relative flex items-center bg-[var(--surface-strong)]">
          <div className="absolute -left-4 h-8 w-8 rounded-full bg-[var(--bg)]" />
          <div className="absolute -right-4 h-8 w-8 rounded-full bg-[var(--bg)]" />
          <div className="mx-6 w-full border-t-2 border-dashed border-[var(--border)]" />
        </div>

        {/* ── Holder info grid ── */}
        <div className="px-6 pt-4 pb-5 grid grid-cols-2 gap-x-4 gap-y-3 text-sm relative z-10">
          {[
            {
              icon: <User className="w-3.5 h-3.5" />,
              label: "Holder",
              value: data.ticket.holder_name,
            },
            {
              icon: <Tag className="w-3.5 h-3.5" />,
              label: "Type",
              value: data.ticket.ticket_type,
            },
            {
              icon: <Hash className="w-3.5 h-3.5" />,
              label: "Seat",
              value: data.ticket.seat || "General",
            },
            {
              icon: <UserCheck className="w-3.5 h-3.5" />,
              label: "Role",
              value: data.ticket.role || "—",
            },
            {
              icon: <BookOpen className="w-3.5 h-3.5" />,
              label: "Dept",
              value: data.ticket.department || "—",
            },
            {
              icon: <BookOpen className="w-3.5 h-3.5" />,
              label: "Year",
              value: data.ticket.year || "—",
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

          {data.ticket.interests && (
            <div className="col-span-2">
              <p className="text-[10px] uppercase tracking-wider section-subtitle font-bold mb-1">
                Interests
              </p>
              <div className="flex flex-wrap gap-1">
                {data.ticket.interests.split(",").map((t) => (
                  <span key={t} className="chip text-xs px-2 py-0.5">
                    {t.trim()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Tear / perforation line ── */}
        <div className="relative flex items-center bg-[var(--surface-strong)]">
          <div className="absolute -left-4 h-8 w-8 rounded-full bg-[var(--bg)]" />
          <div className="absolute -right-4 h-8 w-8 rounded-full bg-[var(--bg)]" />
          <div className="mx-6 w-full border-t-2 border-dashed border-[var(--border)]" />
        </div>

        {/* ── QR zone ── */}
        <div className="px-6 py-6 flex flex-col items-center gap-4 relative z-10 bg-[var(--surface)]">
          {/* QR + countdown ring */}
          <div className="relative">
            <div className="rounded-2xl border border-[var(--border)] bg-white p-3 shadow-lg">
              {isOnline && qrToken ? (
                <QRCodeSVG
                  value={qrValue}
                  size={180}
                  level="H"
                  includeMargin={false}
                />
              ) : (
                <div className="w-[180px] h-[180px] bg-gray-100 rounded-xl flex items-center justify-center">
                  <RefreshCw className="w-8 h-8 text-gray-400 animate-spin" />
                </div>
              )}
              {/* Scan line animation */}
              <div className="absolute inset-3 overflow-hidden rounded-xl pointer-events-none">
                <div className="absolute left-0 right-0 h-0.5 bg-[var(--primary)] opacity-60 animate-[scan_2s_ease-in-out_infinite]" />
              </div>
            </div>

            {/* Countdown ring overlay — bottom right corner */}
            {isOnline && (
              <div className="absolute -bottom-3 -right-3 bg-[var(--surface-strong)] rounded-full border border-[var(--border)] p-0.5 shadow-md">
                <svg width="48" height="48" className="-rotate-90">
                  <circle
                    cx="24"
                    cy="24"
                    r="20"
                    fill="none"
                    stroke="var(--border)"
                    strokeWidth="3"
                  />
                  <circle
                    cx="24"
                    cy="24"
                    r="20"
                    fill="none"
                    stroke={timeLeft > 10 ? "var(--primary)" : "#f59e0b"}
                    strokeWidth="3"
                    strokeDasharray={circumference}
                    strokeDashoffset={timerOffset}
                    strokeLinecap="round"
                    className="[transition:stroke-dashoffset_0.9s_linear]"
                  />
                </svg>
                <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold tabular-nums">
                  {timeLeft}s
                </span>
              </div>
            )}
          </div>

          <p className="text-xs section-subtitle flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-[var(--success)]" />
            {isOnline
              ? "Live rotating QR — screenshots expire"
              : "Offline: using cached data"}
          </p>

          {/* Action buttons */}
          <div className="grid grid-cols-2 gap-2 w-full">
            <button
              onClick={() => setFullQr(true)}
              className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
            >
              <Maximize2 className="w-3.5 h-3.5" /> Full Screen
            </button>
            <button
              onClick={() => window.print()}
              className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
            >
              <Printer className="w-3.5 h-3.5" /> Print
            </button>
            <button
              onClick={() => setBright((p) => !p)}
              className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
            >
              <Sun className="w-3.5 h-3.5" /> {bright ? "Normal" : "Brighten"}
            </button>
            <button
              onClick={async () => {
                if (!wakeLock && "wakeLock" in navigator) {
                  try {
                    setWakeLock(await navigator.wakeLock.request("screen"));
                  } catch {
                    setError("Wake lock unsupported");
                  }
                } else if (wakeLock) {
                  await wakeLock.release();
                  setWakeLock(null);
                }
              }}
              className="btn-secondary text-xs py-2 flex items-center justify-center gap-1.5"
            >
              <BatteryCharging className="w-3.5 h-3.5" />
              {wakeLock ? "Screen: ON" : "Keep Awake"}
            </button>
            {promptEvent && (
              <button
                className="col-span-2 btn-primary text-xs py-2 flex items-center justify-center gap-1.5"
                onClick={async () => {
                  await promptEvent.prompt();
                  await promptEvent.userChoice;
                  setPromptEvent(null);
                }}
              >
                Add to Home Screen
              </button>
            )}
          </div>

          {walletLinks && (
            <UniversalWalletGroup
              appleUrl={walletLinks.apple_wallet_url}
              googleUrl={walletLinks.google_wallet_url}
              samsungUrl={walletLinks.samsung_wallet_url}
              message={walletLinks.message}
            />
          )}
        </div>

        {/* ── Entry / Exit counters ── */}
        <div className="px-6 py-4 border-t border-[var(--border)] grid grid-cols-2 gap-4 relative z-10 bg-[var(--surface-strong)]">
          <div>
            <div className="flex items-center gap-1.5 mb-1 text-xs section-subtitle font-bold uppercase tracking-wider">
              <LogIn className="w-3.5 h-3.5 text-[var(--primary)]" /> Entries
            </div>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black">
                {data.ticket.entry_count}
                <span className="text-sm font-normal opacity-60">
                  /{maxEntries ?? "∞"}
                </span>
              </span>
            </div>
            {maxEntries && (
              <div className="mt-1.5 h-1.5 rounded-full bg-[var(--border)] overflow-hidden">
                <div
                  style={{ width: `${entryPct}%` }}
                  className={`h-full rounded-full transition-all duration-500 ${entryPct >= 100 ? "bg-amber-400" : "bg-[var(--primary)]"}`}
                />
              </div>
            )}
          </div>
          <div>
            <div className="flex items-center gap-1.5 mb-1 text-xs section-subtitle font-bold uppercase tracking-wider">
              <LogOut className="w-3.5 h-3.5 text-[var(--primary)]" /> Exits
            </div>
            <span className="text-2xl font-black">
              {data.ticket.exit_count}
            </span>
          </div>
        </div>

        {/* ── Serial / Signature ── */}
        <div className="px-6 py-3 border-t border-[var(--border)] relative z-10 bg-[var(--surface-strong)]">
          <p className="text-[10px] section-subtitle font-mono tracking-widest">
            #{data.ticket.id.slice(0, 16).toUpperCase()}
          </p>
          {data.ticket.signature && (
            <p className="text-[9px] section-subtitle break-all mt-0.5 opacity-50">
              {data.ticket.signature}
            </p>
          )}
        </div>
      </motion.div>

      {/* ── Full-screen QR overlay ── */}
      <AnimatePresence>
        {fullQr && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black z-50 flex flex-col items-center justify-center p-6"
            onClick={() => setFullQr(false)}
          >
            <motion.div
              initial={{ scale: 0.85 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.85 }}
              className="bg-white p-6 rounded-3xl shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              {qrToken ? (
                <QRCodeSVG
                  value={qrValue}
                  size={300}
                  level="H"
                  includeMargin={false}
                />
              ) : (
                <div className="w-[300px] h-[300px] bg-gray-200 rounded-2xl" />
              )}
            </motion.div>
            <p className="text-white/60 mt-5 text-sm">Tap anywhere to close</p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
