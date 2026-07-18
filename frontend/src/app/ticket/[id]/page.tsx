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
} from "lucide-react";
import { useParams } from "next/navigation";
import Image from "next/image";
import { API_BASE } from "@/lib/api";
import { EventItem, TicketItem } from "@/lib/types";
import BackButton from "@/app/back-button";
import { UniversalWalletGroup } from "@/components/wallet/WalletButtons";
import { AnimatePresence } from "framer-motion";

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
        <div className="border border-[var(--alert)] bg-[var(--alert)]/10 text-[var(--alert)] p-8 max-w-md w-full text-center">
          <AlertCircle className="w-10 h-10 mx-auto mb-4" />
          <h1 className="font-display font-medium text-lg mb-2">Access Denied</h1>
          <p className="text-[10px] font-mono uppercase tracking-widest leading-relaxed">
            {error}
          </p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="app-shell flex items-center justify-center">
        <div className="text-[11px] font-mono text-[var(--muted)] uppercase tracking-widest border border-[var(--border)] px-4 py-3">
          Fetching ticket...
        </div>
      </div>
    );
  }

  const qrValue = qrToken ? `${window.location.origin}/scan?t=${qrToken}` : "";
  const maxEntries = data.ticket.ticket_type === "OC" ? null : 2;

  // Render physical ticket design
  return (
    <div className="app-shell flex flex-col items-center px-4 py-6 sm:py-10">
      <div className="w-full max-w-[540px] mb-4">
        <BackButton href="/" label="Back to Home" />
      </div>

      {(error || !isOnline) && (
        <div className="w-full max-w-[540px] mb-4 border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-[10px] font-mono uppercase text-amber-400 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error ?? "You're offline — showing cached ticket"}
        </div>
      )}

      {/* ── ADMIT CARD (Paper Ticket) ── */}
      <div className="ticket-stage w-full">
        <div className="admit-card relative z-10">
          
          {statusLabel === "revoked" && (
            <div className="absolute inset-0 z-50 bg-[#8C3A2E]/10 backdrop-blur-[1px] flex items-center justify-center pointer-events-none">
              <div className="text-[4rem] font-black uppercase text-[#8C3A2E] tracking-widest border-8 border-[#8C3A2E] px-8 py-2 -rotate-[25deg] opacity-75">
                VOID
              </div>
            </div>
          )}

          {statusLabel === "used" && (
            <div className="absolute inset-0 z-50 bg-[#A9823C]/5 flex items-center justify-center pointer-events-none">
              <div className="text-[4rem] font-black uppercase text-[#A9823C] tracking-widest border-8 border-[#A9823C] px-8 py-2 -rotate-[15deg] opacity-60">
                USED
              </div>
            </div>
          )}
          
          <div className="ac-letterhead">
            <div className="ac-brand">
              {data.event.logo_url && (
                <Image src={data.event.logo_url} width={28} height={28} alt="Logo" unoptimized className="border border-[var(--paper-ink)]" />
              )}
              <div>
                <div className="name">{data.event.name}</div>
                <div className="sub">{data.event.society_name || "NUST Event"}</div>
              </div>
            </div>
            <div className="ac-doctype">
              Admit One
              <br />
              <span style={{ fontSize: '7px' }}>Not Transferable</span>
            </div>
          </div>

          <div className="ac-body">
            <div>
              <div className="ac-field">
                <div className="flabel">Holder Name</div>
                <div className="fvalue">{data.ticket.holder_name}</div>
              </div>

              <div className="ac-field" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div>
                  <div className="flabel">Type</div>
                  <div className="fvalue">{data.ticket.ticket_type}</div>
                </div>
                <div>
                  <div className="flabel">Seat</div>
                  <div className="fvalue">{data.ticket.seat || "GEN"}</div>
                </div>
              </div>

              <div className="ac-field" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div>
                  <div className="flabel">Department</div>
                  <div className="fvalue" style={{ fontSize: '13px' }}>{data.ticket.department || "—"}</div>
                </div>
                <div>
                  <div className="flabel">Year</div>
                  <div className="fvalue" style={{ fontSize: '13px' }}>{data.ticket.year || "—"}</div>
                </div>
              </div>

              <div className="ac-field">
                <div className="flabel">Status</div>
                <span className={`stamp-badge ${statusLabel === 'valid' ? 'verified' : statusLabel === 'revoked' ? 'alert' : 'neutral'}`} style={{ padding: '4px 10px', minHeight: 0 }}>
                  <span style={{ fontSize: '9px', fontWeight: 'bold' }}>
                    {statusLabel.toUpperCase()}
                  </span>
                </span>
              </div>
            </div>

            <div className="ac-photo">
              <div className="bracket tl"></div>
              <div className="bracket tr"></div>
              <div className="bracket bl"></div>
              <div className="bracket br"></div>
              
              <div className="qr-box bg-white p-1">
                {isOnline && qrToken ? (
                   <QRCodeSVG
                    value={qrValue}
                    size={110}
                    level="H"
                    includeMargin={false}
                  />
                ) : (
                  <div className="w-[110px] h-[110px] bg-gray-100 flex items-center justify-center">
                    <RefreshCw className="w-5 h-5 text-gray-400 animate-spin" />
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="ac-meta-row">
            <div>
              <strong>VENUE:</strong> {data.event.venue}
            </div>
            <div>
              <strong>TIME:</strong> {new Date(data.event.starts_at).toLocaleString("en-PK", {
                month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
              })}
            </div>
          </div>

          <div className="perforation">
            {Array.from({ length: 45 }).map((_, i) => <span key={i}></span>)}
          </div>

          <div className="ac-stub">
            <div className="stub-text" style={{ flex: 1 }}>
              <div className="ac-field" style={{ marginBottom: '8px' }}>
                <div className="flabel">Ticket ID</div>
                <div className="fvalue" style={{ fontFamily: 'var(--f-mono)', fontSize: '10px' }}>
                  {data.ticket.id.toUpperCase()}
                </div>
              </div>
              <div className="ac-field" style={{ marginBottom: 0 }}>
                <div className="flabel">Entries</div>
                <div className="fvalue" style={{ fontFamily: 'var(--f-mono)', fontSize: '12px' }}>
                  {data.ticket.entry_count} / {maxEntries ?? "∞"}
                </div>
              </div>
            </div>

            <div className="seal">
              <div className="seal-text">
                NUST
                <br />
                {data.event.society_name?.slice(0, 5) || "EVENT"}
                <br />
                AUTH
              </div>
            </div>
          </div>

        </div>
      </div>

      {/* ── CONTROLS & WALLET (Outside of Paper Ticket) ── */}
      <div className="w-full max-w-[540px] mt-6 grid grid-cols-2 gap-2">
        <button
          onClick={() => setFullQr(true)}
          className="btn-secondary text-[10px]"
        >
          <Maximize2 className="w-3.5 h-3.5" /> Full Screen
        </button>
        <button
          onClick={() => window.print()}
          className="btn-secondary text-[10px]"
        >
          <Printer className="w-3.5 h-3.5" /> Print Backup
        </button>
        <button
          onClick={() => setBright((p) => !p)}
          className="btn-secondary text-[10px]"
        >
          <Sun className="w-3.5 h-3.5" /> {bright ? "Normal" : "Brighten"}
        </button>
        <button
          onClick={async () => {
            if (!wakeLock && "wakeLock" in navigator) {
              try { setWakeLock(await navigator.wakeLock.request("screen")); } 
              catch { setError("Wake lock unsupported"); }
            } else if (wakeLock) {
              await wakeLock.release();
              setWakeLock(null);
            }
          }}
          className="btn-secondary text-[10px]"
        >
          <BatteryCharging className="w-3.5 h-3.5" /> {wakeLock ? "Screen: ON" : "Keep Awake"}
        </button>
      </div>

      <div className="w-full max-w-[540px] mt-4">
        {promptEvent && (
          <button
            className="w-full btn-primary text-xs py-2 mb-3"
            onClick={async () => {
              await promptEvent.prompt();
              await promptEvent.userChoice;
              setPromptEvent(null);
            }}
          >
            Add to Home Screen
          </button>
        )}
        
        {walletLinks && (
          <UniversalWalletGroup
            appleUrl={walletLinks.apple_wallet_url}
            googleUrl={walletLinks.google_wallet_url}
            samsungUrl={walletLinks.samsung_wallet_url}
            message={walletLinks.message}
          />
        )}
        
        <p className="text-[9px] font-mono uppercase text-center mt-6 text-[var(--muted)]">
          <ShieldCheck className="w-3 h-3 inline mr-1" />
          {isOnline ? "Live QR Code token rotates every 30s. Screenshots expire." : "Offline Mode"}
        </p>
      </div>

      {/* ── FULL SCREEN QR OVERLAY ── */}
      <AnimatePresence>
        {fullQr && (
          <div
            className="fixed inset-0 bg-black z-50 flex flex-col items-center justify-center p-6"
            onClick={() => setFullQr(false)}
          >
            <div
              className="bg-white p-6 relative"
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
                <div className="w-[300px] h-[300px] bg-gray-200" />
              )}
            </div>
            <p className="text-[10px] font-mono uppercase tracking-widest text-white/50 mt-6">
              Tap anywhere to close
            </p>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
