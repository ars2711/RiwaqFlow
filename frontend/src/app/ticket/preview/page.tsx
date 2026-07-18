"use client";

import { useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  Maximize2,
  Printer,
  ShieldCheck,
  Sun,
  Zap,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import BackButton from "@/app/back-button";
import {
  UniversalWalletGroup,
  WalletPassData,
} from "@/components/wallet/WalletButtons";

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

const PRINT_TOKEN = `RF_PRINT_STATIC_${MOCK.ticket.id.toUpperCase()}`;

export default function TicketPreviewPage() {
  const [status, setStatus] = useState<Status>("valid");
  const [timeLeft, setTimeLeft] = useState(30);
  const [qrToken, setQrToken] = useState("Riwaq_DEMO_PREVIEW");
  const [fullQr, setFullQr] = useState(false);
  const [bright, setBright] = useState(false);
  const stampTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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
  };

  const maxEntries = 2;

  return (
    <>
      <div className="hidden print:flex fixed inset-0 bg-white z-50 flex-col items-center justify-center gap-6 p-10 text-black">
        <div className="text-center">
          <p className="text-[10px] font-mono tracking-widest uppercase text-gray-400 mb-1">
            {MOCK.event.society_name}
          </p>
          <h1 className="text-3xl font-display font-medium">{MOCK.event.name}</h1>
          <p className="text-sm font-mono uppercase text-gray-500 mt-2">{MOCK.event.venue}</p>
        </div>
        <div className="border border-black p-4">
          <QRCodeSVG value={PRINT_TOKEN} size={220} level="H" />
        </div>
        <div className="text-center space-y-2">
          <p className="font-bold text-xl uppercase tracking-wide">{MOCK.ticket.holder_name}</p>
          <p className="text-xs font-mono uppercase text-gray-600 tracking-widest">
            {MOCK.ticket.ticket_type} &middot; SEAT {MOCK.ticket.seat} &middot; {MOCK.ticket.role}
          </p>
          <p className="font-mono text-[10px] text-gray-400 mt-4">
            #{MOCK.ticket.id.toUpperCase()}
          </p>
        </div>
      </div>

      <div
        className={`app-shell print:hidden flex flex-col items-center px-4 py-6 sm:py-10 relative overflow-hidden min-h-screen transition-[filter] duration-300 ${bright ? "[filter:brightness(1.28)]" : ""}`}
      >
        <div className="w-full max-w-[540px] mb-4">
          <BackButton href="/" label="Back to Home" />
        </div>

        <div className="w-full max-w-[540px] mb-6 border border-[var(--verified)] bg-[var(--verified)]/10 px-4 py-3 text-[10px] font-mono uppercase">
          <p className="font-bold flex items-center gap-2 tracking-widest text-[var(--verified)] mb-1">
            <Zap className="w-3 h-3" /> Design preview
          </p>
          <p className="text-[var(--muted)] tracking-wider">
            Real tickets at /ticket/[id]
          </p>
          <div className="flex gap-2 mt-4">
            {MOCK_STATUSES.map((s) => (
              <button
                key={s}
                onClick={() => handleStatusChange(s)}
                className={`flex-1 border py-2 font-bold tracking-widest transition-colors ${
                  status === s
                    ? "bg-[var(--verified)] text-[var(--bg)] border-[var(--verified)]"
                    : "border-[var(--border)] text-[var(--muted)] hover:border-[var(--verified)]/50 hover:text-[var(--verified)]"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* ── ADMIT CARD ── */}
        <div className="ticket-stage w-full">
          <div className="admit-card relative z-10">
            {status === "revoked" && (
              <div className="absolute inset-0 z-50 bg-[#8C3A2E]/10 backdrop-blur-[1px] flex items-center justify-center pointer-events-none">
                <div className="text-[4rem] font-black uppercase text-[#8C3A2E] tracking-widest border-8 border-[#8C3A2E] px-8 py-2 -rotate-[25deg] opacity-75">
                  VOID
                </div>
              </div>
            )}

            {status === "used" && (
              <div className="absolute inset-0 z-50 bg-[#A9823C]/5 flex items-center justify-center pointer-events-none">
                <div className="text-[4rem] font-black uppercase text-[#A9823C] tracking-widest border-8 border-[#A9823C] px-8 py-2 -rotate-[15deg] opacity-60">
                  USED
                </div>
              </div>
            )}

            <div className="ac-letterhead">
              <div className="ac-brand">
                <div className="h-7 w-7 border border-[var(--paper-ink)] flex items-center justify-center">
                  <Zap className="w-4 h-4 text-[var(--paper-ink)]" />
                </div>
                <div>
                  <div className="name">{MOCK.event.name}</div>
                  <div className="sub">{MOCK.event.society_name}</div>
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
                  <div className="fvalue">{MOCK.ticket.holder_name}</div>
                </div>

                <div className="ac-field" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div>
                    <div className="flabel">Type</div>
                    <div className="fvalue">{MOCK.ticket.ticket_type}</div>
                  </div>
                  <div>
                    <div className="flabel">Seat</div>
                    <div className="fvalue">{MOCK.ticket.seat}</div>
                  </div>
                </div>

                <div className="ac-field" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div>
                    <div className="flabel">Department</div>
                    <div className="fvalue" style={{ fontSize: '13px' }}>{MOCK.ticket.department}</div>
                  </div>
                  <div>
                    <div className="flabel">Year</div>
                    <div className="fvalue" style={{ fontSize: '13px' }}>{MOCK.ticket.year}</div>
                  </div>
                </div>

                <div className="ac-field">
                  <div className="flabel">Status</div>
                  <span className={`stamp-badge ${status === 'valid' ? 'verified' : status === 'revoked' ? 'alert' : 'neutral'}`} style={{ padding: '4px 10px', minHeight: 0 }}>
                    <span style={{ fontSize: '9px', fontWeight: 'bold' }}>
                      {status.toUpperCase()}
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
                  <QRCodeSVG
                    value={
                      status === "valid" ? qrToken : status === "used" ? `USED_${MOCK.ticket.id}` : `REVOKED_${MOCK.ticket.id}`
                    }
                    size={110}
                    level="H"
                    includeMargin={false}
                  />
                </div>
              </div>
            </div>

            <div className="ac-meta-row">
              <div>
                <strong>VENUE:</strong> {MOCK.event.venue}
              </div>
              <div>
                <strong>TIME:</strong> {new Date(MOCK.event.starts_at).toLocaleString("en-PK", {
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
                    {MOCK.ticket.id.toUpperCase()}
                  </div>
                </div>
                <div className="ac-field" style={{ marginBottom: 0 }}>
                  <div className="flabel">Entries</div>
                  <div className="fvalue" style={{ fontFamily: 'var(--f-mono)', fontSize: '12px' }}>
                    {MOCK.ticket.entry_count} / {maxEntries}
                  </div>
                </div>
              </div>

              <div className="seal">
                <div className="seal-text">
                  NUST
                  <br />
                  {MOCK.event.society_name.slice(0, 5)}
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
            disabled={status !== "valid"}
            className="btn-secondary text-[10px] disabled:opacity-30"
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
            onClick={() => {
              if ("wakeLock" in navigator) {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                (navigator as any).wakeLock.request("screen").catch(() => null);
              }
            }}
            className="btn-secondary text-[10px]"
          >
            <Zap className="w-3.5 h-3.5" /> Keep Awake
          </button>
        </div>

        <div className="w-full max-w-[540px] mt-4">
          <UniversalWalletGroup
            passData={{
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
            } satisfies WalletPassData}
          />
          
          <p className="text-[9px] font-mono uppercase text-center mt-6 text-[var(--muted)]">
            <ShieldCheck className="w-3 h-3 inline mr-1" />
            Live QR Code token rotates every 30s. Screenshots expire.
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
                <QRCodeSVG
                  value={qrToken}
                  size={300}
                  level="H"
                  includeMargin={false}
                />
              </div>
              <p className="text-[10px] font-mono uppercase tracking-widest text-white/50 mt-6">
                Tap anywhere to close
              </p>
            </div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
}
