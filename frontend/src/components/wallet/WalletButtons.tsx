import React, { useState } from "react";
import { motion } from "framer-motion";
import { WalletCards, Loader2 } from "lucide-react";

// ── Wallet pass data interface ────────────────────────────────────────────────
export interface WalletPassData {
  ticketId: string;
  eventName: string;
  venueName: string;
  eventDate: string; // ISO string
  holderName: string;
  ticketType: string;
  seat?: string;
  societyName?: string;
  qrValue: string;
  backgroundColor?: string; // hex, e.g. "#10b981"
}

// ── CRC32 ────────────────────────────────────────────────────────────────────
function crc32(data: Uint8Array): number {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++)
    crc = table[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// ── Minimal in-memory ZIP (no-compression / STORED) ─────────────────────────
function buildZip(files: Record<string, string | Uint8Array>): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const cdEntries: Uint8Array[] = [];
  let offset = 0;

  for (const [name, content] of Object.entries(files)) {
    const nameBytes = enc.encode(name);
    const data = typeof content === "string" ? enc.encode(content) : content;
    const crc = crc32(data);
    const len = data.length;

    // Local file header (30 + nameLen bytes)
    const lfh = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(lfh.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, len, true);
    lv.setUint32(22, len, true);
    lv.setUint16(26, nameBytes.length, true);
    lfh.set(nameBytes, 30);

    parts.push(lfh, data);

    // Central directory entry (46 + nameLen bytes)
    const cde = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cde.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 63, true);
    cv.setUint16(6, 20, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, len, true);
    cv.setUint32(24, len, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    cde.set(nameBytes, 46);
    cdEntries.push(cde);

    offset += lfh.length + len;
  }

  const cdStart = offset;
  const cdSize = cdEntries.reduce((s, b) => s + b.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, cdEntries.length, true);
  ev.setUint16(10, cdEntries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, cdStart, true);

  const allParts = [...parts, ...cdEntries, eocd];
  const total = allParts.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const b of allParts) {
    out.set(b, pos);
    pos += b.length;
  }
  return out;
}

// ── Apple pkpass generator ───────────────────────────────────────────────────
function generateApplePkpass(d: WalletPassData): Blob {
  const bg = d.backgroundColor ?? "#10b981";
  const toRgb = (hex: string) => {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgb(${r}, ${g}, ${b})`;
  };

  const passJson = JSON.stringify({
    formatVersion: 1,
    passTypeIdentifier: "pass.com.riwaqflow.ticket",
    serialNumber: d.ticketId,
    teamIdentifier: "RIWAQFLOWDEV",
    organizationName: d.societyName ?? "RiwaqFlow",
    description: d.eventName,
    logoText: "RiwaqFlow",
    foregroundColor: "rgb(255,255,255)",
    backgroundColor: toRgb(bg),
    labelColor: "rgb(255,255,255,0.75)",
    eventTicket: {
      headerFields: [{ key: "type", label: "TYPE", value: d.ticketType }],
      primaryFields: [{ key: "event", label: "EVENT", value: d.eventName }],
      secondaryFields: [
        { key: "holder", label: "NAME", value: d.holderName },
        { key: "seat", label: "SEAT", value: d.seat ?? "—" },
      ],
      auxiliaryFields: [
        { key: "venue", label: "VENUE", value: d.venueName },
        {
          key: "date",
          label: "DATE",
          value: new Date(d.eventDate).toLocaleString("en-PK", {
            month: "short",
            day: "numeric",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          }),
        },
      ],
      backFields: [{ key: "id", label: "TICKET ID", value: d.ticketId }],
    },
    barcode: {
      message: d.qrValue,
      format: "PKBarcodeFormatQR",
      messageEncoding: "iso-8859-1",
      altText: d.ticketId,
    },
  });

  const enc = new TextEncoder();
  const passBytes = enc.encode(passJson);
  // SHA-1 hex of pass.json (SubtleCrypto is async; we approximate with a checksum string here)
  const passHash = Array.from(passBytes)
    .reduce((h, b) => (h * 31 + b) >>> 0, 0)
    .toString(16)
    .padStart(8, "0")
    .repeat(5); // 40-char pseudo-hash

  const manifest = JSON.stringify({ "pass.json": passHash });
  const zipBytes = buildZip({
    "pass.json": passJson,
    "manifest.json": manifest,
    signature: "DEMO_UNSIGNED_PASS — for testing only",
  });
  return new Blob([zipBytes.buffer as ArrayBuffer], {
    type: "application/vnd.apple.pkpass",
  });
}

// ── Download helper ───────────────────────────────────────────────────────────
function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

// ── Base64URL helper (for Google Wallet JWT) ─────────────────────────────────
function b64url(s: string): string {
  return btoa(unescape(encodeURIComponent(s)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ── Google Wallet URL generator ──────────────────────────────────────────────
// Produces a "Save to Google Wallet" URL with an unsigned demo JWT payload.
// In production, the JWT must be RS256-signed by a Google service account.
function generateGoogleWalletUrl(d: WalletPassData): string {
  const issuerId = "3388000000022795088"; // demo issuer ID placeholder
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      iss: "riwaqflow-demo@riwaqflow.iam.gserviceaccount.com",
      aud: "google",
      typ: "savetowallet",
      iat: Math.floor(Date.now() / 1000),
      payload: {
        genericObjects: [
          {
            id: `${issuerId}.${d.ticketId.replace(/[^a-zA-Z0-9_.-]/g, "_")}`,
            classId: `${issuerId}.riwaqflow_event_ticket`,
            genericType: "GENERIC_TYPE_UNSPECIFIED",
            hexBackgroundColor: d.backgroundColor ?? "#10b981",
            logo: { sourceUri: { uri: "https://riwaqflow.app/logo.png" } },
            cardTitle: { defaultValue: { language: "en", value: "RiwaqFlow" } },
            header: { defaultValue: { language: "en", value: d.eventName } },
            subheader: {
              defaultValue: { language: "en", value: d.holderName },
            },
            textModulesData: [
              { header: "TYPE", body: d.ticketType, id: "type" },
              { header: "SEAT", body: d.seat ?? "—", id: "seat" },
              { header: "VENUE", body: d.venueName, id: "venue" },
            ],
            barcode: {
              type: "QR_CODE",
              value: d.qrValue,
              alternateText: d.ticketId,
            },
            validTimeInterval: {
              start: { date: new Date(d.eventDate).toISOString() },
            },
          },
        ],
      },
    }),
  );
  const demoSig = b64url("DEMO_UNSIGNED_PASS");
  const jwt = `${header}.${payload}.${demoSig}`;
  return `https://pay.google.com/gp/v/save/${jwt}`;
}

// ── Samsung Wallet URL generator ─────────────────────────────────────────────
function generateSamsungWalletUrl(d: WalletPassData): string {
  // Samsung Wallet uses a merchant-specific deeplink. Without a Partnership ID
  // we generate the standard web-to-wallet redirect URL with pass data encoded.
  const passData = b64url(
    JSON.stringify({
      partnerInfo: {
        serviceId: "riwaqflow_demo",
        appScheme: "riwaqflow://ticket",
      },
      card: {
        type: "ticket",
        title: d.eventName,
        subTitle: `${d.holderName} · ${d.ticketType}`,
        ticketNumber: d.ticketId,
        venue: d.venueName,
        date: new Date(d.eventDate).toLocaleString("en-PK", {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        }),
        seat: d.seat ?? "—",
        barcode: { type: "QR", value: d.qrValue },
        bgColor: d.backgroundColor ?? "#10b981",
      },
    }),
  );
  return `https://wallet.samsung.com/a2w/detail?cardData=${passData}&serviceId=riwaqflow_demo`;
}

// ── Brand-accurate Apple logo ────────────────────────────────────────────────
function AppleLogo({ className }: { className?: string }) {
  return (
    <svg
      role="img"
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701" />
    </svg>
  );
}

// ── Full-colour Google "G" logo ────────────────────────────────────────────────
function GoogleLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true">
      <path
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
        fill="#4285F4"
      />
      <path
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
        fill="#34A853"
      />
      <path
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
        fill="#FBBC05"
      />
      <path
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
        fill="#EA4335"
      />
    </svg>
  );
}

// ── Samsung Wallet app icon ──────────────────────────────────────────────────
function SamsungLogo({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id="samsung-wallet-bg"
          x1="0"
          y1="0"
          x2="24"
          y2="24"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#1C40A6" />
          <stop offset="1" stopColor="#0A184A" />
        </linearGradient>
      </defs>
      {/* App Icon Background */}
      <rect width="24" height="24" rx="5" fill="url(#samsung-wallet-bg)" />

      {/* Cards stack */}
      <rect x="4.5" y="5.5" width="15" height="9" rx="1.5" fill="#122A70" />
      <rect x="4.5" y="8" width="15" height="9" rx="1.5" fill="#2450D6" />
      <rect x="4.5" y="10.5" width="15" height="9" rx="1.5" fill="#4B7BFF" />

      {/* Fine card details */}
      <path
        d="M6.5 13.5 h2.5"
        stroke="#A8C1FF"
        strokeWidth="1"
        strokeLinecap="round"
      />
      <circle cx="16" cy="14.5" r="1" fill="#A8C1FF" />
      <circle cx="13" cy="14.5" r="1" fill="#A8C1FF" opacity="0.6" />
    </svg>
  );
}

// ── Individual wallet buttons ─────────────────────────────────────────────────

interface AppleProps {
  url?: string | null;
  passData?: WalletPassData;
}
export function AppleWalletButton({ url, passData }: AppleProps) {
  const [busy, setBusy] = useState(false);

  const handleClick = async () => {
    if (url) {
      window.open(url, "_blank");
      return;
    }
    if (passData) {
      setBusy(true);
      try {
        const blob = generateApplePkpass(passData);
        const safeName = passData.eventName
          .replace(/[^a-z0-9]/gi, "_")
          .slice(0, 30);
        triggerDownload(blob, `${safeName}_ticket.pkpass`);
      } finally {
        setBusy(false);
      }
      return;
    }
  };

  const isDemo = !url && !passData;

  return (
    <motion.button
      whileHover={{ scale: 1.025, boxShadow: "0 8px 32px rgba(0,0,0,0.45)" }}
      whileTap={{ scale: 0.97 }}
      onClick={() => void handleClick()}
      disabled={busy || isDemo}
      className="flex items-center gap-3 w-full rounded-2xl py-3.5 px-5 font-semibold text-sm transition-all select-none disabled:opacity-40 disabled:cursor-not-allowed"
      style={{
        background: "linear-gradient(135deg,#1a1a1a 0%,#0a0a0a 100%)",
        color: "white",
        border: "1px solid rgba(255,255,255,0.12)",
      }}
      aria-label="Add to Apple Wallet"
    >
      {busy ? (
        <Loader2 className="w-5 h-5 flex-shrink-0 animate-spin" />
      ) : (
        <AppleLogo className="w-5 h-6 flex-shrink-0" />
      )}
      <div className="flex flex-col items-start leading-none">
        <span className="text-[9px] font-light opacity-65 tracking-widest uppercase mb-0.5">
          Add to
        </span>
        <span className="text-[13px] font-bold tracking-tight">
          Apple Wallet
        </span>
      </div>
      {passData && !url && (
        <span className="ml-auto text-[9px] opacity-55 font-medium text-emerald-400">
          ↓ download
        </span>
      )}
    </motion.button>
  );
}

interface GoogleProps {
  url?: string | null;
  passData?: WalletPassData;
}
export function GoogleWalletButton({ url, passData }: GoogleProps) {
  const resolvedUrl =
    url ?? (passData ? generateGoogleWalletUrl(passData) : null);

  const handleClick = () => {
    if (resolvedUrl) {
      window.open(resolvedUrl, "_blank");
    }
  };

  const isDemo = !url && !passData;

  return (
    <motion.button
      whileHover={{
        scale: 1.025,
        boxShadow: "0 8px 32px rgba(66,133,244,0.25)",
      }}
      whileTap={{ scale: 0.97 }}
      onClick={handleClick}
      disabled={isDemo}
      className="flex items-center gap-3 w-full rounded-2xl py-3.5 px-5 font-semibold text-sm transition-all select-none disabled:opacity-40 disabled:cursor-not-allowed"
      style={{
        background: "linear-gradient(135deg,#1e2433 0%,#131926 100%)",
        color: "white",
        border: "1px solid rgba(66,133,244,0.3)",
      }}
      aria-label="Save to Google Wallet"
    >
      <GoogleLogo className="w-5 h-5 flex-shrink-0" />
      <div className="flex flex-col items-start leading-none">
        <span className="text-[9px] font-light opacity-65 tracking-widest uppercase mb-0.5">
          Save to
        </span>
        <span className="text-[13px] font-bold tracking-tight">
          Google Wallet
        </span>
      </div>
      {passData && !url && (
        <span className="ml-auto text-[9px] opacity-55 font-medium text-blue-400">
          ↗ open
        </span>
      )}
    </motion.button>
  );
}

interface SamsungProps {
  url?: string | null;
  passData?: WalletPassData;
}
export function SamsungWalletButton({ url, passData }: SamsungProps) {
  const resolvedUrl =
    url ?? (passData ? generateSamsungWalletUrl(passData) : null);

  const handleClick = () => {
    if (resolvedUrl) {
      window.open(resolvedUrl, "_blank");
    }
  };

  const isDemo = !url && !passData;

  return (
    <motion.button
      whileHover={{ scale: 1.025, boxShadow: "0 8px 32px rgba(20,40,160,0.4)" }}
      whileTap={{ scale: 0.97 }}
      onClick={handleClick}
      disabled={isDemo}
      className="flex items-center gap-3 w-full rounded-2xl py-3.5 px-5 font-semibold text-sm transition-all select-none disabled:opacity-40 disabled:cursor-not-allowed"
      style={{
        background: "linear-gradient(135deg,#1428A0 0%,#0d1c75 100%)",
        color: "white",
        border: "1px solid rgba(255,255,255,0.12)",
      }}
      aria-label="Add to Samsung Wallet"
    >
      <SamsungLogo className="w-5 h-5 flex-shrink-0" />
      <div className="flex flex-col items-start leading-none">
        <span className="text-[9px] font-light opacity-65 tracking-widest uppercase mb-0.5">
          Add to
        </span>
        <span className="text-[13px] font-bold tracking-tight">
          Samsung Wallet
        </span>
      </div>
      {passData && !url && (
        <span className="ml-auto text-[9px] opacity-55 font-medium text-blue-300">
          ↗ open
        </span>
      )}
    </motion.button>
  );
}

// ── Grouped wallet section ────────────────────────────────────────────────────

export function UniversalWalletGroup({
  appleUrl,
  googleUrl,
  samsungUrl,
  passData,
  message,
}: {
  appleUrl?: string | null;
  googleUrl?: string | null;
  samsungUrl?: string | null;
  passData?: WalletPassData;
  message?: string;
}) {
  const hasData = !!(appleUrl || googleUrl || samsungUrl || passData);
  return (
    <div className="flex flex-col gap-3 w-full mt-6 col-span-2">
      <div className="flex items-center gap-2 section-subtitle mb-1 justify-center border-t border-[var(--border)] pt-4">
        <WalletCards className="w-4 h-4" />
        <span className="text-xs uppercase tracking-wider font-bold">
          Save to Device Wallet
        </span>
      </div>
      <div className="flex flex-col gap-2.5 w-full">
        <AppleWalletButton url={appleUrl} passData={passData} />
        <GoogleWalletButton url={googleUrl} passData={passData} />
        <SamsungWalletButton url={samsungUrl} passData={passData} />
      </div>
      {message && (
        <p className="text-[10px] section-subtitle text-center mt-1">
          {message}
        </p>
      )}
      {passData && !appleUrl && (
        <p className="text-[10px] text-center opacity-50 mt-0.5 leading-relaxed">
          Apple → downloads a <code className="font-mono">.pkpass</code> file ·
          Google &amp; Samsung → open Wallet in-browser. Production passes are
          signed with real credentials after purchase.
        </p>
      )}
      {!hasData && (
        <p className="text-[10px] text-center opacity-40 mt-0.5">
          Wallet passes are generated after ticket purchase.
        </p>
      )}
    </div>
  );
}
