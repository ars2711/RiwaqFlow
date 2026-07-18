"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  BarChart3,
  Building2,
  CalendarRange,
  CreditCard,
  Download,
  Globe2,
  Map,
  MessageSquare,
  ScanLine,
  ShieldCheck,
  Smartphone,
  Ticket,
  Users,
  Wallet,
} from "lucide-react";

import { RiwaqLogo } from "@/components/ui/Logo";

type DeferredPrompt = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
};

const FEATURE_GROUPS = [
  {
    title: "E-Ticketing & Access Control",
    icon: Ticket,
    items: [
      "Rotating QR tokens (30 s expiry — anti-screenshot)",
      "Device-locked tickets via fingerprint on first open",
      "Entry / exit enforcement with server-side counters",
      "Re-entry logic (max 2 entries for non-OC; unlimited for OC)",
      "Ticket revoke, reissue, and bulk creation",
      "CSV import / export of attendee lists",
      "Offline ticket viewing (cached in localStorage)",
      "Apple / Google / Samsung Wallet link endpoints",
    ],
  },
  {
    title: "Admin, Roles & Organiser Model",
    icon: ShieldCheck,
    items: [
      "Super-admin + scoped society-manager accounts",
      "Manager TOTP 2FA enrolment and enforcement",
      "Plan-tier gates (Starter / Pro / Enterprise limits)",
      "Event fields: organiser type, tier, capacity, venue coords, payment & form URLs",
      "Admin filters by organiser type, event tier, and venue",
      "Calendar sync URL update endpoint per event",
    ],
  },
  {
    title: "Scanner Operations",
    icon: ScanLine,
    items: [
      "Event-scoped scanner login (code + allowlisted device ID)",
      "Offline scan queue via IndexedDB — auto-syncs on reconnect",
      "Live scan logs and event stats per gate",
      "Browser-based QR scanner (html5-qrcode)",
    ],
  },
  {
    title: "Payments & Purchase Flow",
    icon: CreditCard,
    items: [
      "Attendee purchase flow with early-bird / default / on-spot pricing",
      "Ticket starts as pending_payment; activates on webhook success",
      "Payment records API with checkout-link generation",
      "Local mock checkout simulator (/checkout/[id]) for webhook testing",
      "Easypaisa / JazzCash / card / manual payment method fields",
    ],
  },
  {
    title: "Live Map & Analytics",
    icon: Map,
    items: [
      "Venue analytics API (/analytics/venues) for map-ready occupancy aggregates",
      "Coordinate-based venue plot with occupancy heat radii",
      "Calendar / discovery page with capacity fill percentages",
      "Venue occupancy summary for security and attendees",
    ],
  },
  {
    title: "Social Networking",
    icon: MessageSquare,
    items: [
      "Attendee profile creation with department, year, interests, and bio",
      "People discovery with interest-tag frequency cloud",
      "Connection requests and accept / reject flow",
      "Direct messages per accepted connection",
    ],
  },
  {
    title: "UX & PWA",
    icon: Smartphone,
    items: [
      "Global dark / light theme toggle persisted in localStorage",
      "High-contrast alt mode for accessibility",
      "Installable PWA with offline support and service worker",
      "Add to Home Screen prompt handled natively",
      "Back-navigation buttons on every major page",
      "Screen wake-lock on ticket page to prevent dimming at gate",
    ],
  },
];

export default function Home() {
  const [promptEvent, setPromptEvent] = useState<DeferredPrompt | null>(null);

  useEffect(() => {
    const onBeforeInstallPrompt = (event: Event) => {
      event.preventDefault();
      setPromptEvent(event as DeferredPrompt);
    };
    window.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
    return () =>
      window.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
  }, []);

  return (
    <div className="app-shell relative">
      <div className="jali"></div>

      {/* ── Hero Section (v3) ────────────────────────────────────── */}
      <section className="hero">
        <div className="wrap">
          <div className="eyebrow">
            <span className="line"></span> NUST Campus
          </div>
          <h1>
            From gatherings <em>to flow</em>
          </h1>
          <p className="sub">
            A live digital layer over campus life — showing what's happening,
            where it's happening, how crowded it is, and getting you in with
            secure tickets and venue navigation.
          </p>

          <div className="hero-ctas">
            <Link href="/calendar" className="btn-primary">
              Explore Events
            </Link>
            {promptEvent ? (
              <button
                onClick={async () => {
                  await promptEvent.prompt();
                  await promptEvent.userChoice;
                  setPromptEvent(null);
                }}
                className="btn-secondary"
              >
                <Download className="w-4 h-4" /> Install App
              </button>
            ) : (
              <Link href="/ticket/preview" className="btn-secondary">
                Preview Ticket
              </Link>
            )}
          </div>

          <div className="stats-row mt-8">
            <div className="stat">
              <div className="num">42</div>
              <div className="label">SOCIETIES</div>
            </div>
            <div className="stat">
              <div className="num">12.5k</div>
              <div className="label">ATTENDEES</div>
            </div>
            <div className="stat">
              <div className="num">99.9%</div>
              <div className="label">UPTIME</div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Features Section (v3) ────────────────────────────────── */}
      <section className="section">
        <div className="wrap">
          <div className="section-label">Platform capabilities</div>
          <h2>Institutional core</h2>
          <p className="lead mb-12">
            Everything currently active in this build. Designed for scale, security, and flow.
          </p>

          <div className="feature-grid">
            {FEATURE_GROUPS.map((group, idx) => {
              const Icon = group.icon;
              return (
                <div key={idx} className="feature">
                  <div className="bx">
                    <div className="bracket tl"></div>
                    <div className="bracket tr"></div>
                    <div className="bracket bl"></div>
                    <div className="bracket br"></div>
                    <Icon strokeWidth={1.5} />
                  </div>
                  <h3>{group.title}</h3>
                  <div className="space-y-3 mt-3">
                    {group.items.map((item, i) => (
                      <p key={i} className="flex gap-2">
                        <span className="text-[var(--verified)] shrink-0">⌐</span>
                        <span>{item}</span>
                      </p>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── Quick Links Section (v3) ─────────────────────────────── */}
      <section className="section" style={{ borderBottom: "none" }}>
        <div className="wrap">
          <div className="section-label">Directory</div>
          <h2 className="mb-6">Navigation</h2>
          
          <div className="flex flex-wrap gap-4">
            <Link href="/admin" className="btn-secondary">
              <BarChart3 className="w-4 h-4" /> Dashboard
            </Link>
            <Link href="/scan" className="btn-ghost">
              <ScanLine className="w-4 h-4" /> Scanner
            </Link>
            <Link href="/map" className="btn-ghost">
              <Map className="w-4 h-4" /> Live Map
            </Link>
            <Link href="/societies" className="btn-ghost">
              <Building2 className="w-4 h-4" /> Societies
            </Link>
            <Link href="/network" className="btn-ghost">
              <Users className="w-4 h-4" /> Network
            </Link>
            <Link href="/pricing" className="btn-ghost">
              <Wallet className="w-4 h-4" /> Pricing
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
