"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  ArrowRight,
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

const APP_SECTIONS = [
  {
    href: "/calendar",
    icon: Globe2,
    label: "Explore",
    desc: "Events near you, live calendar, filters by society, department, tier, and venue.",
    color: "text-[var(--primary)]",
  },
  {
    href: "/map",
    icon: Map,
    label: "Map",
    desc: "Campus venue heat-overview, live occupancy visualisation, and coordinate-based event plotting.",
    color: "text-cyan-400",
  },
  {
    href: "/ticket/preview",
    icon: Ticket,
    label: "Tickets",
    desc: "Your QR pass with rotating 30-second token, wallet links, and offline cached viewing.",
    color: "text-emerald-400",
  },
  {
    href: "/societies",
    icon: Building2,
    label: "Societies",
    desc: "Society hubs — browse organisers, their upcoming events, and quick-buy links.",
    color: "text-violet-400",
  },
  {
    href: "/network",
    icon: Users,
    label: "Network",
    desc: "Attendee profiles, connection requests, interest matching, and direct messages.",
    color: "text-amber-400",
  },
  {
    href: "/admin",
    icon: BarChart3,
    label: "Dashboard",
    desc: "Organiser control room — stats, ticket creation, scanner setup, payment tracking.",
    color: "text-rose-400",
  },
];

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
    <div className="app-shell relative overflow-hidden">
      <motion.div
        animate={{ scale: [1, 1.1, 1], opacity: [0.5, 0.7, 0.5] }}
        transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
        className="pulse-orb h-64 w-64 left-[-3rem] top-[2rem] bg-blue-500/60"
      />
      <motion.div
        animate={{ scale: [1, 1.2, 1], opacity: [0.4, 0.6, 0.4] }}
        transition={{
          duration: 15,
          repeat: Infinity,
          ease: "easeInOut",
          delay: 2,
        }}
        className="pulse-orb h-56 w-56 right-[-3rem] top-[20rem] bg-cyan-400/50"
      />

      <div className="mx-auto max-w-6xl py-10 lg:py-16 space-y-10">
        {/* ── Hero ─────────────────────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="glass-panel relative overflow-hidden p-6 sm:p-10"
        >
          <div className="absolute inset-0 opacity-60 pointer-events-none bg-[radial-gradient(circle_at_10%_15%,rgba(109,141,255,0.22),transparent_45%)]" />
          <div className="relative z-10 text-center">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 200, delay: 0.2 }}
              className="mx-auto mb-5 flex justify-center"
            >
              <div className="rounded-3xl p-4 bg-[var(--primary-soft)] border border-[var(--border)] shadow-xl shadow-blue-500/20">
                <RiwaqLogo className="w-14 h-14" />
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4, staggerChildren: 0.1 }}
              className="mb-4 flex flex-wrap justify-center gap-2"
            >
              {[
                "Society-first platform",
                "NUST campus events",
                "Secure e-ticketing",
                "Live campus intelligence",
              ].map((tag, i) => (
                <motion.span
                  key={tag}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.5 + i * 0.1 }}
                  className="chip"
                >
                  {tag}
                </motion.span>
              ))}
            </motion.div>

            <h1 className="section-title text-4xl sm:text-5xl font-black flex items-center justify-center gap-3">
              Riwaq <span className="opacity-80 mt-1">رواق</span>
            </h1>
            <p className="section-subtitle mx-auto mt-2 text-base italic opacity-70">
              From gatherings to flow
            </p>
            <p className="section-subtitle mx-auto mt-4 max-w-3xl text-base sm:text-lg">
              A live digital layer over campus life — showing what&apos;s
              happening, where it&apos;s happening, how crowded it is, and
              getting you in with secure tickets and venue navigation.
            </p>

            {promptEvent && (
              <button
                onClick={async () => {
                  await promptEvent.prompt();
                  await promptEvent.userChoice;
                  setPromptEvent(null);
                }}
                className="btn-secondary mt-5 px-5 py-2 text-sm inline-flex items-center gap-2"
              >
                <Download className="w-4 h-4" /> Add to Home Screen
              </button>
            )}
          </div>
        </motion.div>
        {/* ── App Sections ─────────────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
        >
          <h2 className="text-xl font-bold px-1 mb-4">App sections</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {APP_SECTIONS.map((section, i) => {
              const Icon = section.icon;
              return (
                <motion.div
                  key={section.href}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.1 }}
                >
                  <Link
                    href={section.href}
                    className="block group glass-panel rounded-2xl border border-[var(--border)] p-5 text-left hover:border-[var(--primary)] transition-colors h-full"
                  >
                    <div className="flex items-center justify-between">
                      <Icon className={`w-7 h-7 ${section.color}`} />
                      <ArrowRight className="w-5 h-5 opacity-0 -translate-x-3 group-hover:opacity-60 group-hover:translate-x-0 transition-all" />
                    </div>
                    <h3 className="mt-3 text-lg font-extrabold">
                      {section.label}
                    </h3>
                    <p className="mt-1 text-sm section-subtitle">
                      {section.desc}
                    </p>
                  </Link>
                </motion.div>
              );
            })}
          </div>
        </motion.div>

        {/* ── Feature List ─────────────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
        >
          <h2 className="text-xl font-bold px-1 mb-1">Platform features</h2>
          <p className="section-subtitle px-1 mb-4 text-sm">
            Everything that is live in this build today.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {FEATURE_GROUPS.map((group, idx) => {
              const Icon = group.icon;
              return (
                <motion.div
                  key={group.title}
                  initial={{ opacity: 0, x: idx % 2 === 0 ? -20 : 20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: idx * 0.1 }}
                  className="glass-panel p-5 rounded-2xl"
                >
                  <div className="flex items-center gap-2 mb-3">
                    <Icon className="w-5 h-5 text-[var(--primary)]" />
                    <h3 className="font-bold text-base">{group.title}</h3>
                  </div>
                  <ul className="space-y-1.5">
                    {group.items.map((item) => (
                      <li
                        key={item}
                        className="flex items-start gap-2 text-sm section-subtitle"
                      >
                        <span className="mt-0.5 text-[var(--primary)] shrink-0">
                          ✓
                        </span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </motion.div>
              );
            })}
          </div>
        </motion.div>

        {/* ── Quick links ──────────────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="glass-panel p-5 rounded-2xl"
        >
          <h2 className="text-base font-bold mb-3">Quick links</h2>
          <div className="flex flex-wrap gap-3 text-sm">
            <Link
              href="/admin"
              className="btn-primary px-4 py-2 inline-flex items-center gap-2"
            >
              <BarChart3 className="w-4 h-4" /> Admin / Organiser dashboard
            </Link>
            <Link
              href="/scan"
              className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
            >
              <ScanLine className="w-4 h-4" /> Gate scanner
            </Link>
            <Link
              href="/calendar"
              className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
            >
              <CalendarRange className="w-4 h-4" /> Explore events
            </Link>
            <Link
              href="/map"
              className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
            >
              <Map className="w-4 h-4" /> Campus map
            </Link>
            <Link
              href="/societies"
              className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
            >
              <Building2 className="w-4 h-4" /> Societies
            </Link>
            <Link
              href="/network"
              className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
            >
              <Users className="w-4 h-4" /> Network
            </Link>
            <Link
              href="/pricing"
              className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
            >
              <Wallet className="w-4 h-4" /> Pricing
            </Link>
          </div>
          <p className="mt-4 text-xs section-subtitle">
            Secure QR scan verification over HTTPS. Screenshots expire due to
            rotating 30 s QR tokens.{" "}
            <Link href="/about-ticket" className="underline underline-offset-2">
              About tickets
            </Link>
            {" · "}
            <Link
              href="/privacy-policy"
              className="underline underline-offset-2"
            >
              Privacy policy
            </Link>
          </p>
        </motion.div>
      </div>
    </div>
  );
}
