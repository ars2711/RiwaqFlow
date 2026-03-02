"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import BackButton from "@/app/back-button";
import { API_BASE } from "@/lib/api";
import { EventItem } from "@/lib/types";
import {
  CalendarRange,
  MapPin,
  Ticket,
  CreditCard,
  Banknote,
  SmartphoneNfc,
} from "lucide-react";

type PurchaseResult = {
  ticket_id: string;
  payment_id: string;
  amount_pkr: number;
  checkout_url: string;
  status: string;
};

export default function BuyEventTicketPage() {
  const params = useParams<{ eventId: string }>();
  const eventId = params.eventId;

  const [event, setEvent] = useState<EventItem | null>(null);
  const [form, setForm] = useState({
    holder_name: "",
    department: "",
    year: "",
    attendee_type: "student",
    interests: "",
    role: "Student",
    ticket_tier: "default",
    payer_name: "",
    payer_email: "",
    payment_method: "manual",
  });
  const [result, setResult] = useState<PurchaseResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const getGoogleMapsLink = () => {
    if (!event?.venue_lat || !event?.venue_lng) {
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(event?.venue || "")}`;
    }
    return `https://www.google.com/maps/dir/?api=1&destination=${event.venue_lat},${event.venue_lng}`;
  };

  const getCalendarLink = () => {
    if (!event) return "#";
    const start = new Date(event.starts_at)
      .toISOString()
      .replace(/-|:|\.\d+/g, "");
    const end = new Date(event.ends_at).toISOString().replace(/-|:|\.\d+/g, "");
    const url = new URL("https://calendar.google.com/calendar/render");
    url.searchParams.append("action", "TEMPLATE");
    url.searchParams.append("text", event.name);
    url.searchParams.append("dates", `${start}/${end}`);
    url.searchParams.append("details", event.description || "");
    url.searchParams.append("location", event.venue || "");
    return url.toString();
  };

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE}/events/`);
        if (!res.ok) return;
        const all: EventItem[] = await res.json();
        const found = all.find((e) => e.id === eventId) ?? null;
        setEvent(found);
        // Pre-fill tier based on current event tier
        if (found?.event_tier) {
          setForm((prev) => ({
            ...prev,
            ticket_tier: found.event_tier ?? "default",
          }));
        }
      } catch {
        // silently continue — form still works without event detail
      }
    };
    void load();
  }, [eventId]);

  const tierPrice = useMemo(() => {
    if (!event) return null;
    const tier = form.ticket_tier;
    if (tier === "early-bird") return event.early_bird_price_pkr;
    if (tier === "on-spot") return event.on_spot_price_pkr;
    return event.default_price_pkr;
  }, [event, form.ticket_tier]);

  const submitPurchase = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/public/purchase`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, event_id: eventId }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => null);
        throw new Error(payload?.detail || "Failed to purchase ticket");
      }
      const payload: PurchaseResult = await res.json();
      setResult(payload);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Purchase failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="app-shell p-6">
      <div className="max-w-2xl mx-auto space-y-4">
        <BackButton href="/calendar" label="Back to events" />

        {/* Event info card */}
        {event ? (
          <div className="glass-panel p-5 rounded-2xl">
            <div className="flex items-start gap-3">
              <div className="rounded-xl p-2 bg-[var(--primary-soft)] border border-[var(--border)] shrink-0">
                <Ticket className="w-6 h-6 text-[var(--primary)]" />
              </div>
              <div className="flex-1 min-w-0">
                <h1 className="section-title text-xl font-black">
                  {event.name}
                </h1>
                {event.society_name && (
                  <p className="text-sm section-subtitle mt-0.5">
                    {event.society_name}
                  </p>
                )}
                {event.description && (
                  <p className="text-sm section-subtitle mt-1">
                    {event.description}
                  </p>
                )}
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <a
                href={getCalendarLink()}
                target="_blank"
                rel="noopener noreferrer"
                className="glass-soft rounded-xl p-3 border border-[var(--border)] flex items-start gap-2 hover:bg-[var(--primary-soft)] transition-colors cursor-pointer group"
                title="Add to Google Calendar"
              >
                <CalendarRange className="w-4 h-4 text-[var(--primary)] mt-0.5 shrink-0 group-hover:scale-110 transition-transform" />
                <div>
                  <p className="font-semibold group-hover:text-[var(--primary)] transition-colors">
                    Date & time
                  </p>
                  <p className="section-subtitle text-xs mt-0.5">
                    {new Date(event.starts_at).toLocaleString("en-PK", {
                      day: "numeric",
                      month: "long",
                      year: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </p>
                  <p className="section-subtitle text-xs">
                    Ends:{" "}
                    {new Date(event.ends_at).toLocaleString("en-PK", {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </p>
                </div>
              </a>

              <a
                href={getGoogleMapsLink()}
                target="_blank"
                rel="noopener noreferrer"
                className="glass-soft rounded-xl p-3 border border-[var(--border)] flex items-start gap-2 hover:bg-[var(--primary-soft)] transition-colors cursor-pointer group"
                title="Get Directions"
              >
                <MapPin className="w-4 h-4 text-[var(--primary)] mt-0.5 shrink-0 group-hover:scale-110 transition-transform" />
                <div>
                  <p className="font-semibold group-hover:text-[var(--primary)] transition-colors">
                    Venue
                  </p>
                  <p className="section-subtitle text-xs mt-0.5">
                    {event.venue}
                  </p>
                  {event.capacity && (
                    <p className="section-subtitle text-xs">
                      Capacity: {event.capacity.toLocaleString()}
                    </p>
                  )}
                </div>
              </a>
            </div>

            {/* Pricing */}
            <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
              {event.early_bird_price_pkr != null && (
                <div className="glass-soft rounded-lg p-2 border border-[var(--border)]">
                  <p className="font-bold">Early Bird</p>
                  <p className="section-subtitle">
                    PKR {event.early_bird_price_pkr}
                  </p>
                </div>
              )}
              {event.default_price_pkr != null && (
                <div className="glass-soft rounded-lg p-2 border border-[var(--primary)]/40 bg-[var(--primary-soft)]">
                  <p className="font-bold text-[var(--primary)]">Default</p>
                  <p className="section-subtitle">
                    PKR {event.default_price_pkr}
                  </p>
                </div>
              )}
              {event.on_spot_price_pkr != null && (
                <div className="glass-soft rounded-lg p-2 border border-[var(--border)]">
                  <p className="font-bold">On-Spot</p>
                  <p className="section-subtitle">
                    PKR {event.on_spot_price_pkr}
                  </p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="glass-panel p-5 rounded-2xl">
            <h1 className="section-title">Buy Ticket</h1>
            <p className="section-subtitle text-xs mt-1 font-mono">
              Event {eventId}
            </p>
          </div>
        )}

        {/* Purchase form */}
        <div className="glass-panel p-6 space-y-4 rounded-2xl">
          <h2 className="font-bold text-base">Attendee details</h2>
          <p className="section-subtitle text-sm -mt-2">
            Fill in your details and proceed to checkout. Ticket activates after
            payment confirmation.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <input
              className="field"
              placeholder="Full name *"
              value={form.holder_name}
              onChange={(e) =>
                setForm({ ...form, holder_name: e.target.value })
              }
            />
            <input
              className="field"
              placeholder="Department"
              value={form.department}
              onChange={(e) => setForm({ ...form, department: e.target.value })}
            />
            <input
              className="field"
              placeholder="Year (e.g. 2nd year)"
              value={form.year}
              onChange={(e) => setForm({ ...form, year: e.target.value })}
            />
            <select
              className="field"
              title="Attendee Type"
              aria-label="Attendee Type"
              value={form.attendee_type}
              onChange={(e) =>
                setForm({ ...form, attendee_type: e.target.value })
              }
            >
              <option value="student">Student</option>
              <option value="alumni">Alumni</option>
              <option value="faculty">Faculty</option>
              <option value="guest">Guest</option>
            </select>
            <input
              className="field md:col-span-2"
              placeholder="Interests (comma-separated)"
              value={form.interests}
              onChange={(e) => setForm({ ...form, interests: e.target.value })}
            />
          </div>

          <h2 className="font-bold text-base pt-1">Ticket & payment</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <select
              className="field"
              title="Ticket Tier"
              aria-label="Ticket Tier"
              value={form.ticket_tier}
              onChange={(e) =>
                setForm({ ...form, ticket_tier: e.target.value })
              }
            >
              <option value="early-bird">Early Bird</option>
              <option value="default">Default</option>
              <option value="on-spot">On-Spot</option>
            </select>

            <div className="md:col-span-2 space-y-2 mt-2">
              <label className="text-xs font-semibold text-[var(--fg-muted)] uppercase tracking-wider">
                Payment Method
              </label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {[
                  {
                    id: "manual",
                    label: "Cash",
                    icon: Banknote,
                    color: "text-emerald-500",
                  },
                  {
                    id: "card",
                    label: "Card",
                    icon: CreditCard,
                    color: "text-blue-500",
                  },
                  {
                    id: "easypaisa",
                    label: "Easypaisa",
                    icon: SmartphoneNfc,
                    color: "text-green-500",
                  },
                  {
                    id: "jazzcash",
                    label: "JazzCash",
                    icon: SmartphoneNfc,
                    color: "text-orange-500",
                  },
                ].map((method) => {
                  const Icon = method.icon;
                  const isActive = form.payment_method === method.id;
                  return (
                    <button
                      key={method.id}
                      type="button"
                      onClick={() =>
                        setForm({ ...form, payment_method: method.id })
                      }
                      className={`flex flex-col items-center justify-center gap-2 p-3 rounded-xl border transition-all ${
                        isActive
                          ? "bg-[var(--primary)]/10 border-[var(--primary)] ring-1 ring-[var(--primary)]/30"
                          : "bg-[var(--fg)]/5 border-[var(--border)] hover:bg-[var(--fg)]/10"
                      }`}
                    >
                      <Icon
                        className={`w-6 h-6 ${isActive ? "text-[var(--primary)]" : method.color}`}
                      />
                      <span
                        className={`text-xs font-bold ${isActive ? "text-[var(--primary)]" : "text-[var(--fg-muted)]"}`}
                      >
                        {method.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            <input
              className="field mt-2"
              placeholder="Payer name"
              value={form.payer_name}
              onChange={(e) => setForm({ ...form, payer_name: e.target.value })}
            />
            <input
              className="field"
              placeholder="Payer email"
              value={form.payer_email}
              onChange={(e) =>
                setForm({ ...form, payer_email: e.target.value })
              }
            />
          </div>

          {tierPrice != null && (
            <p className="text-sm font-semibold text-[var(--primary)]">
              Selected tier price: PKR {tierPrice}
            </p>
          )}

          <button
            className="btn-primary w-full py-2.5 font-bold"
            onClick={() => void submitPurchase()}
            disabled={submitting || !form.holder_name.trim()}
          >
            {submitting ? "Processing…" : "Buy Ticket →"}
          </button>

          {error && <p className="text-sm text-red-500">{error}</p>}

          {result && (
            <div className="glass-soft border border-[var(--border)] rounded-xl p-4 space-y-2">
              <p className="font-semibold text-emerald-400">
                ✓ Ticket purchase initiated
              </p>
              <p className="text-sm section-subtitle">
                Ticket ID:{" "}
                <a
                  href={`/ticket/${result.ticket_id}`}
                  className="text-[var(--primary)] underline"
                >
                  {result.ticket_id}
                </a>
              </p>
              <p className="text-sm section-subtitle">
                Amount: PKR {result.amount_pkr}
              </p>
              <p className="text-sm section-subtitle">
                Status: {result.status}
              </p>
              <div className="flex gap-2 flex-wrap pt-1">
                <a
                  href={result.checkout_url}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-primary px-4 py-2 text-sm"
                >
                  Continue to Checkout →
                </a>
                <a
                  href={`/ticket/${result.ticket_id}`}
                  className="btn-secondary px-4 py-2 text-sm"
                >
                  View ticket
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
