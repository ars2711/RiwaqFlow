"use client";

import { useEffect, useMemo, useState } from "react";
import BackButton from "@/app/back-button";
import { API_BASE, authHeaders } from "@/lib/api";
import { EventItem, VenueAnalyticsPoint } from "@/lib/types";
import { motion } from "framer-motion";
import { CalendarPlus, ExternalLink } from "lucide-react";

type EventStats = { issued: number; entries: number; exits: number };

// ── Calendar utility helpers ──────────────────────────────────────────────

function formatDtUTC(dateStr: string): string {
  return (
    new Date(dateStr).toISOString().replace(/[-:.]/g, "").slice(0, 15) + "Z"
  );
}

function makeGoogleCalUrl(event: EventItem): string {
  const params = new URLSearchParams({
    action: "TEMPLATE",
    text: event.name,
    dates: `${formatDtUTC(event.starts_at)}/${formatDtUTC(event.ends_at)}`,
    details: `${event.society_name ?? "Independent"} event at NUST — Secure tickets at riwaq.app`,
    location: `${event.venue}, NUST H-12, Islamabad`,
  });
  return `https://www.google.com/calendar/render?${params.toString()}`;
}

function downloadIcal(event: EventItem): void {
  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Riwaq//NUST Events//EN",
    "BEGIN:VEVENT",
    `SUMMARY:${event.name}`,
    `DTSTART:${formatDtUTC(event.starts_at)}`,
    `DTEND:${formatDtUTC(event.ends_at)}`,
    `LOCATION:${event.venue}, NUST H-12, Islamabad`,
    `DESCRIPTION:${event.society_name ?? "Independent"} event at NUST. Secure tickets on Riwaq.`,
    `UID:riwaq-${event.id}@nust.edu.pk`,
    "END:VEVENT",
    "END:VCALENDAR",
  ];
  const blob = new Blob([lines.join("\r\n")], {
    type: "text/calendar;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${event.name.replace(/\s+/g, "-")}.ics`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function CalendarPage() {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [stats, setStats] = useState<Record<string, EventStats>>({});
  const [venueAnalytics, setVenueAnalytics] = useState<VenueAnalyticsPoint[]>(
    [],
  );
  const [query, setQuery] = useState("");

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE}/events/`);
        if (!res.ok) return;
        const data: EventItem[] = await res.json();
        setEvents(data);

        const allStats = await Promise.all(
          data.slice(0, 30).map(async (event) => {
            try {
              const statRes = await fetch(
                `${API_BASE}/event/${event.id}/stats`,
                { headers: { ...authHeaders() } },
              );
              if (!statRes.ok)
                return [event.id, { issued: 0, entries: 0, exits: 0 }] as const;
              const payload = (await statRes.json()) as EventStats;
              return [event.id, payload] as const;
            } catch {
              return [event.id, { issued: 0, entries: 0, exits: 0 }] as const;
            }
          }),
        );

        setStats(Object.fromEntries(allStats));

        try {
          const venueRes = await fetch(`${API_BASE}/analytics/venues`);
          if (venueRes.ok) {
            const points: VenueAnalyticsPoint[] = await venueRes.json();
            setVenueAnalytics(points);
          }
        } catch {
          /* venue analytics unavailable */
        }
      } catch {
        /* backend offline – render empty state */
      }
    };

    void load();
  }, []);

  const filtered = useMemo(() => {
    return events.filter((event) => {
      const haystack =
        `${event.name} ${event.society_name ?? ""} ${event.host_department ?? ""} ${event.venue}`.toLowerCase();
      return haystack.includes(query.toLowerCase());
    });
  }, [events, query]);

  const plottedPoints = useMemo(() => {
    const withCoords = venueAnalytics.filter(
      (point) => point.venue_lat && point.venue_lng,
    );
    if (withCoords.length === 0) return [];

    const lats = withCoords.map((point) => Number(point.venue_lat));
    const lngs = withCoords.map((point) => Number(point.venue_lng));
    const minLat = Math.min(...lats);
    const maxLat = Math.max(...lats);
    const minLng = Math.min(...lngs);
    const maxLng = Math.max(...lngs);

    return withCoords.map((point) => {
      const lat = Number(point.venue_lat);
      const lng = Number(point.venue_lng);
      const x =
        maxLng === minLng ? 50 : ((lng - minLng) / (maxLng - minLng)) * 100;
      const y =
        maxLat === minLat
          ? 50
          : 100 - ((lat - minLat) / (maxLat - minLat)) * 100;
      return { ...point, x, y };
    });
  }, [venueAnalytics]);

  const maxEntries = useMemo(
    () => Math.max(1, ...venueAnalytics.map((point) => point.total_entries)),
    [venueAnalytics],
  );

  return (
    <div className="app-shell p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="glass-panel p-6">
          <BackButton href="/" label="Back" />
          <h1 className="section-title">NUST Event Calendar & Capacity</h1>
          <p className="section-subtitle mt-2">
            Discover society, department, and individual events. Quick occupancy
            insights help security and attendees choose events.
          </p>
          <input
            title="Search events"
            placeholder="Search by event, society, department, or venue"
            className="field mt-4"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>

        <div className="grid lg:grid-cols-2 gap-4">
          <div className="glass-panel p-5">
            <h2 className="text-xl font-bold mb-3">Calendar list</h2>
            <div className="space-y-3 max-h-[32rem] overflow-auto">
              {filtered.map((event, _idx) => {
                const stat = stats[event.id] ?? {
                  issued: 0,
                  entries: 0,
                  exits: 0,
                };
                const capacity = event.capacity ?? 0;
                const fillPct =
                  capacity > 0
                    ? Math.min(100, Math.round((stat.entries / capacity) * 100))
                    : 0;
                return (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, x: -20 }}
                    transition={{ delay: _idx * 0.05 }}
                    whileHover={{ scale: 1.01 }}
                    key={event.id}
                    className="glass-soft border border-[var(--border)] rounded-xl p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-bold">{event.name}</p>
                      <span className="chip">
                        {event.organizer_type ?? "society"}
                      </span>
                    </div>
                    <p className="text-xs section-subtitle mt-1">
                      {event.society_name ?? "Independent"} • {event.venue}
                    </p>
                    <p className="text-xs section-subtitle">
                      {new Date(event.starts_at).toLocaleString()}
                    </p>
                    <p className="text-xs section-subtitle mt-1">
                      Issued: {stat.issued} • Inside/entered: {stat.entries} •
                      Exits: {stat.exits}
                    </p>
                    {capacity > 0 && (
                      <p className="text-xs section-subtitle">
                        Capacity: {capacity} • Fill: {fillPct}%
                      </p>
                    )}
                    <p className="text-xs section-subtitle mt-1">
                      Prices: Early Bird PKR {event.early_bird_price_pkr ?? "-"}{" "}
                      • Default PKR {event.default_price_pkr ?? "-"} • On-Spot
                      PKR {event.on_spot_price_pkr ?? "-"}
                    </p>
                    <div className="flex flex-wrap gap-2 mt-2">
                      <a
                        href={`/buy/${event.id}`}
                        className="btn-secondary inline-flex px-2 py-1 text-xs"
                      >
                        Buy Ticket
                      </a>
                      {/* ── Add to Calendar ── */}
                      <a
                        href={makeGoogleCalUrl(event)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-lg border border-[var(--border)] bg-[var(--surface-muted)] hover:bg-[var(--primary)]/10 hover:border-[var(--primary)]/40 transition-colors text-[var(--foreground)]"
                        title="Add to Google Calendar"
                      >
                        <ExternalLink className="w-3 h-3" />
                        Google Cal
                      </a>
                      <button
                        onClick={() => downloadIcal(event)}
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded-lg border border-[var(--border)] bg-[var(--surface-muted)] hover:bg-[var(--primary)]/10 hover:border-[var(--primary)]/40 transition-colors text-[var(--foreground)]"
                        title="Download iCal / Apple Calendar"
                      >
                        <CalendarPlus className="w-3 h-3" />
                        iCal
                      </button>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>

          <div className="glass-panel p-5">
            <h2 className="text-xl font-bold mb-3">
              Campus activity heat overview
            </h2>
            <p className="text-sm section-subtitle mb-3">
              Venue density is visualized below. Coordinates render on a
              campus-style plot where available.
            </p>
            <div className="glass-soft border border-[var(--border)] rounded-xl p-3 mb-3">
              <svg
                viewBox="0 0 100 100"
                className="w-full h-52 rounded-lg bg-[var(--surface-strong)]"
              >
                <rect x="0" y="0" width="100" height="100" fill="transparent" />
                {plottedPoints.map((point) => {
                  const radius = 2 + (point.total_entries / maxEntries) * 5;
                  return (
                    <g key={`plot-${point.venue}`}>
                      <circle
                        cx={point.x}
                        cy={point.y}
                        r={radius}
                        fill="var(--primary)"
                        fillOpacity="0.7"
                      />
                      <text
                        x={point.x + 1}
                        y={point.y - 1}
                        fontSize="2.8"
                        fill="var(--foreground)"
                      >
                        {point.venue.slice(0, 14)}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
            <div className="space-y-2">
              {venueAnalytics.map((point) => (
                <div
                  key={point.venue}
                  className="glass-soft rounded-lg p-3 border border-[var(--border)] flex items-center justify-between"
                >
                  <div>
                    <span className="text-sm font-semibold">{point.venue}</span>
                    <p className="text-xs section-subtitle">
                      Events: {point.event_count} • Issued: {point.total_issued}
                    </p>
                    {(point.venue_lat || point.venue_lng) && (
                      <p className="text-[10px] section-subtitle">
                        Lat/Lng: {point.venue_lat || "-"},{" "}
                        {point.venue_lng || "-"}
                      </p>
                    )}
                    {(() => {
                      const ratio = Math.min(
                        100,
                        (point.total_entries / maxEntries) * 100,
                      );
                      const widthClass =
                        ratio >= 90
                          ? "w-full"
                          : ratio >= 80
                            ? "w-10/12"
                            : ratio >= 70
                              ? "w-9/12"
                              : ratio >= 60
                                ? "w-8/12"
                                : ratio >= 50
                                  ? "w-7/12"
                                  : ratio >= 40
                                    ? "w-6/12"
                                    : ratio >= 30
                                      ? "w-5/12"
                                      : ratio >= 20
                                        ? "w-4/12"
                                        : ratio >= 10
                                          ? "w-3/12"
                                          : "w-2/12";
                      return (
                        <div className="mt-1 h-1.5 w-44 rounded-full bg-[var(--surface-strong)] border border-[var(--border)]">
                          <div
                            className={`h-full rounded-full bg-[var(--primary)] ${widthClass}`}
                          />
                        </div>
                      );
                    })()}
                  </div>
                  <span className="chip">
                    {point.total_entries} active entries
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
