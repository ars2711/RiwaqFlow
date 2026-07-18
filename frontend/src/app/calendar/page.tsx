"use client";

import { useEffect, useMemo, useState } from "react";
import BackButton from "@/app/back-button";
import { API_BASE, authHeaders } from "@/lib/api";
import { EventItem, VenueAnalyticsPoint } from "@/lib/types";
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
    <div className="app-shell">
      <div className="wrap py-10">
        <BackButton href="/" label="Back to Home" />

        <div className="my-8">
          <div className="eyebrow">
            <span className="line"></span> Discovery
          </div>
          <h1 className="section-title">NUST Event Calendar</h1>
          <p className="section-subtitle mt-4 max-w-2xl">
            Discover society, department, and individual events. Quick occupancy
            insights help security and attendees choose events.
          </p>
          <input
            title="Search events"
            placeholder="Search by event, society, department, or venue..."
            className="field mt-6 max-w-md"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>

        <div className="grid lg:grid-cols-12 gap-12 mt-12">
          {/* Main Events List */}
          <div className="lg:col-span-7">
            <div className="section-label mb-6">Upcoming</div>
            
            <div className="space-y-0">
              {filtered.map((event) => {
                const stat = stats[event.id] ?? {
                  issued: 0,
                  entries: 0,
                  exits: 0,
                };
                
                const d = new Date(event.starts_at);
                const day = d.getDate();
                const month = d.toLocaleString('default', { month: 'short' }).toUpperCase();

                const isLive = stat.entries > 0;

                return (
                  <div key={event.id} className="event-row">
                    <div className="ev-date">
                      <span className="big">{day}</span>
                      {month}
                    </div>
                    <div>
                      <div className="ev-title flex items-center gap-3">
                        {event.name}
                        {isLive && <span className="tag-live">Live</span>}
                      </div>
                      <div className="ev-meta flex flex-wrap gap-x-4 gap-y-1">
                        <span>{event.society_name ?? "Independent"}</span>
                        <span>{event.venue}</span>
                        <span>
                          Issued: {stat.issued} • In: {stat.entries}
                        </span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                       <a href={`/buy/${event.id}`} className="btn-secondary" style={{ padding: "8px 14px", fontSize: "11px" }}>
                         Get Ticket
                       </a>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Sidebar Analytics */}
          <div className="lg:col-span-5">
            <div className="section-label mb-6">Live Heatmap</div>
            
            <div className="border border-[var(--border)] bg-[var(--surface)] p-1 mb-6">
              <svg
                viewBox="0 0 100 100"
                className="w-full h-64 bg-[var(--surface-2)]"
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
                        fill="var(--verified)"
                        fillOpacity="0.4"
                      />
                      <circle
                        cx={point.x}
                        cy={point.y}
                        r={radius / 2}
                        fill="var(--verified)"
                      />
                      <text
                        x={point.x + 2}
                        y={point.y - 2}
                        fontSize="2.5"
                        fill="var(--text)"
                        fontFamily="var(--f-mono)"
                      >
                        {point.venue.slice(0, 14)}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            <div className="space-y-4">
              {venueAnalytics.map((point) => (
                <div
                  key={point.venue}
                  className="border-b border-[var(--border)] pb-4 last:border-0"
                >
                  <div className="flex justify-between items-baseline mb-1">
                    <span className="font-mono text-[13px] font-semibold">{point.venue}</span>
                    <span className="text-[11px] font-mono text-[var(--verified)]">
                      {point.total_entries} Active
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-[var(--muted)] flex justify-between">
                    <span>Events: {point.event_count}</span>
                    <span>Issued: {point.total_issued}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
