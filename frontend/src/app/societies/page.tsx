"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import BackButton from "@/app/back-button";
import { API_BASE } from "@/lib/api";
import { EventItem } from "@/lib/types";
import {
  Building2,
  Search,
  Ticket,
  Users,
  Landmark,
  User,
  Plus,
  Minus
} from "lucide-react";

type SocietyGroup = {
  name: string;
  organizer_type: "society" | "department" | "individual";
  events: EventItem[];
  upcomingCount: number;
  totalCapacity: number;
};

function groupBySociety(events: EventItem[]): SocietyGroup[] {
  const now = new Date();
  const map = new Map<string, { type: string; events: EventItem[] }>();

  for (const event of events) {
    const name =
      event.society_name?.trim() ||
      event.host_department?.trim() ||
      event.organizer_name?.trim() ||
      "Independent Organiser";
    const type = event.organizer_type ?? "individual";

    if (!map.has(name)) map.set(name, { type, events: [] });
    map.get(name)!.events.push(event);
  }

  return Array.from(map.entries())
    .map(([name, { type, events: evts }]) => ({
      name,
      organizer_type: type as "society" | "department" | "individual",
      events: evts,
      upcomingCount: evts.filter((e) => new Date(e.ends_at) >= now).length,
      totalCapacity: evts.reduce((s, e) => s + (e.capacity ?? 0), 0),
    }))
    .sort((a, b) => b.events.length - a.events.length);
}

const TYPE_LABELS: Record<string, string> = {
  society: "SOCIETY",
  department: "DEPARTMENT",
  individual: "INDIVIDUAL",
};

export default function SocietiesPage() {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "society" | "department" | "individual">("all");
  const [loading, setLoading] = useState(true);
  const [expandedSociety, setExpandedSociety] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${API_BASE}/events/`);
        if (res.ok) {
          const data: EventItem[] = await res.json();
          setEvents(data);
        }
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const groups = useMemo(() => groupBySociety(events), [events]);

  const filtered = useMemo(() => {
    return groups.filter((g) => {
      const matchesQ = g.name.toLowerCase().includes(query.toLowerCase());
      const matchesT = filter === "all" || g.organizer_type === filter;
      return matchesQ && matchesT;
    });
  }, [groups, query, filter]);

  const stats = useMemo(
    () => ({
      societies: groups.filter((g) => g.organizer_type === "society").length,
      departments: groups.filter((g) => g.organizer_type === "department").length,
      individuals: groups.filter((g) => g.organizer_type === "individual").length,
    }),
    [groups],
  );

  return (
    <div className="app-shell">
      <div className="wrap py-10">
        <BackButton href="/" label="Back to Home" />

        <div className="my-8">
          <div className="eyebrow">
            <span className="line"></span> Directory
          </div>
          <h1 className="section-title">Societies & Organisers</h1>
          <p className="section-subtitle mt-4 max-w-2xl">
            Browse every society, department, and individual organiser running
            events on Riwaq.
          </p>

          <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6">
              <div className="flex items-center gap-3 mb-2">
                <Users className="w-4 h-4 text-[var(--verified)]" />
                <p className="text-[11px] uppercase tracking-widest font-mono text-[var(--muted)]">Societies</p>
              </div>
              <p className="text-3xl font-mono">{stats.societies}</p>
            </div>
            
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6">
              <div className="flex items-center gap-3 mb-2">
                <Landmark className="w-4 h-4 text-[var(--brass)]" />
                <p className="text-[11px] uppercase tracking-widest font-mono text-[var(--muted)]">Departments</p>
              </div>
              <p className="text-3xl font-mono">{stats.departments}</p>
            </div>
            
            <div className="border border-[var(--border)] bg-[var(--surface)] p-6">
              <div className="flex items-center gap-3 mb-2">
                <User className="w-4 h-4 text-[var(--verified)]" />
                <p className="text-[11px] uppercase tracking-widest font-mono text-[var(--muted)]">Individuals</p>
              </div>
              <p className="text-3xl font-mono">{stats.individuals}</p>
            </div>
          </div>

          <div className="mt-8 flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
              <input
                className="field pl-9 w-full"
                placeholder="Search organisers..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <select
              title="Filter by organiser type"
              className="select sm:w-48 text-sm"
              value={filter}
              onChange={(e) => setFilter(e.target.value as typeof filter)}
            >
              <option value="all">All types</option>
              <option value="society">Societies</option>
              <option value="department">Departments</option>
              <option value="individual">Individuals</option>
            </select>
          </div>
        </div>

        {/* Grid */}
        {loading ? (
          <div className="border border-[var(--border)] p-10 text-center font-mono text-sm uppercase tracking-widest">
            Loading directory...
          </div>
        ) : filtered.length === 0 ? (
          <div className="border border-[var(--border)] p-10 text-center font-mono text-sm uppercase tracking-widest text-[var(--muted)]">
            No organisers found.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {filtered.map((group) => {
              const isExpanded = expandedSociety === group.name;
              return (
                <div
                  key={group.name}
                  className="border border-[var(--border)] bg-[var(--bg)]"
                >
                  <button
                    className="w-full p-5 text-left hover:bg-[var(--surface)] transition-colors"
                    onClick={() => setExpandedSociety(isExpanded ? null : group.name)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        {group.organizer_type === "society" ? (
                          <Building2 className="w-5 h-5 text-[var(--verified)] shrink-0" />
                        ) : group.organizer_type === "department" ? (
                          <Users className="w-5 h-5 text-[var(--brass)] shrink-0" />
                        ) : (
                          <Ticket className="w-5 h-5 text-[var(--verified)] shrink-0" />
                        )}
                        <h3 className="font-display font-medium text-lg leading-tight">
                          {group.name}
                        </h3>
                      </div>
                      {isExpanded ? (
                        <Minus className="w-4 h-4 text-[var(--muted)] shrink-0 mt-1" />
                      ) : (
                        <Plus className="w-4 h-4 text-[var(--muted)] shrink-0 mt-1" />
                      )}
                    </div>

                    <div className="mt-4 flex items-center gap-2">
                      <span className="text-[10px] font-mono tracking-widest uppercase text-[var(--muted)] border border-[var(--border)] px-2 py-1">
                        {TYPE_LABELS[group.organizer_type]}
                      </span>
                      <span className="text-[10px] font-mono tracking-widest uppercase text-[var(--muted)] border border-[var(--border)] px-2 py-1">
                        {group.events.length} EVENTS
                      </span>
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="border-t border-[var(--border)] bg-[var(--surface)]">
                      {group.events.map((event) => {
                        const upcoming = new Date(event.ends_at) >= new Date();
                        return (
                          <div
                            key={event.id}
                            className="flex items-center justify-between p-4 border-b border-[var(--border)] last:border-0"
                          >
                            <div>
                              <p className="font-medium text-sm mb-1">{event.name}</p>
                              <div className="text-[10px] font-mono uppercase text-[var(--muted)] flex gap-2">
                                <span>{event.venue}</span>
                                <span>•</span>
                                <span>
                                  {new Date(event.starts_at).toLocaleDateString("en-PK", {
                                    day: "numeric", month: "short", year: "numeric"
                                  })}
                                </span>
                              </div>
                            </div>
                            {upcoming ? (
                              <Link
                                href={`/buy/${event.id}`}
                                className="text-[10px] font-mono font-bold uppercase border border-[var(--border)] px-3 py-1 hover:border-[var(--verified)] hover:text-[var(--verified)] transition-colors"
                              >
                                BUY
                              </Link>
                            ) : (
                              <span className="text-[10px] font-mono uppercase text-[var(--muted)] italic">
                                PAST
                              </span>
                            )}
                          </div>
                        );
                      })}
                      <Link
                        href={`/calendar?q=${encodeURIComponent(group.name)}`}
                        className="block w-full p-3 text-center text-[10px] font-mono uppercase tracking-widest border-t border-[var(--border)] hover:bg-[var(--surface-2)] transition-colors"
                      >
                        View in Calendar
                      </Link>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
