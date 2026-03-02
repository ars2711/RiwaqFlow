"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import BackButton from "@/app/back-button";
import { API_BASE } from "@/lib/api";
import { EventItem } from "@/lib/types";
import {
  ArrowRight,
  Building2,
  CalendarRange,
  Search,
  Ticket,
  Users,
  Landmark,
  User,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

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
  society: "Society",
  department: "Department",
  individual: "Individual",
};

export default function SocietiesPage() {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<
    "all" | "society" | "department" | "individual"
  >("all");
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
      departments: groups.filter((g) => g.organizer_type === "department")
        .length,
      individuals: groups.filter((g) => g.organizer_type === "individual")
        .length,
    }),
    [groups],
  );

  return (
    <div className="app-shell p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="glass-panel p-6">
          <BackButton href="/" label="Back" />
          <h1 className="section-title mt-2">Societies & Organisers</h1>
          <p className="section-subtitle mt-2">
            Browse every society, department, and individual organiser running
            events on Riwaq. Tap a card to see their event listing.
          </p>

          <div className="mt-6 grid grid-cols-3 gap-3 md:gap-4">
            <div className="glass-soft rounded-2xl p-4 md:p-5 border border-[var(--border)] relative overflow-hidden group hover:border-[var(--primary)]/50 transition-colors">
              <div className="absolute right-[-10%] top-[-10%] opacity-5 group-hover:opacity-10 transition-opacity">
                <Users className="w-24 h-24 text-[var(--primary)]" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <Users className="w-4 h-4 text-[var(--primary)]" />
                <p className="text-xs uppercase tracking-wide font-bold section-subtitle">
                  Societies
                </p>
              </div>
              <p className="text-3xl font-black mt-1 text-[var(--primary)]">
                {stats.societies}
              </p>
            </div>
            <div className="glass-soft rounded-2xl p-4 md:p-5 border border-[var(--border)] relative overflow-hidden group hover:border-amber-500/50 transition-colors">
              <div className="absolute right-[-10%] top-[-10%] opacity-5 group-hover:opacity-10 transition-opacity">
                <Landmark className="w-24 h-24 text-amber-500" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <Landmark className="w-4 h-4 text-amber-500" />
                <p className="text-xs uppercase tracking-wide font-bold section-subtitle">
                  Departments
                </p>
              </div>
              <p className="text-3xl font-black mt-1 text-amber-500">
                {stats.departments}
              </p>
            </div>
            <div className="glass-soft rounded-2xl p-4 md:p-5 border border-[var(--border)] relative overflow-hidden group hover:border-emerald-500/50 transition-colors">
              <div className="absolute right-[-10%] top-[-10%] opacity-5 group-hover:opacity-10 transition-opacity">
                <User className="w-24 h-24 text-emerald-500" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <User className="w-4 h-4 text-emerald-500" />
                <p className="text-xs uppercase tracking-wide font-bold section-subtitle">
                  Individuals
                </p>
              </div>
              <p className="text-3xl font-black mt-1 text-emerald-500">
                {stats.individuals}
              </p>
            </div>
          </div>

          {/* Search + filter */}
          <div className="mt-4 flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
              <input
                className="field pl-9 w-full"
                placeholder="Search societies, departments, organisers..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <select
              title="Filter by organiser type"
              className="field sm:w-48"
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
          <div className="glass-panel p-10 text-center section-subtitle text-sm">
            Loading organisers…
          </div>
        ) : filtered.length === 0 ? (
          <div className="glass-panel p-10 text-center section-subtitle text-sm">
            No organisers found matching your search.
          </div>
        ) : (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"
          >
            <AnimatePresence>
              {filtered.map((group, _idx) => {
                const isExpanded = expandedSociety === group.name;
                return (
                  <motion.div
                    initial={{ opacity: 0, y: 30, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.9 }}
                    transition={{
                      delay: _idx * 0.05,
                      type: "spring",
                      stiffness: 200,
                      damping: 20,
                    }}
                    whileHover={{ scale: 1.02 }}
                    key={group.name}
                    className="glass-panel rounded-2xl border border-[var(--border)] overflow-hidden"
                  >
                    {/* Society header */}
                    <button
                      className="w-full p-5 text-left hover:bg-[var(--surface-strong)] transition-colors"
                      onClick={() =>
                        setExpandedSociety(isExpanded ? null : group.name)
                      }
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {group.organizer_type === "society" ? (
                            <Building2 className="w-5 h-5 text-violet-400 shrink-0" />
                          ) : group.organizer_type === "department" ? (
                            <Users className="w-5 h-5 text-amber-400 shrink-0" />
                          ) : (
                            <Ticket className="w-5 h-5 text-emerald-400 shrink-0" />
                          )}
                          <h3 className="font-extrabold text-base leading-tight">
                            {group.name}
                          </h3>
                        </div>
                        <ArrowRight
                          className={`w-4 h-4 opacity-50 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                        />
                      </div>

                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <span className="chip text-xs">
                          {TYPE_LABELS[group.organizer_type]}
                        </span>
                        <span className="chip text-xs">
                          {group.events.length} event
                          {group.events.length !== 1 ? "s" : ""}
                        </span>
                        {group.upcomingCount > 0 && (
                          <span className="chip text-xs bg-[var(--primary-soft)] text-[var(--primary)] border-[var(--primary)]/30">
                            {group.upcomingCount} upcoming
                          </span>
                        )}
                      </div>

                      {group.totalCapacity > 0 && (
                        <p className="text-xs section-subtitle mt-1">
                          Combined capacity:{" "}
                          {group.totalCapacity.toLocaleString()} seats
                        </p>
                      )}
                    </button>

                    {/* Expanded event list */}
                    {isExpanded && (
                      <div className="border-t border-[var(--border)] bg-[var(--surface-strong)] px-4 py-3 space-y-2">
                        {group.events.map((event) => {
                          const upcoming =
                            new Date(event.ends_at) >= new Date();
                          return (
                            <div
                              key={event.id}
                              className="flex items-start gap-3 glass-soft rounded-xl p-3 border border-[var(--border)]"
                            >
                              <CalendarRange className="w-4 h-4 mt-0.5 text-[var(--primary)] shrink-0" />
                              <div className="flex-1 min-w-0">
                                <p className="font-semibold text-sm truncate">
                                  {event.name}
                                </p>
                                <p className="text-xs section-subtitle">
                                  {event.venue}
                                </p>
                                <p className="text-xs section-subtitle">
                                  {new Date(event.starts_at).toLocaleDateString(
                                    "en-PK",
                                    {
                                      day: "numeric",
                                      month: "short",
                                      year: "numeric",
                                    },
                                  )}
                                </p>
                                {!upcoming && (
                                  <span className="text-[10px] section-subtitle italic">
                                    Past event
                                  </span>
                                )}
                              </div>
                              {upcoming && (
                                <Link
                                  href={`/buy/${event.id}`}
                                  className="btn-secondary text-xs px-2 py-1 shrink-0"
                                >
                                  Buy
                                </Link>
                              )}
                            </div>
                          );
                        })}

                        <Link
                          href={`/calendar?q=${encodeURIComponent(group.name)}`}
                          className="block text-center text-xs text-[var(--primary)] hover:underline mt-2 pb-1"
                        >
                          View all in calendar →
                        </Link>
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </motion.div>
        )}
      </div>
    </div>
  );
}
