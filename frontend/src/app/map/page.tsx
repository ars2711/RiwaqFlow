"use client";

import dynamic from "next/dynamic";
import { useEffect, useMemo, useState } from "react";
import BackButton from "@/app/back-button";
import { API_BASE } from "@/lib/api";
import { VenueAnalyticsPoint } from "@/lib/types";
import type { VenuePin } from "@/components/ui/LeafletMap";
import {
  AlertTriangle,
  Clock,
  Coffee,
  ExternalLink,
  MapPin,
  Navigation,
  Search,
  ShieldAlert,
  Users,
  Zap,
} from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";

// Load Leaflet map only on client (no SSR) — Leaflet requires window/document
const LeafletMap = dynamic(() => import("@/components/ui/LeafletMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full min-h-[60vh] lg:min-h-[80vh] rounded-3xl bg-[var(--foreground)]/5 border border-[var(--foreground)]/10 flex items-center justify-center">
      <div className="flex flex-col items-center gap-3 text-[var(--muted)]">
        <div className="w-8 h-8 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin" />
        <span className="text-sm font-medium">Loading NUST campus map…</span>
      </div>
    </div>
  ),
});

// ── NUST H-12 campus landmarks with real approximate coordinates ──────────
type Landmark = {
  id: string;
  name: string;
  lat: number;
  lng: number;
  x: number;
  y: number;
  type: "academic" | "food" | "residential" | "gate";
  baseCapacity: number;
};

const NUST_LANDMARKS: Landmark[] = [
  {
    id: "seecs",
    name: "SEECS",
    lat: 33.6448,
    lng: 72.9848,
    x: 250,
    y: 650,
    type: "academic",
    baseCapacity: 800,
  },
  {
    id: "nbs",
    name: "NBS",
    lat: 33.6402,
    lng: 72.9895,
    x: 750,
    y: 450,
    type: "academic",
    baseCapacity: 500,
  },
  {
    id: "s3h",
    name: "S3H",
    lat: 33.64,
    lng: 72.9902,
    x: 780,
    y: 350,
    type: "academic",
    baseCapacity: 400,
  },
  {
    id: "sada",
    name: "SADA",
    lat: 33.6428,
    lng: 72.986,
    x: 450,
    y: 350,
    type: "academic",
    baseCapacity: 300,
  },
  {
    id: "library",
    name: "Central Library",
    lat: 33.6424,
    lng: 72.9856,
    x: 500,
    y: 500,
    type: "academic",
    baseCapacity: 1000,
  },
  {
    id: "smme",
    name: "SMME",
    lat: 33.6456,
    lng: 72.9842,
    x: 300,
    y: 300,
    type: "academic",
    baseCapacity: 600,
  },
  {
    id: "scme",
    name: "SCME",
    lat: 33.6463,
    lng: 72.9854,
    x: 380,
    y: 250,
    type: "academic",
    baseCapacity: 450,
  },
  {
    id: "c1",
    name: "C1 Cafeteria",
    lat: 33.6415,
    lng: 72.9858,
    x: 600,
    y: 750,
    type: "food",
    baseCapacity: 200,
  },
  {
    id: "c2",
    name: "C2 Cafeteria",
    lat: 33.6442,
    lng: 72.9848,
    x: 300,
    y: 450,
    type: "food",
    baseCapacity: 150,
  },
  {
    id: "nstp",
    name: "NSTP",
    lat: 33.6386,
    lng: 72.993,
    x: 800,
    y: 800,
    type: "academic",
    baseCapacity: 1200,
  },
  {
    id: "hostels",
    name: "Hostels Area",
    lat: 33.6478,
    lng: 72.9825,
    x: 150,
    y: 150,
    type: "residential",
    baseCapacity: 2500,
  },
  {
    id: "gate1",
    name: "Gate 1 (Main)",
    lat: 33.6422,
    lng: 72.995,
    x: 920,
    y: 920,
    type: "gate",
    baseCapacity: 100,
  },
];

export default function MapPage() {
  const [apiVenues, setApiVenues] = useState<VenueAnalyticsPoint[]>([]);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [timeOffset, setTimeOffset] = useState<number>(0);
  const [showHeatmap, setShowHeatmap] = useState(true);
  const [activeRoute, setActiveRoute] = useState<{
    from: string;
    to: string;
  } | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [poiType, setPoiType] = useState<Landmark["type"] | null>(null);
  const [userLat, setUserLat] = useState<number | undefined>();
  const [userLng, setUserLng] = useState<number | undefined>();
  const [apiStatus, setApiStatus] = useState<"live" | "fallback">("fallback");
  const [fetchError, setFetchError] = useState<string | null>(null);

  const isLiveTime = timeOffset === 0;

  useEffect(() => {
    if (typeof window === "undefined" || !("geolocation" in navigator)) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setUserLat(pos.coords.latitude);
        setUserLng(pos.coords.longitude);
      },
      () => {
        setUserLat(33.643);
        setUserLng(72.9858);
      },
      { enableHighAccuracy: true, timeout: 6000 },
    );
  }, []);

  useEffect(() => {
    const controller = new AbortController();

    const load = async () => {
      try {
        const res = await fetch(`${API_BASE}/analytics/venues`, {
          signal: controller.signal,
          headers: { Accept: "application/json" },
          cache: "no-store",
        });

        if (!res.ok) {
          throw new Error(`venues endpoint returned ${res.status}`);
        }

        const data: VenueAnalyticsPoint[] = await res.json();
        setApiVenues(Array.isArray(data) ? data : []);
        setApiStatus("live");
        setFetchError(null);
      } catch (error) {
        if (controller.signal.aborted) return;
        setApiVenues([]);
        setApiStatus("fallback");
        setFetchError(
          error instanceof Error
            ? error.message
            : "Failed to fetch venue analytics",
        );
      }
    };

    void load();
    return () => controller.abort();
  }, []);

  const mappedLocations = useMemo(() => {
    return NUST_LANDMARKS.map((landmark) => {
      const apiMatch = apiVenues.find(
        (venue) =>
          venue.venue.toLowerCase().includes(landmark.name.toLowerCase()) ||
          landmark.name.toLowerCase().includes(venue.venue.toLowerCase()),
      );

      const timeVariance = Math.sin(timeOffset + landmark.x) * 0.3;
      const syntheticLoad = isLiveTime
        ? Math.floor(landmark.baseCapacity * (0.2 + (timeVariance + 1) / 2))
        : Math.floor(
            landmark.baseCapacity *
              (0.4 + (timeVariance + 1) / 2 + Math.abs(timeOffset) * 0.05),
          );

      const activeEntries = apiMatch
        ? apiMatch.total_entries
        : Math.max(0, syntheticLoad);
      const capacityRatio = Math.min(1, activeEntries / landmark.baseCapacity);

      return {
        ...landmark,
        activeEntries,
        capacityRatio,
        isCongested: capacityRatio > 0.8,
      };
    });
  }, [apiVenues, isLiveTime, timeOffset]);

  const filteredLocations = useMemo(
    () =>
      mappedLocations.filter((location) => {
        const matchesSearch = location.name
          .toLowerCase()
          .includes(searchQuery.toLowerCase());
        const matchesType = !poiType || location.type === poiType;
        return matchesSearch && matchesType;
      }),
    [mappedLocations, poiType, searchQuery],
  );

  const congestedCount = mappedLocations.filter(
    (location) => location.isCongested,
  ).length;

  const handleRouteRequest = (targetId: string) => {
    setActiveRoute((current) =>
      current?.to === targetId ? null : { from: "you", to: targetId },
    );
  };

  // Build VenuePins for Leaflet map
  const leafletVenues: VenuePin[] = useMemo(
    () =>
      filteredLocations.map((location) => ({
        id: location.id,
        name: location.name,
        lat: location.lat,
        lng: location.lng,
        capacityRatio: location.capacityRatio,
        activeEntries: location.activeEntries,
        baseCapacity: location.baseCapacity,
        isCongested: location.isCongested,
        type: location.type,
      })),
    [filteredLocations],
  );

  const googleMapsNust =
    "https://www.google.com/maps/dir/?api=1&destination=NUST+H-12+Islamabad";

  return (
    <div className="min-h-screen bg-background text-[var(--foreground)] selection:bg-[var(--primary)]/30 font-sans pattern-bg">
      <div className="absolute inset-0 pattern-grid opacity-30 pointer-events-none" />

      <div className="relative z-50 p-4 md:p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pointer-events-none">
        <div className="pointer-events-auto flex items-center gap-4">
          <BackButton href="/" label="" />
          <div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight flex flex-wrap items-center gap-3">
              Campus Intelligence
              <span className="text-[10px] px-2 py-0.5 bg-[var(--primary)] text-[var(--background)] rounded-full font-bold uppercase tracking-widest mt-1">
                Beta
              </span>
            </h1>
            <p className="text-xs sm:text-sm opacity-60 font-medium mt-1">
              Live NUST Map & Routing ·{" "}
              <span className="arabic-riwaq-sm text-sm" lang="ar">
                رواق
              </span>
            </p>
          </div>
        </div>
        <div className="pointer-events-auto">
          <a
            href={googleMapsNust}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary px-4 py-2 text-sm inline-flex items-center gap-2 rounded-xl"
          >
            <Navigation className="w-4 h-4" />
            Directions to NUST
            <ExternalLink className="w-3.5 h-3.5 opacity-70" />
          </a>
        </div>
      </div>

      <div className="relative z-10 p-4 sm:p-6 w-full max-w-7xl mx-auto flex flex-col lg:flex-row gap-6 items-stretch">
        <div className="flex-1 flex flex-col gap-6">
          <div className="pointer-events-auto flex items-center gap-3 bg-[var(--foreground)]/5 backdrop-blur-xl border border-[var(--foreground)]/10 rounded-2xl shadow-xl w-full md:w-auto overflow-x-auto hidden-scrollbar p-2">
            <button
              onClick={() => setShowHeatmap((previous) => !previous)}
              className={`px-4 py-2 rounded-xl text-sm font-bold flex items-center gap-2 transition-all shrink-0 ${
                showHeatmap
                  ? "bg-[var(--primary)] text-[var(--background)]"
                  : "hover:bg-[var(--foreground)]/10"
              }`}
            >
              <Zap className="w-4 h-4" />
              Heatmaps
            </button>

            <div className="h-8 w-px bg-[var(--foreground)]/10 shrink-0" />

            <div className="flex items-center gap-2 px-3 shrink-0">
              <label htmlFor="map-time-offset" className="sr-only">
                Time offset
              </label>
              <Clock className="w-4 h-4 text-[var(--primary)]" />
              <input
                id="map-time-offset"
                title="Time offset"
                type="range"
                min="-12"
                max="0"
                step="1"
                value={timeOffset}
                onChange={(event) => setTimeOffset(Number(event.target.value))}
                className="w-24 md:w-32 accent-[var(--primary)] cursor-pointer"
              />
              {isLiveTime ? (
                <span className="flex items-center gap-1.5 text-xs font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded-full border border-red-500/20">
                  <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />{" "}
                  LIVE
                </span>
              ) : (
                <span className="text-xs font-bold opacity-60 w-12 text-center">
                  {Math.abs(timeOffset)}h ago
                </span>
              )}
            </div>

            <div className="h-8 w-px bg-[var(--foreground)]/10 shrink-0" />
            <span
              className={`text-[10px] px-2 py-1 rounded-full font-bold uppercase tracking-wide shrink-0 ${
                apiStatus === "live"
                  ? "bg-green-500/20 text-green-400"
                  : "bg-yellow-500/20 text-yellow-400"
              }`}
              title={fetchError ?? "Venue analytics status"}
            >
              {apiStatus === "live" ? "API Live" : "Simulated"}
            </span>
          </div>

          {/* ── Real interactive Leaflet map ─────────────────────────── */}
          <div className="pointer-events-auto relative rounded-3xl border border-[var(--foreground)]/10 bg-background/40 backdrop-blur-md overflow-hidden shadow-2xl min-h-[60vh] lg:min-h-[80vh]">
            <LeafletMap
              venues={leafletVenues}
              onVenueClick={handleRouteRequest}
              activeRouteId={activeRoute?.to ?? null}
              showHeatmap={showHeatmap}
              userLat={userLat}
              userLng={userLng}
            />
            {/* Legend */}
            <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-[400] pointer-events-none">
              <div className="bg-background/80 backdrop-blur-xl border border-[var(--foreground)]/10 rounded-2xl px-4 py-2 flex gap-4 sm:gap-6 text-[10px] sm:text-xs font-semibold shadow-2xl">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-[var(--primary)]" />
                  Venue
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-[var(--primary)] ring-2 ring-[var(--primary)]/30" />
                  You Are Here
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  Congested
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-yellow-400" />
                  Busy
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="w-full lg:w-96 flex flex-col gap-4 pointer-events-auto z-20">
          <div className="bg-[var(--foreground)]/5 border border-[var(--foreground)]/10 backdrop-blur-2xl rounded-3xl p-5 shadow-xl flex-shrink-0">
            <label htmlFor="map-search" className="sr-only">
              Search venues
            </label>
            <div className="flex flex-col gap-3 relative mb-4">
              <Search className="text-[var(--foreground)]/40 absolute left-3 top-3 w-5 h-5" />
              <input
                id="map-search"
                type="text"
                title="Search venues"
                placeholder="Search venues..."
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                className="w-full bg-[var(--foreground)]/5 border border-[var(--foreground)]/10 rounded-2xl pl-10 pr-4 py-3 outline-none focus:border-[var(--primary)] transition-colors"
              />
            </div>

            <div className="flex flex-col gap-2">
              <button
                onClick={() => {
                  setPoiType((current) => (current === "food" ? null : "food"));
                  setActiveRoute((current) =>
                    current?.to === "c1" ? null : { from: "you", to: "c1" },
                  );
                }}
                className={`flex items-center gap-3 p-3 rounded-2xl transition-colors border text-left ${
                  poiType === "food"
                    ? "bg-[var(--primary)]/10 border-[var(--primary)]/50"
                    : "bg-[var(--foreground)]/5 hover:bg-[var(--foreground)]/10 border-transparent hover:border-[var(--foreground)]/10"
                }`}
              >
                <div className="w-10 h-10 rounded-xl bg-orange-500/20 flex items-center justify-center shrink-0">
                  <Coffee className="w-5 h-5 text-orange-400" />
                </div>
                <div>
                  <p className="font-bold text-sm">Find Nearest Cafe</p>
                  <p className="text-xs opacity-60">C1 is 3 mins away</p>
                </div>
              </button>

              <button
                onClick={() => {
                  setPoiType((current) => (current === "gate" ? null : "gate"));
                  setActiveRoute((current) =>
                    current?.to === "gate1"
                      ? null
                      : { from: "you", to: "gate1" },
                  );
                }}
                className={`flex items-center gap-3 p-3 rounded-2xl transition-colors border text-left ${
                  poiType === "gate"
                    ? "bg-red-500/10 border-red-500/50"
                    : "bg-[var(--foreground)]/5 hover:bg-[var(--foreground)]/10 border-transparent hover:border-[var(--foreground)]/10"
                }`}
              >
                <div className="w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center shrink-0">
                  <ShieldAlert className="w-5 h-5 text-red-500" />
                </div>
                <div>
                  <p className="font-bold text-sm">Evacuation Routes</p>
                  <p className="text-xs opacity-60">Direct to Gate 1</p>
                </div>
              </button>

              {/* ── Get Directions to NUST (Google Maps) ─── */}
              <a
                href={googleMapsNust}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 p-3 rounded-2xl transition-colors border bg-[var(--foreground)]/5 hover:bg-[var(--primary)]/10 border-transparent hover:border-[var(--primary)]/30 text-left"
              >
                <div className="w-10 h-10 rounded-xl bg-[var(--primary)]/15 flex items-center justify-center shrink-0">
                  <Navigation className="w-5 h-5 text-[var(--primary)]" />
                </div>
                <div>
                  <p className="font-bold text-sm">Directions to NUST</p>
                  <p className="text-xs opacity-60">Opens in Google Maps</p>
                </div>
                <ExternalLink className="w-3.5 h-3.5 ml-auto opacity-40 shrink-0" />
              </a>
            </div>
          </div>

          <AnimatePresence>
            {congestedCount > 0 && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="bg-red-500/10 border border-red-500/30 backdrop-blur-2xl rounded-3xl p-5 shadow-xl flex-shrink-0 overflow-hidden"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h2 className="text-lg font-bold text-red-500 flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5" /> Congestion Alerts
                    </h2>
                    <p className="text-xs text-red-400/80 mt-1">
                      High crowd volume detected
                    </p>
                  </div>
                  <div className="bg-red-500 text-[var(--background)] px-2 py-1 rounded-lg text-xs font-black">
                    {congestedCount} ZONES
                  </div>
                </div>

                <div className="mt-4 space-y-2">
                  {mappedLocations
                    .filter((location) => location.isCongested)
                    .map((location) => (
                      <div
                        key={location.id}
                        className="flex justify-between items-center bg-red-950/40 p-3 rounded-xl border border-red-500/20"
                      >
                        <span className="font-bold text-sm">
                          {location.name}
                        </span>
                        <span className="text-xs font-mono text-red-400 bg-red-500/10 px-2 py-1 rounded-full">
                          {Math.round(location.capacityRatio * 100)}% FULL
                        </span>
                      </div>
                    ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="bg-[var(--foreground)]/5 border border-[var(--foreground)]/10 backdrop-blur-2xl rounded-3xl p-5 shadow-xl flex-1 flex flex-col min-h-[300px]">
            <div className="flex items-center justify-between gap-2 mb-4">
              <h2 className="text-lg font-bold flex items-center gap-2">
                <MapPin className="text-[var(--primary)]" /> Venue Directory
              </h2>
              <span
                className={`text-[10px] px-2 py-1 rounded-full font-bold uppercase tracking-wide ${
                  apiStatus === "live"
                    ? "bg-green-500/20 text-green-400"
                    : "bg-yellow-500/20 text-yellow-400"
                }`}
                title={fetchError ?? "Venue analytics status"}
              >
                {apiStatus === "live" ? "API Live" : "Fallback"}
              </span>
            </div>

            <div className="flex-1 overflow-y-auto hidden-scrollbar pr-2 space-y-3">
              {filteredLocations
                .slice()
                .sort((a, b) => b.capacityRatio - a.capacityRatio)
                .map((location) => (
                  <motion.div
                    key={location.id}
                    onMouseEnter={() => setHoveredNode(location.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    onClick={() => handleRouteRequest(location.id)}
                    className={`p-4 rounded-2xl cursor-pointer transition-all border ${
                      hoveredNode === location.id ||
                      activeRoute?.to === location.id
                        ? "bg-[var(--foreground)]/10 border-[var(--primary)]"
                        : "bg-[var(--foreground)]/5 border-[var(--foreground)]/10 hover:bg-[var(--foreground)]/10"
                    }`}
                  >
                    <div className="flex justify-between items-center">
                      <div className="font-bold">{location.name}</div>
                      <div className="flex items-center gap-1.5 opacity-60">
                        <Users className="w-3.5 h-3.5" />
                        <span className="text-xs font-mono">
                          {location.activeEntries} / {location.baseCapacity}
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 h-1.5 w-full bg-background/50 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{
                          width: `${Math.min(100, location.capacityRatio * 100)}%`,
                        }}
                        className={`h-full rounded-full ${
                          location.isCongested
                            ? "bg-red-500"
                            : location.capacityRatio > 0.5
                              ? "bg-yellow-400"
                              : "bg-[var(--primary)]"
                        }`}
                      />
                    </div>

                    {activeRoute?.to === location.id && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        className="mt-3 pt-3 border-t border-[var(--foreground)]/10 flex justify-between items-center gap-2"
                      >
                        <div className="text-xs text-[var(--primary)] flex items-center gap-1">
                          <Navigation className="w-3 h-3" /> Routing to{" "}
                          {location.name}…
                        </div>
                        <a
                          href={`https://www.google.com/maps/dir/?api=1&destination=${location.lat},${location.lng}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="text-xs flex items-center gap-1 text-[var(--primary)] border border-[var(--primary)]/30 px-2 py-1 rounded-lg hover:bg-[var(--primary)]/10 transition-colors shrink-0"
                        >
                          <ExternalLink className="w-3 h-3" /> Maps
                        </a>
                      </motion.div>
                    )}
                  </motion.div>
                ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
