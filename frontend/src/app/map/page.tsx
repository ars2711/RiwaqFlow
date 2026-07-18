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

// Load Leaflet map only on client (no SSR)
const LeafletMap = dynamic(() => import("@/components/ui/LeafletMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full min-h-[60vh] rounded-none bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center">
      <div className="flex flex-col items-center gap-3 text-[var(--muted)] font-mono text-sm uppercase tracking-widest">
        <span>Loading map interface...</span>
      </div>
    </div>
  ),
});

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
  { id: "seecs", name: "SEECS", lat: 33.6448, lng: 72.9848, x: 250, y: 650, type: "academic", baseCapacity: 800 },
  { id: "nbs", name: "NBS", lat: 33.6402, lng: 72.9895, x: 750, y: 450, type: "academic", baseCapacity: 500 },
  { id: "s3h", name: "S3H", lat: 33.64, lng: 72.9902, x: 780, y: 350, type: "academic", baseCapacity: 400 },
  { id: "sada", name: "SADA", lat: 33.6428, lng: 72.986, x: 450, y: 350, type: "academic", baseCapacity: 300 },
  { id: "library", name: "Central Library", lat: 33.6424, lng: 72.9856, x: 500, y: 500, type: "academic", baseCapacity: 1000 },
  { id: "smme", name: "SMME", lat: 33.6456, lng: 72.9842, x: 300, y: 300, type: "academic", baseCapacity: 600 },
  { id: "scme", name: "SCME", lat: 33.6463, lng: 72.9854, x: 380, y: 250, type: "academic", baseCapacity: 450 },
  { id: "c1", name: "C1 Cafeteria", lat: 33.6415, lng: 72.9858, x: 600, y: 750, type: "food", baseCapacity: 200 },
  { id: "c2", name: "C2 Cafeteria", lat: 33.6442, lng: 72.9848, x: 300, y: 450, type: "food", baseCapacity: 150 },
  { id: "nstp", name: "NSTP", lat: 33.6386, lng: 72.993, x: 800, y: 800, type: "academic", baseCapacity: 1200 },
  { id: "hostels", name: "Hostels Area", lat: 33.6478, lng: 72.9825, x: 150, y: 150, type: "residential", baseCapacity: 2500 },
  { id: "gate1", name: "Gate 1 (Main)", lat: 33.6422, lng: 72.995, x: 920, y: 920, type: "gate", baseCapacity: 100 },
];

export default function MapPage() {
  const [apiVenues, setApiVenues] = useState<VenueAnalyticsPoint[]>([]);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [timeOffset, setTimeOffset] = useState<number>(0);
  const [showHeatmap, setShowHeatmap] = useState(true);
  const [activeRoute, setActiveRoute] = useState<{ from: string; to: string; } | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [poiType, setPoiType] = useState<Landmark["type"] | null>(null);
  const [userLat, setUserLat] = useState<number | undefined>();
  const [userLng, setUserLng] = useState<number | undefined>();
  const [apiStatus, setApiStatus] = useState<"live" | "fallback">("fallback");

  const isLiveTime = timeOffset === 0;

  useEffect(() => {
    if (typeof window === "undefined" || !("geolocation" in navigator)) return;
    navigator.geolocation.getCurrentPosition(
      (pos) => { setUserLat(pos.coords.latitude); setUserLng(pos.coords.longitude); },
      () => { setUserLat(33.643); setUserLng(72.9858); },
      { enableHighAccuracy: true, timeout: 6000 }
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
        if (!res.ok) throw new Error(`venues endpoint returned ${res.status}`);
        const data: VenueAnalyticsPoint[] = await res.json();
        setApiVenues(Array.isArray(data) ? data : []);
        setApiStatus("live");
      } catch (error) {
        if (controller.signal.aborted) return;
        setApiVenues([]);
        setApiStatus("fallback");
      }
    };
    void load();
    return () => controller.abort();
  }, []);

  const mappedLocations = useMemo(() => {
    return NUST_LANDMARKS.map((landmark) => {
      const apiMatch = apiVenues.find((v) =>
        v.venue.toLowerCase().includes(landmark.name.toLowerCase()) ||
        landmark.name.toLowerCase().includes(v.venue.toLowerCase())
      );
      const timeVariance = Math.sin(timeOffset + landmark.x) * 0.3;
      const syntheticLoad = isLiveTime
        ? Math.floor(landmark.baseCapacity * (0.2 + (timeVariance + 1) / 2))
        : Math.floor(landmark.baseCapacity * (0.4 + (timeVariance + 1) / 2 + Math.abs(timeOffset) * 0.05));
      const activeEntries = apiMatch ? apiMatch.total_entries : Math.max(0, syntheticLoad);
      const capacityRatio = Math.min(1, activeEntries / landmark.baseCapacity);
      
      return {
        ...landmark,
        activeEntries,
        capacityRatio,
        isCongested: capacityRatio > 0.8,
      };
    });
  }, [apiVenues, isLiveTime, timeOffset]);

  const filteredLocations = useMemo(() => mappedLocations.filter((location) => {
    const matchesSearch = location.name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = !poiType || location.type === poiType;
    return matchesSearch && matchesType;
  }), [mappedLocations, poiType, searchQuery]);

  const congestedCount = mappedLocations.filter((l) => l.isCongested).length;

  const handleRouteRequest = (targetId: string) => {
    setActiveRoute((current) => current?.to === targetId ? null : { from: "you", to: targetId });
  };

  const leafletVenues: VenuePin[] = useMemo(() => filteredLocations.map((l) => ({
    id: l.id, name: l.name, lat: l.lat, lng: l.lng, capacityRatio: l.capacityRatio,
    activeEntries: l.activeEntries, baseCapacity: l.baseCapacity, isCongested: l.isCongested, type: l.type,
  })), [filteredLocations]);

  const googleMapsNust = "https://www.google.com/maps/dir/?api=1&destination=NUST+H-12+Islamabad";

  return (
    <div className="app-shell" data-theme="dark">
      <div className="wrap py-10">
        <div className="flex justify-between items-start flex-wrap gap-4 mb-8">
          <div>
            <BackButton href="/" label="Back to Home" />
            <div className="mt-6 eyebrow">
              <span className="line"></span> Night Signal
            </div>
            <h1 className="section-title">Campus Intelligence</h1>
            <p className="section-subtitle mt-2">
              Live NUST Map & Routing
            </p>
          </div>
          <a
            href={googleMapsNust}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary"
          >
            <Navigation className="w-4 h-4" />
            Directions
          </a>
        </div>

        <div className="grid lg:grid-cols-[1fr_360px] gap-8 items-start">
          {/* Main Map Area */}
          <div className="flex flex-col gap-4">
            {/* Map Controls */}
            <div className="flex flex-wrap items-center gap-4 bg-[var(--surface)] border border-[var(--border)] p-3 shadow-sm">
              <button
                onClick={() => setShowHeatmap((prev) => !prev)}
                className={`px-4 py-2 text-[11px] font-mono font-bold uppercase tracking-widest flex items-center gap-2 border ${
                  showHeatmap
                    ? "bg-[var(--verified)] text-[var(--bg)] border-[var(--verified)]"
                    : "bg-transparent text-[var(--text)] border-[var(--border)]"
                }`}
              >
                <Zap className="w-4 h-4" /> Heatmaps
              </button>

              <div className="h-6 w-px bg-[var(--border)] hidden sm:block" />

              <div className="flex items-center gap-3">
                <Clock className="w-4 h-4 text-[var(--muted)]" />
                <input
                  type="range"
                  min="-12"
                  max="0"
                  step="1"
                  value={timeOffset}
                  onChange={(e) => setTimeOffset(Number(e.target.value))}
                  className="w-24 sm:w-32 accent-[var(--verified)] cursor-pointer"
                />
                {isLiveTime ? (
                  <span className="tag-live">Live</span>
                ) : (
                  <span className="text-[10px] font-mono text-[var(--muted)] w-12 uppercase">
                    {Math.abs(timeOffset)}H AGO
                  </span>
                )}
              </div>

              <div className="h-6 w-px bg-[var(--border)] hidden sm:block" />
              <span className={`text-[10px] font-mono uppercase tracking-widest px-2 py-1 border ${
                apiStatus === "live" ? "text-[var(--verified)] border-[var(--verified)]" : "text-[var(--brass)] border-[var(--brass)]"
              }`}>
                {apiStatus === "live" ? "API Live" : "Simulated"}
              </span>
            </div>

            {/* Leaflet Map */}
            <div className="relative border border-[var(--border)] bg-[var(--surface)] min-h-[60vh] lg:min-h-[70vh]">
              <LeafletMap
                venues={leafletVenues}
                onVenueClick={handleRouteRequest}
                activeRouteId={activeRoute?.to ?? null}
                showHeatmap={showHeatmap}
                userLat={userLat}
                userLng={userLng}
              />
              
              {/* Legend overlay */}
              <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-[400] pointer-events-none">
                <div className="bg-[var(--surface)] border border-[var(--border)] px-4 py-2 flex gap-4 sm:gap-6 text-[10px] font-mono uppercase tracking-widest shadow-lg">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-[var(--verified)]" /> Venue
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-[var(--alert)]" /> Congested
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-[var(--brass)]" /> Busy
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="flex flex-col gap-6">
            {/* Search and Filters */}
            <div className="bg-[var(--surface)] border border-[var(--border)] p-5">
              <div className="relative mb-5">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-[var(--muted)]" />
                <input
                  type="text"
                  placeholder="Search venues..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="field pl-9 h-10"
                />
              </div>

              <div className="flex flex-col gap-3">
                <button
                  onClick={() => {
                    setPoiType((c) => (c === "food" ? null : "food"));
                    setActiveRoute((c) => c?.to === "c1" ? null : { from: "you", to: "c1" });
                  }}
                  className={`flex items-center gap-3 p-3 border text-left transition-colors ${
                    poiType === "food"
                      ? "border-[var(--brass)] bg-[var(--brass)]/10"
                      : "border-[var(--border)] hover:bg-[var(--surface-2)]"
                  }`}
                >
                  <Coffee className={`w-5 h-5 ${poiType === "food" ? "text-[var(--brass)]" : "text-[var(--muted)]"}`} />
                  <div>
                    <div className="text-[12px] font-mono uppercase tracking-widest">Find Cafe</div>
                    <div className="text-xs text-[var(--muted)]">Quick food routing</div>
                  </div>
                </button>

                <button
                  onClick={() => {
                    setPoiType((c) => (c === "gate" ? null : "gate"));
                    setActiveRoute((c) => c?.to === "gate1" ? null : { from: "you", to: "gate1" });
                  }}
                  className={`flex items-center gap-3 p-3 border text-left transition-colors ${
                    poiType === "gate"
                      ? "border-[var(--alert)] bg-[var(--alert)]/10"
                      : "border-[var(--border)] hover:bg-[var(--surface-2)]"
                  }`}
                >
                  <ShieldAlert className={`w-5 h-5 ${poiType === "gate" ? "text-[var(--alert)]" : "text-[var(--muted)]"}`} />
                  <div>
                    <div className="text-[12px] font-mono uppercase tracking-widest">Evac Routes</div>
                    <div className="text-xs text-[var(--muted)]">Direct to Gate 1</div>
                  </div>
                </button>
              </div>
            </div>

            {/* Alert Box */}
            {congestedCount > 0 && (
              <div className="border border-[var(--alert)] bg-[var(--alert)]/10 p-5">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="text-[13px] font-mono font-bold uppercase tracking-widest text-[var(--alert)] flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" /> Congestion Alerts
                    </h2>
                  </div>
                  <div className="bg-[var(--alert)] text-[var(--bg)] px-2 py-0.5 text-[10px] font-mono font-bold">
                    {congestedCount} ZONES
                  </div>
                </div>
                <div className="space-y-3">
                  {mappedLocations.filter((l) => l.isCongested).map((l) => (
                    <div key={l.id} className="flex justify-between items-center">
                      <span className="font-bold text-sm">{l.name}</span>
                      <span className="text-[10px] font-mono text-[var(--alert)] border border-[var(--alert)] px-1.5 py-0.5">
                        {Math.round(l.capacityRatio * 100)}% FULL
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Directory */}
            <div className="bg-[var(--surface)] border border-[var(--border)] p-5 flex-1 flex flex-col min-h-[300px]">
              <div className="section-label mb-4">Venue Directory</div>
              <div className="flex-1 overflow-y-auto space-y-4">
                {filteredLocations
                  .slice()
                  .sort((a, b) => b.capacityRatio - a.capacityRatio)
                  .map((location) => (
                    <div
                      key={location.id}
                      onMouseEnter={() => setHoveredNode(location.id)}
                      onMouseLeave={() => setHoveredNode(null)}
                      onClick={() => handleRouteRequest(location.id)}
                      className={`p-4 border transition-colors cursor-pointer ${
                        hoveredNode === location.id || activeRoute?.to === location.id
                          ? "border-[var(--verified)] bg-[var(--verified)]/5"
                          : "border-[var(--border)] hover:bg-[var(--surface-2)]"
                      }`}
                    >
                      <div className="flex justify-between items-center mb-3">
                        <div className="font-bold text-sm">{location.name}</div>
                        <div className="text-[10px] font-mono text-[var(--muted)] flex items-center gap-1.5">
                          <Users className="w-3 h-3" />
                          {location.activeEntries} / {location.baseCapacity}
                        </div>
                      </div>
                      
                      <div className="h-1 w-full bg-[var(--surface-2)] overflow-hidden">
                        <div
                          className={`h-full ${
                            location.isCongested
                              ? "bg-[var(--alert)]"
                              : location.capacityRatio > 0.5
                                ? "bg-[var(--brass)]"
                                : "bg-[var(--verified)]"
                          }`}
                          style={{ width: `${Math.min(100, location.capacityRatio * 100)}%` }}
                        />
                      </div>
                      
                      {activeRoute?.to === location.id && (
                        <div className="mt-4 pt-3 border-t border-[var(--border)] flex justify-between items-center">
                          <div className="text-[10px] font-mono text-[var(--verified)] uppercase tracking-widest flex items-center gap-1">
                            <Navigation className="w-3 h-3" /> Routing
                          </div>
                          <a
                            href={`https://www.google.com/maps/dir/?api=1&destination=${location.lat},${location.lng}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="text-[10px] font-mono text-[var(--verified)] border border-[var(--verified)] px-2 py-1 uppercase"
                          >
                            Google Maps
                          </a>
                        </div>
                      )}
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
