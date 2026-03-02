"use client";
// This component must be loaded with dynamic({ ssr: false }) to avoid SSR issues with Leaflet
import { useEffect, useRef } from "react";

export type VenuePin = {
  id: string;
  name: string;
  lat: number;
  lng: number;
  capacityRatio: number;
  activeEntries: number;
  baseCapacity: number;
  isCongested: boolean;
  type: string;
};

type LeafletMapProps = {
  venues: VenuePin[];
  onVenueClick?: (id: string) => void;
  activeRouteId?: string | null;
  showHeatmap: boolean;
  userLat?: number;
  userLng?: number;
};

// NUST H-12 campus center
const NUST_CENTER: [number, number] = [33.6422, 72.9843];

export default function LeafletMapComponent({
  venues,
  onVenueClick,
  activeRouteId,
  showHeatmap,
  userLat,
  userLng,
}: LeafletMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const leafletRef = useRef<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const markersLayerRef = useRef<any[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const heatLayerRef = useRef<any[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const userMarkerRef = useRef<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const routeLineRef = useRef<any>(null);

  // Initialize map once
  useEffect(() => {
    if (!mapRef.current || leafletRef.current) return;

    // Dynamically import Leaflet to avoid SSR
    import("leaflet").then((L) => {
      // Fix Leaflet default icon with webpack/Next.js
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (L.Icon.Default.prototype as any)._getIconUrl;
      L.Icon.Default.mergeOptions({
        iconRetinaUrl:
          "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
        iconUrl:
          "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
        shadowUrl:
          "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
      });

      const map = L.map(mapRef.current!, {
        center: NUST_CENTER,
        zoom: 16,
        zoomControl: true,
        attributionControl: true,
      });

      // Dark-mode aware tile layer — use CartoDB dark for dark themes
      const isDark =
        document.documentElement.dataset.theme === "dark" ||
        !document.documentElement.dataset.theme;

      const tileUrl = isDark
        ? "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        : "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";

      const attribution = isDark
        ? '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'
        : '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';

      L.tileLayer(tileUrl, { attribution, maxZoom: 19 }).addTo(map);

      leafletRef.current = map;
    });

    return () => {
      if (leafletRef.current) {
        leafletRef.current.remove();
        leafletRef.current = null;
      }
    };
    // Only run once on mount — empty dep array is intentional
  }, []);

  // Update venue markers when venues or activeRouteId changes
  useEffect(() => {
    if (!leafletRef.current) {
      // Retry after map initialises
      const t = setTimeout(() => {
        // re-run by depending on venues length change externally
      }, 600);
      return () => clearTimeout(t);
    }

    import("leaflet").then((L) => {
      const map = leafletRef.current;
      if (!map) return;

      // Remove old markers + heat circles
      markersLayerRef.current.forEach((m) => m.remove());
      markersLayerRef.current = [];
      heatLayerRef.current.forEach((c) => c.remove());
      heatLayerRef.current = [];
      if (routeLineRef.current) {
        routeLineRef.current.remove();
        routeLineRef.current = null;
      }

      // User location marker
      if (userMarkerRef.current) {
        userMarkerRef.current.remove();
        userMarkerRef.current = null;
      }

      const effectiveLat = userLat ?? NUST_CENTER[0];
      const effectiveLng = userLng ?? NUST_CENTER[1];

      const youIcon = L.divIcon({
        html: `<div style="
          width:18px;height:18px;border-radius:50%;
          background:var(--primary, #335dff);
          border:3px solid #fff;
          box-shadow:0 0 0 6px rgba(51,93,255,0.25);
        "></div>`,
        className: "",
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });

      userMarkerRef.current = L.marker([effectiveLat, effectiveLng], {
        icon: youIcon,
        zIndexOffset: 1000,
      })
        .bindTooltip("You are here", { permanent: false, direction: "top" })
        .addTo(map);

      venues.forEach((venue) => {
        const isActive = activeRouteId === venue.id;
        // Heatmap circle
        if (showHeatmap && venue.capacityRatio > 0.15) {
          const radius = 20 + venue.capacityRatio * 120; // metres
          const heatCircle = L.circle([venue.lat, venue.lng], {
            color: "transparent",
            fillColor: venue.isCongested ? "#ef4444" : "#f59e0b",
            fillOpacity: venue.capacityRatio * 0.35,
            radius,
          }).addTo(map);
          heatLayerRef.current.push(heatCircle);
        }

        // Venue marker
        const markerSize = isActive ? 20 : 14;
        const icon = L.divIcon({
          html: `<div style="
            width:${markerSize}px;height:${markerSize}px;border-radius:50%;
            background:${isActive ? "#335dff" : venue.isCongested ? "#ef4444" : "#335dff"};
            border:${isActive ? "3px" : "2px"} solid #fff;
            box-shadow:0 0 ${isActive ? "14px" : "6px"} ${venue.isCongested ? "#ef4444" : "#335dff"}88;
            transition:all 0.2s;
          "></div>`,
          className: "",
          iconSize: [markerSize, markerSize],
          iconAnchor: [markerSize / 2, markerSize / 2],
        });

        const pct = Math.round(venue.capacityRatio * 100);
        const barW = Math.min(100, pct);
        const barColor = venue.isCongested
          ? "#ef4444"
          : pct > 60
            ? "#f59e0b"
            : "#335dff";

        const popup = L.popup({ minWidth: 180 }).setContent(`
          <div style="font-family:system-ui,sans-serif;padding:4px 2px">
            <div style="font-weight:700;font-size:14px;margin-bottom:4px">${venue.name}</div>
            <div style="font-size:12px;color:#888;margin-bottom:6px">
              ${venue.activeEntries.toLocaleString()} / ${venue.baseCapacity.toLocaleString()} people &nbsp;•&nbsp; ${pct}% full
            </div>
            <div style="height:5px;background:#e5e7eb;border-radius:3px;margin-bottom:8px">
              <div style="width:${barW}%;height:100%;background:${barColor};border-radius:3px"></div>
            </div>
            <a href="https://www.google.com/maps/dir/?api=1&destination=${venue.lat},${venue.lng}"
               target="_blank" rel="noopener noreferrer"
               style="display:inline-flex;align-items:center;gap:5px;font-size:12px;
                      color:#335dff;text-decoration:none;font-weight:600;
                      border:1px solid #335dff33;padding:4px 8px;border-radius:6px">
              📍 Get Directions
            </a>
          </div>
        `);

        const marker = L.marker([venue.lat, venue.lng], { icon })
          .bindPopup(popup)
          .addTo(map);

        if (isActive) {
          marker.openPopup();
          map.setView([venue.lat, venue.lng], 17, { animate: true });
        }

        if (onVenueClick) {
          marker.on("click", () => onVenueClick(venue.id));
        }

        markersLayerRef.current.push(marker);

        // Route line from user to active venue
        if (isActive) {
          routeLineRef.current = L.polyline(
            [
              [effectiveLat, effectiveLng],
              [venue.lat, venue.lng],
            ],
            {
              color: "#335dff",
              weight: 3,
              opacity: 0.8,
              dashArray: "8 8",
            },
          ).addTo(map);
        }
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [venues, activeRouteId, showHeatmap, userLat, userLng]);

  return (
    <>
      {/* Leaflet CSS inline — works with Next.js without needing CSS imports at top level */}
      <style>{`
        .leaflet-container { background: #0a0e1a; font-family: system-ui, sans-serif; }
        .leaflet-popup-content-wrapper { border-radius: 12px !important; box-shadow: 0 8px 32px rgba(0,0,0,0.3) !important; }
        .leaflet-control-attribution { font-size: 9px !important; }
        .leaflet-bar a { background: rgba(10,14,26,0.9) !important; color: #e7edff !important; border-color: rgba(155,180,255,0.2) !important; }
        .leaflet-bar a:hover { background: rgba(51,93,255,0.3) !important; }
      `}</style>
      <div
        ref={mapRef}
        className="w-full rounded-3xl overflow-hidden min-h-[60vh] z-[1] lg:min-h-[80vh]"
        aria-label="NUST Campus interactive map"
      />
    </>
  );
}
