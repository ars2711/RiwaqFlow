import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Riwaq — رواق",
    short_name: "Riwaq",
    description:
      "A society-first platform for NUST events, e-ticketing, and live campus intelligence.",
    start_url: "/",
    display: "standalone",
    background_color: "#070b17",
    theme_color: "#335dff",
    orientation: "portrait-primary",
    categories: ["education", "social", "events"],
    icons: [
      {
        src: "/icon.svg",
        sizes: "any",
        type: "image/svg+xml",
        purpose: "any maskable",
      },
      {
        src: "/favicon.ico",
        sizes: "48x48",
        type: "image/x-icon",
      },
    ],
    shortcuts: [
      {
        name: "Explore Events",
        url: "/calendar",
        description: "Browse upcoming NUST events",
      },
      {
        name: "Campus Map",
        url: "/map",
        description: "Live NUST campus map",
      },
      {
        name: "Gate Scanner",
        url: "/scan",
        description: "Volunteer ticket scanner",
      },
    ],
  };
}
