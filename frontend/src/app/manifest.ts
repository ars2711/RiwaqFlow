import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Riwaq",
    short_name: "Riwaq",
    description:
      "A society-first platform for events, e-ticketing, and live campus intelligence.",
    start_url: "/",
    display: "standalone",
    background_color: "#070b17",
    theme_color: "#335dff",
    icons: [
      {
        src: "/favicon.ico",
        sizes: "any",
        type: "image/x-icon",
      },
    ],
  };
}
