import type { Metadata } from "next";
import { Fraunces, Archivo, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import SwRegister from "./sw-register";
import Navbar from "./navbar";

/** Display — serif with ink-trap detailing, used for headlines & names */
const fraunces = Fraunces({
  variable: "--font-fraunces",
  subsets: ["latin"],
  display: "swap",
});

/** Body — architectural grotesque, used for paragraph text */
const archivo = Archivo({
  variable: "--font-archivo",
  subsets: ["latin"],
  display: "swap",
});

/** Mono — codes, IDs, timestamps, all-caps eyebrow text */
const ibmPlexMono = IBM_Plex_Mono({
  weight: ["400", "500", "600"],
  variable: "--font-ibm-plex-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "Riwaq — The courtyard campus life happens in",
    template: "%s · Riwaq",
  },
  applicationName: "Riwaq",
  description:
    "A society-first platform for events, e-ticketing, and live campus intelligence. Secure digital ticketing, scanner verification, venue analytics, and campus networking for NUST.",
  keywords: [
    "Riwaq",
    "NUST",
    "event management",
    "digital tickets",
    "campus events",
    "scanner verification",
    "society events",
    "department events",
    "e-ticketing",
    "campus intelligence",
  ],
  robots: {
    index: true,
    follow: true,
  },
  openGraph: {
    title: "Riwaq",
    description:
      "From gatherings to flow — secure e-ticketing, live campus intelligence, and event operations for NUST societies.",
    type: "website",
    locale: "en_PK",
  },
  twitter: {
    card: "summary_large_image",
    title: "Riwaq",
    description:
      "A society-first platform for NUST events, e-ticketing, and live campus intelligence.",
  },
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", type: "image/x-icon" },
    ],
    shortcut: ["/icon.svg"],
    apple: [{ url: "/icon.svg", type: "image/svg+xml" }],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Noto Nastaliq Urdu — loaded via <link> since next/font/google doesn't reliably support Nastaliq subsets */}
        <link
          rel="preconnect"
          href="https://fonts.googleapis.com"
        />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Noto+Nastaliq+Urdu:wght@600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body
        className={`${fraunces.variable} ${archivo.variable} ${ibmPlexMono.variable} antialiased`}
      >
        <SwRegister />
        <Navbar />
        <main className="page-transition">{children}</main>
      </body>
    </html>
  );
}
