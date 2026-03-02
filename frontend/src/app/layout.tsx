import type { Metadata } from "next";
import { Geist, Geist_Mono, Scheherazade_New } from "next/font/google";
import "./globals.css";
import SwRegister from "./sw-register";
import Navbar from "./navbar";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

/** Scheherazade New — an award-winning Arabic font by SIL, ideal for رواق */
const arabicFont = Scheherazade_New({
  weight: ["400", "700"],
  subsets: ["arabic"],
  variable: "--font-arabic",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "Riwaq",
    template: "%s • Riwaq",
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
      <body
        className={`${geistSans.variable} ${geistMono.variable} ${arabicFont.variable} antialiased`}
      >
        <SwRegister />
        <Navbar />
        <main className="page-transition">{children}</main>
      </body>
    </html>
  );
}
