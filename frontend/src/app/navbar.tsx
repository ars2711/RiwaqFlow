"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { RiwaqLogo } from "@/components/ui/Logo";
import ThemeToggle from "./theme-toggle";

const navItems = [
  { href: "/", label: "Home" },
  { href: "/calendar", label: "Explore" },
  { href: "/map", label: "Map" },
  { href: "/societies", label: "Societies" },
  { href: "/network", label: "Network" },
  { href: "/pricing", label: "Pricing" },
  { href: "/admin", label: "Admin" },
  { href: "/scan", label: "Scanner" },
];

export default function Navbar() {
  const pathname = usePathname();

  return (
    <header className="site-nav-wrap">
      <nav className="site-nav glass-panel" aria-label="Primary">
        <Link href="/" className="site-logo" aria-label="Riwaq home">
          <span className="site-logo-mark" aria-hidden>
            <RiwaqLogo className="h-6 w-6" />
          </span>
          <span className="site-logo-text flex items-center gap-2">
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-[var(--primary)] to-[var(--accent-violet)] font-black tracking-tight">
              Riwaq
            </span>
            <span
              className="arabic-riwaq-sm text-base leading-none"
              aria-label="رواق"
            >
              رواق
            </span>
          </span>
        </Link>

        <div className="site-nav-links">
          {navItems.map((item) => {
            const active =
              pathname === item.href ||
              (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`site-nav-link ${active ? "active" : ""}`}
              >
                {item.label}
              </Link>
            );
          })}
        </div>

        <div className="site-nav-actions">
          <ThemeToggle />
        </div>
      </nav>
    </header>
  );
}
