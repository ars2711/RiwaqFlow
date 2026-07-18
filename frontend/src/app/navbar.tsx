"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { RiwaqLogo } from "@/components/ui/Logo";
import ThemeToggle from "./theme-toggle";

const navItems = [
  { href: "/calendar", label: "Events" },
  { href: "/map", label: "Campus pulse" },
  { href: "/societies", label: "Societies" },
  { href: "/admin", label: "Admin", hideMobile: true },
  { href: "/scan", label: "Scanner", hideMobile: true },
];

export default function Navbar() {
  const pathname = usePathname();

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/" className="brand" aria-label="Riwaq home">
          <RiwaqLogo className="h-[26px] w-[26px]" />
          <span className="brand-text">Riwaq</span>
        </Link>

        <nav className="nav-links" aria-label="Primary">
          {navItems.map((item) => {
            const active =
              pathname === item.href ||
              (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`${active ? "active" : ""} ${item.hideMobile ? "hide-mobile" : ""}`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <ThemeToggle />
      </div>
    </header>
  );
}
