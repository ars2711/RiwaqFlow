"use client";

import { useEffect, useState } from "react";

type ThemeMode = "dark" | "light";

/**
 * v3 theme toggle — text-only label ("Dark mode" / "Light mode").
 * No leading dot, no icon. Squared button with mono font.
 */
export default function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("theme_mode");
    const resolved: ThemeMode =
      stored === "dark" || stored === "light"
        ? stored
        : window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light";
    setTheme(resolved);
    document.documentElement.dataset.theme = resolved;
    setMounted(true);
  }, []);

  const toggleTheme = () => {
    const next: ThemeMode = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("theme_mode", next);
    document.documentElement.dataset.theme = next;
  };

  // Stable placeholder until hydrated
  if (!mounted) {
    return (
      <button
        type="button"
        className="theme-toggle"
        aria-label="Toggle theme"
      >
        Dark mode
      </button>
    );
  }

  return (
    <>
      <button
        type="button"
        onClick={toggleTheme}
        className="theme-toggle"
        aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        aria-pressed={theme === "light" ? "true" : "false"}
      >
        {theme === "dark" ? "Dark mode" : "Light mode"}
      </button>
      <div className="sr-only" role="status" aria-live="polite" id="theme-announce" />
    </>
  );
}
