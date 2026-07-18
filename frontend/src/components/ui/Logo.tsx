/**
 * Riwaq v3 Logo — Three abstracted arches with a pulse dot.
 *
 * Three overlapping arches (outer two at 35% opacity, centre at full)
 * with a small verified-green dot at the apex of the centre arch.
 * The dot is the brand mark's identity, not a UI status indicator.
 *
 * No framer-motion, no glow filter. Static SVG.
 */

interface RiwaqLogoProps {
  className?: string;
  /** Use paper-ink colors (for the admit-card letterhead on cream paper) */
  paper?: boolean;
}

export function RiwaqLogo({ className = "h-6 w-6", paper = false }: RiwaqLogoProps) {
  const archColor = paper ? "#1C3344" : "currentColor";
  const dotColor = paper ? "#146353" : "var(--verified)";

  return (
    <svg
      viewBox="0 0 40 40"
      className={className}
      aria-hidden="true"
      style={{ color: "var(--text)" }}
    >
      {/* Left arch (35% opacity) */}
      <path
        d="M4 34 L4 18 A6 6 0 0 1 16 18 L16 34 Z"
        fill={archColor}
        opacity={paper ? 0.35 : 0.35}
      />
      {/* Centre arch (full opacity) */}
      <path
        d="M14 34 L14 18 A6 6 0 0 1 26 18 L26 34 Z"
        fill={archColor}
      />
      {/* Right arch (35% opacity) */}
      <path
        d="M24 34 L24 18 A6 6 0 0 1 36 18 L36 34 Z"
        fill={archColor}
        opacity={paper ? 0.35 : 0.35}
      />
      {/* Pulse dot at apex — brand mark identity, NOT a status indicator */}
      <circle cx="20" cy="14" r="2" fill={dotColor} />
    </svg>
  );
}
