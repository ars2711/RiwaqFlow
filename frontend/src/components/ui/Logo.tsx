"use client";

import { motion } from "framer-motion";

export function RiwaqLogo({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        {/* Primary gradient — uses CSS theme variables so it responds to dark/light mode */}
        <linearGradient
          id="riwaq-grad-1"
          x1="10"
          y1="90"
          x2="90"
          y2="10"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="var(--primary, #335dff)" />
          <stop offset="1" stopColor="var(--accent-violet, #8B5CF6)" />
        </linearGradient>
        <linearGradient
          id="riwaq-grad-2"
          x1="10"
          y1="10"
          x2="90"
          y2="90"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="var(--accent, #0ea5e9)" />
          <stop offset="1" stopColor="var(--primary, #335dff)" />
        </linearGradient>
        {/* Glow filter */}
        <filter id="riwaq-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      {/* Main outer portal/arch — the رواق (Riwaq) colonnade form */}
      <motion.path
        d="M 18 90 V 44 C 18 23 34 12 50 12 C 66 12 82 23 82 44 V 90"
        stroke="url(#riwaq-grad-1)"
        strokeWidth="11"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.4, ease: "easeInOut" }}
        filter="url(#riwaq-glow)"
      />

      {/* Inner flowing line — the رواق "flow" current */}
      <motion.path
        d="M 50 90 V 58 C 50 43 34 43 34 28"
        stroke="url(#riwaq-grad-2)"
        strokeWidth="11"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.4, ease: "easeInOut", delay: 0.45 }}
      />

      {/* Animated glow dot at the tip of the flow */}
      <motion.circle
        cx="34"
        cy="28"
        r="7"
        fill="var(--accent-violet, #8B5CF6)"
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.45, delay: 1.7 }}
        filter="url(#riwaq-glow)"
      />
      <motion.circle
        cx="34"
        cy="28"
        r="3.5"
        fill="var(--foreground, #ffffff)"
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 0.9 }}
        transition={{ duration: 0.3, delay: 1.85 }}
      />
    </svg>
  );
}
