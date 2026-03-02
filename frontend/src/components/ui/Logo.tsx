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
        <linearGradient
          id="riwaq-grad-1"
          x1="10"
          y1="90"
          x2="90"
          y2="10"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#3B82F6" />
          <stop offset="1" stopColor="#8B5CF6" />
        </linearGradient>
        <linearGradient
          id="riwaq-grad-2"
          x1="10"
          y1="10"
          x2="90"
          y2="90"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#06B6D4" />
          <stop offset="1" stopColor="#3B82F6" />
        </linearGradient>
      </defs>

      {/* Main outer portal/arch shape representing "Riwaq" */}
      <motion.path
        d="M 20 90 V 45 C 20 25 35 15 50 15 C 65 15 80 25 80 45 V 90"
        stroke="url(#riwaq-grad-1)"
        strokeWidth="12"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.5, ease: "easeInOut" }}
      />

      {/* Inner flowing line representing "Flow" */}
      <motion.path
        d="M 50 90 V 60 C 50 45 35 45 35 30"
        stroke="url(#riwaq-grad-2)"
        strokeWidth="12"
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.5, ease: "easeInOut", delay: 0.5 }}
      />

      {/* Dynamic glowing dot */}
      <motion.circle
        cx="35"
        cy="30"
        r="6"
        fill="#ffffff"
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5, delay: 1.8 }}
      />
    </svg>
  );
}
