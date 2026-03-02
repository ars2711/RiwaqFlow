"use client";

import BackButton from "@/app/back-button";
import { motion } from "framer-motion";
import { Check, Zap, Star, Shield } from "lucide-react";

const plans = [
  {
    name: "Starter",
    price: "PKR 0",
    period: "/ month",
    bestFor: "Small society pilots",
    icon: Zap,
    color: "from-blue-400 to-cyan-400",
    bgLight: "bg-blue-500/10 text-blue-400",
    features: [
      "Up to 2 active events",
      "Up to 200 tickets/event",
      "Basic scanner controls",
      "CSV import (manual)",
    ],
  },
  {
    name: "Pro",
    price: "PKR 9,500",
    period: "/ month",
    bestFor: "Active societies & departments",
    icon: Star,
    isPopular: true,
    color: "from-violet-400 to-fuchsia-400",
    bgLight: "bg-violet-500/10 text-violet-400",
    features: [
      "Up to 10 active events",
      "Up to 2,000 tickets/event",
      "Bulk import + scan export",
      "Advanced scanner allowlists",
    ],
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    bestFor: "University-wide operations",
    icon: Shield,
    color: "from-amber-400 to-orange-400",
    bgLight: "bg-amber-500/10 text-amber-400",
    features: [
      "Unlimited events & tickets",
      "Dedicated support + SLAs",
      "Advanced analytics & integrations",
      "Production wallet issuer setup",
    ],
  },
];

export default function PricingPage() {
  return (
    <div className="app-shell relative min-h-screen overflow-hidden p-6">
      {/* Background Ambience */}
      <div className="absolute top-[-10%] left-[-10%] w-96 h-96 bg-blue-500/20 rounded-full blur-[120px] pointer-events-none dark:opacity-40" />
      <div className="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-violet-500/20 rounded-full blur-[120px] pointer-events-none dark:opacity-40" />

      <div className="max-w-6xl mx-auto space-y-12 relative z-10 pt-16">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center space-y-4 pt-8"
        >
          <div className="flex justify-center mb-6">
            <BackButton href="/" label="Home" />
          </div>
          <h1 className="text-5xl font-black tracking-tight bg-clip-text text-transparent bg-gradient-to-br from-[var(--fg)] to-[var(--fg-muted)]">
            Simple, transparent pricing
          </h1>
          <p className="text-lg text-[var(--fg-muted)] max-w-2xl mx-auto">
            Built for NUST societies, departments, and individual organizers.
            Choose the plan tailored to your ticket volume and event complexity.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-3 gap-6 lg:gap-8 items-start mt-10">
          {plans.map((plan, i) => {
            const Icon = plan.icon;
            return (
              <motion.div
                key={plan.name}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.15, type: "spring", stiffness: 100 }}
                className={`relative glass-panel rounded-3xl p-8 flex flex-col h-full transition-transform hover:-translate-y-2 hover:shadow-2xl ${
                  plan.isPopular
                    ? "border-[var(--primary)] shadow-[0_0_40px_rgba(59,130,246,0.15)] ring-1 ring-[#3B82F6]/50"
                    : ""
                }`}
              >
                {plan.isPopular && (
                  <div className="absolute -top-4 inset-x-0 flex justify-center">
                    <span className="bg-gradient-to-r from-blue-500 to-violet-500 text-white text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wider shadow-lg">
                      Most Popular
                    </span>
                  </div>
                )}

                <div className="flex items-center gap-4 mb-6">
                  <div className={`p-3 rounded-2xl ${plan.bgLight}`}>
                    <Icon className="w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold">{plan.name}</h2>
                    <p className="text-sm text-[var(--fg-muted)]">
                      {plan.bestFor}
                    </p>
                  </div>
                </div>

                <div className="mb-8 flex items-baseline">
                  <span className="text-4xl font-black tracking-tight">
                    {plan.price}
                  </span>
                  {plan.period && (
                    <span className="text-[var(--fg-muted)] ml-2 font-medium">
                      {plan.period}
                    </span>
                  )}
                </div>

                <ul className="space-y-4 mb-8 flex-grow">
                  {plan.features.map((feature) => (
                    <li key={feature} className="flex items-start gap-3">
                      <div className="mt-1 bg-[var(--fg)]/5 p-1 rounded-full border border-[var(--border)] shrink-0">
                        <Check className="w-3 h-3 text-[var(--primary)]" />
                      </div>
                      <span className="text-sm font-medium leading-relaxed">
                        {feature}
                      </span>
                    </li>
                  ))}
                </ul>

                <button
                  className={`w-full py-4 mt-auto text-sm font-bold rounded-xl transition-all ${
                    plan.isPopular
                      ? "bg-[var(--primary)] text-white hover:bg-blue-600 hover:shadow-lg hover:shadow-blue-500/25"
                      : "bg-[var(--fg)]/5 hover:bg-[var(--fg)]/10 border border-[var(--border)]"
                  }`}
                >
                  Get Started
                </button>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
