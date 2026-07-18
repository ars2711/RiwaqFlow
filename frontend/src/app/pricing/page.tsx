"use client";

import BackButton from "@/app/back-button";
import { Check, Zap, Star, Shield } from "lucide-react";

const plans = [
  {
    name: "Starter",
    price: "PKR 0",
    period: "/ month",
    bestFor: "Small society pilots",
    icon: Zap,
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
    <div className="app-shell">
      <div className="wrap py-10">
        <BackButton href="/" label="Back to Home" />

        <div className="my-8 text-center">
          <div className="eyebrow justify-center">
            <span className="line"></span> For Organisers
          </div>
          <h1 className="section-title">Transparent Pricing</h1>
          <p className="section-subtitle mt-4 max-w-2xl mx-auto">
            Built for NUST societies, departments, and individual organizers.
            Choose the plan tailored to your ticket volume and event complexity.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-0 border border-[var(--border)] mt-12 bg-[var(--surface)]">
          {plans.map((plan, i) => {
            const Icon = plan.icon;
            return (
              <div
                key={plan.name}
                className={`relative p-8 flex flex-col h-full border-b md:border-b-0 md:border-r border-[var(--border)] last:border-0 ${
                  plan.isPopular ? "bg-[var(--surface-2)]" : ""
                }`}
              >
                {plan.isPopular && (
                  <div className="absolute top-0 right-0 bg-[var(--verified)] text-[var(--bg)] text-[10px] font-mono font-bold px-3 py-1 uppercase tracking-widest">
                    Most Popular
                  </div>
                )}

                <div className="flex items-center gap-4 mb-6 mt-4">
                  <div className="border border-[var(--border)] p-3 bg-[var(--bg)]">
                    <Icon className="w-5 h-5 text-[var(--verified)]" />
                  </div>
                  <div>
                    <h2 className="text-xl font-display font-medium">{plan.name}</h2>
                    <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--muted)] mt-1">
                      {plan.bestFor}
                    </p>
                  </div>
                </div>

                <div className="mb-8 flex items-baseline border-b border-[var(--border)] pb-6">
                  <span className="text-3xl font-mono">
                    {plan.price}
                  </span>
                  {plan.period && (
                    <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--muted)] ml-2">
                      {plan.period}
                    </span>
                  )}
                </div>

                <ul className="space-y-4 mb-8 flex-grow">
                  {plan.features.map((feature) => (
                    <li key={feature} className="flex items-start gap-3">
                      <div className="mt-0.5 border border-[var(--border)] p-0.5 bg-[var(--bg)] shrink-0">
                        <Check className="w-3 h-3 text-[var(--verified)]" />
                      </div>
                      <span className="text-sm font-medium leading-relaxed">
                        {feature}
                      </span>
                    </li>
                  ))}
                </ul>

                <button
                  className={`w-full py-4 mt-auto text-xs font-mono font-bold uppercase tracking-widest border transition-colors ${
                    plan.isPopular
                      ? "bg-[var(--verified)] text-[var(--bg)] border-[var(--verified)] hover:bg-[var(--verified)]/90"
                      : "bg-transparent text-[var(--text)] border-[var(--border)] hover:bg-[var(--surface-2)]"
                  }`}
                >
                  Get Started
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
