"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";

export default function BackButton({
  href = "/",
  label = "Back",
}: {
  href?: string;
  label?: string;
}) {
  const router = useRouter();

  return (
    <div className="mb-4">
      <button
        type="button"
        onClick={() => {
          if (window.history.length > 1) {
            router.back();
            return;
          }
          router.push(href);
        }}
        className="btn-secondary px-3 py-2 text-sm"
        aria-label={label}
      >
        <ArrowLeft className="h-4 w-4" />
        {label}
      </button>
      <Link
        href={href}
        className="ml-2 text-xs section-subtitle underline underline-offset-4"
      >
        Home
      </Link>
    </div>
  );
}
