"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";
import { SlidersHorizontal } from "lucide-react";

export function PropertyFilters() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const guests = searchParams.get("guests") || "";
  const bedrooms = searchParams.get("bedrooms") || "";

  const updateParams = useCallback(
    (key: string, value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (value) {
        params.set(key, value);
      } else {
        params.delete(key);
      }
      router.push(`/properties?${params.toString()}`);
    },
    [router, searchParams],
  );

  return (
    <div className="glass-card inline-flex flex-wrap items-center gap-4 rounded-2xl px-5 py-3">
      <SlidersHorizontal className="h-4 w-4 text-muted" />
      <select
        value={guests}
        onChange={(e) => updateParams("guests", e.target.value)}
        className="appearance-none rounded-xl border border-gray-200 bg-white/80 px-4 py-2 text-sm text-foreground backdrop-blur-sm transition-all duration-200 focus:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/15"
      >
        <option value="">Any guests</option>
        <option value="2">2+ guests</option>
        <option value="4">4+ guests</option>
        <option value="6">6+ guests</option>
      </select>

      <select
        value={bedrooms}
        onChange={(e) => updateParams("bedrooms", e.target.value)}
        className="appearance-none rounded-xl border border-gray-200 bg-white/80 px-4 py-2 text-sm text-foreground backdrop-blur-sm transition-all duration-200 focus:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/15"
      >
        <option value="">Any bedrooms</option>
        <option value="1">1+ bedrooms</option>
        <option value="2">2+ bedrooms</option>
        <option value="3">3+ bedrooms</option>
      </select>

      {(guests || bedrooms) && (
        <button
          onClick={() => router.push("/properties")}
          className="rounded-xl px-3 py-1.5 text-sm font-medium text-primary transition-all duration-200 hover:bg-primary/5"
        >
          Clear
        </button>
      )}
    </div>
  );
}
