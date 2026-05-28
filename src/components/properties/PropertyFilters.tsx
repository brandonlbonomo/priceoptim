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
    <div className="glass-surface inline-flex flex-wrap items-center gap-4 rounded-full px-6 py-3">
      <SlidersHorizontal className="h-4 w-4 text-muted" />
      <select
        value={guests}
        onChange={(e) => updateParams("guests", e.target.value)}
        className="appearance-none rounded-full border-0 bg-transparent px-3 py-1.5 text-[13px] text-foreground focus:outline-none focus:ring-0"
      >
        <option value="">Any guests</option>
        <option value="2">2+ guests</option>
        <option value="4">4+ guests</option>
        <option value="6">6+ guests</option>
      </select>

      <div className="h-4 w-px bg-black/[0.06]" />

      <select
        value={bedrooms}
        onChange={(e) => updateParams("bedrooms", e.target.value)}
        className="appearance-none rounded-full border-0 bg-transparent px-3 py-1.5 text-[13px] text-foreground focus:outline-none focus:ring-0"
      >
        <option value="">Any bedrooms</option>
        <option value="1">1+ bedrooms</option>
        <option value="2">2+ bedrooms</option>
        <option value="3">3+ bedrooms</option>
      </select>

      {(guests || bedrooms) && (
        <>
          <div className="h-4 w-px bg-black/[0.06]" />
          <button
            onClick={() => router.push("/properties")}
            className="text-[13px] text-accent-dark transition-colors duration-300 hover:text-accent"
          >
            Clear
          </button>
        </>
      )}
    </div>
  );
}
