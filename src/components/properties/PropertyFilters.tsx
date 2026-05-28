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
    <div className="flex flex-wrap items-center gap-4">
      <SlidersHorizontal className="h-5 w-5 text-muted" />
      <select
        value={guests}
        onChange={(e) => updateParams("guests", e.target.value)}
        className="rounded-lg border border-gray-300 px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
      >
        <option value="">Any guests</option>
        <option value="2">2+ guests</option>
        <option value="4">4+ guests</option>
        <option value="6">6+ guests</option>
      </select>

      <select
        value={bedrooms}
        onChange={(e) => updateParams("bedrooms", e.target.value)}
        className="rounded-lg border border-gray-300 px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
      >
        <option value="">Any bedrooms</option>
        <option value="1">1+ bedrooms</option>
        <option value="2">2+ bedrooms</option>
        <option value="3">3+ bedrooms</option>
      </select>

      {(guests || bedrooms) && (
        <button
          onClick={() => router.push("/properties")}
          className="text-sm text-primary underline hover:text-primary-light"
        >
          Clear filters
        </button>
      )}
    </div>
  );
}
