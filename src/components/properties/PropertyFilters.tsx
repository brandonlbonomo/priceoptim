"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useState } from "react";
import { SlidersHorizontal, Search } from "lucide-react";

export function PropertyFilters() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const q = searchParams.get("q") || "";
  const guests = searchParams.get("guests") || "";
  const bedrooms = searchParams.get("bedrooms") || "";
  const [searchValue, setSearchValue] = useState(q);

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

  const handleSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      updateParams("q", searchValue);
    },
    [searchValue, updateParams],
  );

  return (
    <div className="glass-surface inline-flex flex-wrap items-center gap-4 rounded-full px-6 py-3">
      <form onSubmit={handleSearch} className="flex items-center gap-2">
        <Search className="h-4 w-4 text-muted" />
        <input
          type="text"
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          placeholder="Search properties..."
          className="w-32 border-0 bg-transparent text-[13px] text-foreground placeholder:text-muted/60 focus:outline-none focus:ring-0 sm:w-40"
        />
      </form>
      <div className="h-4 w-px bg-black/[0.06]" />
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

      {(q || guests || bedrooms) && (
        <>
          <div className="h-4 w-px bg-black/[0.06]" />
          <button
            onClick={() => {
              setSearchValue("");
              router.push("/properties");
            }}
            className="text-[13px] text-gold-dark transition-colors duration-300 hover:text-gold"
          >
            Clear
          </button>
        </>
      )}
    </div>
  );
}
