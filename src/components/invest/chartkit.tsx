"use client";

import { useState, useCallback } from "react";

/* ---------- formatters ---------- */

export function fmtUSD(n: number): string {
  const sign = n < 0 ? "-" : "";
  return `${sign}$${Math.abs(Math.round(n)).toLocaleString("en-US")}`;
}

export function fmtCompactUSD(n: number): string {
  const sign = n < 0 ? "-" : "";
  const a = Math.abs(n);
  if (a >= 1_000_000) return `${sign}$${(a / 1_000_000).toFixed(2)}M`;
  if (a >= 1_000) return `${sign}$${Math.round(a / 1_000)}K`;
  return `${sign}$${Math.round(a)}`;
}

/* ---------- legend ---------- */

export function Legend({
  items,
}: {
  items: { label: string; color: string }[];
}) {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-5 gap-y-2">
      {items.map((it) => (
        <span key={it.label} className="flex items-center gap-2">
          <span
            className="h-2.5 w-2.5 rounded-full"
            style={{ backgroundColor: it.color }}
          />
          <span className="text-[12px] font-medium text-hunter/80">
            {it.label}
          </span>
        </span>
      ))}
    </div>
  );
}

/* ---------- tooltip (pixel-positioned, viewBox-safe) ---------- */

export interface TooltipState {
  x: number;
  y: number;
  title: string;
  rows: { label: string; value: string; color?: string }[];
}

export function useTooltip() {
  const [tip, setTip] = useState<TooltipState | null>(null);
  const show = useCallback((t: TooltipState) => setTip(t), []);
  const hide = useCallback(() => setTip(null), []);
  return { tip, show, hide };
}

export function ChartTooltip({ tip }: { tip: TooltipState | null }) {
  if (!tip) return null;
  return (
    <div
      className="pointer-events-none absolute z-20 -translate-x-1/2 -translate-y-full rounded-[4px] border border-hunter/10 bg-white px-3 py-2 text-left shadow-lg"
      style={{ left: tip.x, top: tip.y - 10 }}
    >
      <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-hunter">
        {tip.title}
      </div>
      <div className="mt-1 space-y-0.5">
        {tip.rows.map((r) => (
          <div key={r.label} className="flex items-center gap-2 text-[12px]">
            {r.color && (
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: r.color }}
              />
            )}
            <span className="text-muted">{r.label}</span>
            <span className="ml-auto font-semibold text-foreground">
              {r.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Map a pointer event to coordinates inside the chart's positioned wrapper. */
export function localXY(
  e: React.PointerEvent | React.MouseEvent,
  wrapper: HTMLElement | null,
): { x: number; y: number } {
  if (!wrapper) return { x: 0, y: 0 };
  const r = wrapper.getBoundingClientRect();
  return { x: e.clientX - r.left, y: e.clientY - r.top };
}
