"use client";

import { useEffect, useRef, useState } from "react";
import { Container } from "@/components/ui/Container";

interface Stat {
  value: number;
  label: string;
  suffix?: string;
  live?: boolean;
}

interface PortfolioStatStripProps {
  stats: Stat[];
}

function useCountUp(target: number, active: boolean, durationMs = 1100) {
  const [value, setValue] = useState(0);
  const startedRef = useRef(false);

  useEffect(() => {
    if (!active || startedRef.current) return;
    startedRef.current = true;

    let raf = 0;
    let startTs: number | null = null;

    const tick = (ts: number) => {
      if (startTs === null) startTs = ts;
      const progress = Math.min((ts - startTs) / durationMs, 1);
      // easeOutCubic for a settled, premium feel
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));
      if (progress < 1) raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [active, target, durationMs]);

  return value;
}

function StatCell({ stat, active }: { stat: Stat; active: boolean }) {
  const value = useCountUp(stat.value, active);

  return (
    <div className="group px-4 py-8 text-center transition-colors duration-300 hover:bg-hunter/[0.02]">
      <div className="flex items-center justify-center gap-2">
        <div className="font-display text-3xl font-medium tabular-nums text-hunter transition-transform duration-300 group-hover:-translate-y-0.5 sm:text-4xl">
          {value}
          {stat.suffix}
        </div>
        {stat.live && (
          <span className="relative flex h-2 w-2" aria-hidden="true">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-gold-dark/60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-gold-dark" />
          </span>
        )}
      </div>
      <div className="mt-1.5 text-[11px] uppercase tracking-[0.16em] text-muted">
        {stat.label}
      </div>
    </div>
  );
}

export function PortfolioStatStrip({ stats }: PortfolioStatStripProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setActive(true);
          observer.disconnect();
        }
      },
      { threshold: 0.35 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <section className="border-b border-hunter/10 bg-cream">
      <Container>
        <div className="flex items-center justify-center gap-2 pt-8 sm:justify-start">
          <span className="relative flex h-1.5 w-1.5" aria-hidden="true">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-600/50" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-green-600" />
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted">
            Portfolio status · Live
          </span>
        </div>
        <div
          ref={ref}
          className="grid grid-cols-2 divide-x divide-y divide-hunter/10 sm:grid-cols-4 sm:divide-y-0"
        >
          {stats.map((stat) => (
            <StatCell key={stat.label} stat={stat} active={active} />
          ))}
        </div>
      </Container>
    </section>
  );
}
