"use client";

import { useRef } from "react";
import {
  monthlyNetCashFlow2026 as monthly,
  cashFlowProjection as proj,
  equityByProperty,
  revenueByYear,
  SERIES_COLORS,
} from "@/data/investorModel";
import {
  fmtUSD,
  fmtCompactUSD,
  Legend,
  ChartTooltip,
  useTooltip,
  localXY,
} from "./chartkit";

const AXIS = "#c9c2af"; // recessive grid/axis on cream
const INK = "#6d6a5b"; // muted text token

/* ============ 1. Monthly net cash flow (2026) — bars, actual vs projected ============ */

export function MonthlyCashFlowChart() {
  const { tip, show, hide } = useTooltip();
  const wrap = useRef<HTMLDivElement>(null);
  const data = monthly.points;
  const cut = monthly.actualThroughIndex;

  const W = 720, H = 320, padL = 50, padR = 14, padT = 14, padB = 28;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const vals = data.map((d) => d.value);
  const yMin = Math.floor(Math.min(0, ...vals) / 2500) * 2500;
  const yMax = Math.ceil(Math.max(...vals) / 2500) * 2500;
  const y = (v: number) => padT + plotH * (1 - (v - yMin) / (yMax - yMin));
  const zeroY = y(0);
  const band = plotW / data.length;
  const barW = band * 0.58;

  const ticks: number[] = [];
  for (let t = yMin; t <= yMax; t += 2500) ticks.push(t);

  return (
    <div ref={wrap} className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Monthly net cash flow, 2026">
        <defs>
          <pattern id="fc-hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
            <rect width="6" height="6" fill={SERIES_COLORS.green} opacity="0.16" />
            <line x1="0" y1="0" x2="0" y2="6" stroke={SERIES_COLORS.green} strokeWidth="2.5" opacity="0.55" />
          </pattern>
        </defs>

        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} stroke={AXIS} strokeWidth={t === 0 ? 1.2 : 0.6} opacity={t === 0 ? 0.9 : 0.5} />
            <text x={padL - 8} y={y(t) + 3.5} textAnchor="end" fontSize="10.5" fill={INK}>{fmtCompactUSD(t)}</text>
          </g>
        ))}

        {data.map((d, i) => {
          const x = padL + i * band + (band - barW) / 2;
          const top = Math.min(y(d.value), zeroY);
          const h = Math.abs(zeroY - y(d.value));
          const isFc = i > cut;
          return (
            <g key={d.month}
              onPointerEnter={(e) => show({ ...localXY(e, wrap.current), title: `${d.month} 2026`, rows: [{ label: isFc ? "Projected" : "Actual", value: fmtUSD(d.value), color: SERIES_COLORS.green }] })}
              onPointerMove={(e) => show({ ...localXY(e, wrap.current), title: `${d.month} 2026`, rows: [{ label: isFc ? "Projected" : "Actual", value: fmtUSD(d.value), color: SERIES_COLORS.green }] })}
              onPointerLeave={hide}>
              {/* invisible hit area */}
              <rect x={padL + i * band} y={padT} width={band} height={plotH} fill="transparent" />
              <rect x={x} y={top} width={barW} height={Math.max(h, 1)} rx="3"
                fill={isFc ? "url(#fc-hatch)" : SERIES_COLORS.green}
                stroke={isFc ? SERIES_COLORS.green : "none"} strokeWidth={isFc ? 1 : 0} strokeOpacity={0.5} />
            </g>
          );
        })}

        {data.map((d, i) => (
          <text key={d.month} x={padL + i * band + band / 2} y={H - 9} textAnchor="middle" fontSize="10.5" fill={INK}>{d.month}</text>
        ))}
      </svg>
      <div className="mt-3"><Legend items={[{ label: "Actual (Jan–Jun)", color: SERIES_COLORS.green }, { label: "Projected (Jul–Dec)", color: "#9ec4a3" }]} /></div>
      <ChartTooltip tip={tip} />
    </div>
  );
}

/* ============ 2. 10-year cash-flow projection — multi-series line ============ */

export function CashFlowProjectionChart() {
  const { tip, show, hide } = useTooltip();
  const wrap = useRef<HTMLDivElement>(null);
  const { years, series } = proj;

  const W = 720, H = 360, padL = 52, padR = 68, padT = 18, padB = 30;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const yMax = Math.ceil(Math.max(...series.flatMap((s) => s.values)) / 50000) * 50000;
  const x = (i: number) => padL + (plotW * i) / (years.length - 1);
  const y = (v: number) => padT + plotH * (1 - v / yMax);

  const ticks: number[] = [];
  for (let t = 0; t <= yMax; t += 50000) ticks.push(t);

  function onMove(e: React.PointerEvent) {
    const { x: mx, y: my } = localXY(e, wrap.current);
    const rel = Math.max(0, Math.min(1, (mx - padL) / plotW));
    const i = Math.round(rel * (years.length - 1));
    show({
      x: x(i), y: my, title: `${years[i]}`,
      rows: series.map((s) => ({ label: s.label, value: fmtCompactUSD(s.values[i]), color: s.color })),
    });
  }

  return (
    <div ref={wrap} className="relative">
      <div className="mb-3"><Legend items={series.map((s) => ({ label: s.label, color: s.color }))} /></div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Ten-year net cash flow projection"
        onPointerMove={onMove} onPointerLeave={hide}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} stroke={AXIS} strokeWidth="0.6" opacity="0.5" />
            <text x={padL - 8} y={y(t) + 3.5} textAnchor="end" fontSize="10.5" fill={INK}>{fmtCompactUSD(t)}</text>
          </g>
        ))}
        {years.map((yr, i) => (
          (i % 2 === 0 || i === years.length - 1) && (
            <text key={yr} x={x(i)} y={H - 9} textAnchor="middle" fontSize="10.5" fill={INK}>{yr}</text>
          )
        ))}

        {tip && <line x1={tip.x} x2={tip.x} y1={padT} y2={padT + plotH} stroke={AXIS} strokeWidth="1" opacity="0.8" />}

        {series.map((s) => {
          const d = s.values.map((v, i) => `${i === 0 ? "M" : "L"}${x(i)},${y(v)}`).join(" ");
          return (
            <g key={s.key}>
              <path d={d} fill="none" stroke={s.color} strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
              <circle cx={x(years.length - 1)} cy={y(s.values[years.length - 1])} r="3.5" fill={s.color} stroke="#fff" strokeWidth="1.5" />
              <text x={W - padR + 6} y={y(s.values[years.length - 1]) + 3.5} fontSize="10.5" fontWeight="600" fill={s.color}>
                {fmtCompactUSD(s.values[years.length - 1])}
              </text>
            </g>
          );
        })}
      </svg>
      <ChartTooltip tip={tip} />
    </div>
  );
}

/* ============ 3. Equity by property — horizontal bars ============ */

export function EquityByPropertyChart() {
  const total = equityByProperty.reduce((s, p) => s + p.equity, 0);
  const max = Math.max(...equityByProperty.map((p) => p.equity));
  const W = 720, rowH = 52, padL = 4, padR = 4, barLeft = 150, barRight = 96;
  const barMax = W - barLeft - barRight;
  const H = equityByProperty.length * rowH + 8;

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Equity by property">
        {equityByProperty.map((p, i) => {
          const cy = i * rowH + rowH / 2;
          const w = (p.equity / max) * barMax;
          return (
            <g key={p.name}>
              <text x={padL} y={cy - 3} fontSize="13" fontWeight="600" fill="#1e2333">{p.name}</text>
              <text x={padL} y={cy + 13} fontSize="10.5" fill={INK}>{p.market}</text>
              <rect x={barLeft} y={cy - 12} width={barMax} height={24} rx="4" fill={AXIS} opacity="0.22" />
              <rect x={barLeft} y={cy - 12} width={Math.max(w, 2)} height={24} rx="4" fill={p.color} />
              <text x={barLeft + Math.max(w, 2) + 10} y={cy + 4} fontSize="12.5" fontWeight="700" fill="#1e2333">{fmtCompactUSD(p.equity)}</text>
            </g>
          );
        })}
      </svg>
      <p className="mt-2 text-center text-[12px] text-muted">
        Total portfolio equity <span className="font-semibold text-hunter">{fmtCompactUSD(total)}</span> across {equityByProperty.length} properties
      </p>
    </div>
  );
}

/* ============ 4. Revenue by year — bars, single hue ============ */

export function RevenueByYearChart() {
  const { tip, show, hide } = useTooltip();
  const wrap = useRef<HTMLDivElement>(null);
  const data = revenueByYear;
  const W = 720, H = 300, padL = 52, padR = 14, padT = 26, padB = 28;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const yMax = Math.ceil(Math.max(...data.map((d) => d.value)) / 100000) * 100000;
  const y = (v: number) => padT + plotH * (1 - v / yMax);
  const band = plotW / data.length;
  const barW = Math.min(band * 0.5, 130);

  const ticks: number[] = [];
  for (let t = 0; t <= yMax; t += 100000) ticks.push(t);

  return (
    <div ref={wrap} className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Annual revenue">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} stroke={AXIS} strokeWidth="0.6" opacity="0.5" />
            <text x={padL - 8} y={y(t) + 3.5} textAnchor="end" fontSize="10.5" fill={INK}>{fmtCompactUSD(t)}</text>
          </g>
        ))}
        {data.map((d, i) => {
          const x = padL + i * band + (band - barW) / 2;
          return (
            <g key={d.year}
              onPointerEnter={(e) => show({ ...localXY(e, wrap.current), title: d.year, rows: [{ label: d.note, value: fmtUSD(d.value), color: SERIES_COLORS.green }] })}
              onPointerMove={(e) => show({ ...localXY(e, wrap.current), title: d.year, rows: [{ label: d.note, value: fmtUSD(d.value), color: SERIES_COLORS.green }] })}
              onPointerLeave={hide}>
              <rect x={padL + i * band} y={padT} width={band} height={plotH} fill="transparent" />
              <rect x={x} y={y(d.value)} width={barW} height={plotH - (y(d.value) - padT)} rx="4" fill={SERIES_COLORS.green} />
              <text x={x + barW / 2} y={y(d.value) - 8} textAnchor="middle" fontSize="12.5" fontWeight="700" fill="#1e2333">{fmtCompactUSD(d.value)}</text>
              <text x={x + barW / 2} y={H - 9} textAnchor="middle" fontSize="11.5" fill={INK}>{d.year}</text>
            </g>
          );
        })}
      </svg>
      <ChartTooltip tip={tip} />
    </div>
  );
}
