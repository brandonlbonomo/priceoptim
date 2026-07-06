import { MapPin } from "lucide-react";
import type { PortfolioAsset } from "@/data/portfolio";

export function AssetCard({ asset }: { asset: PortfolioAsset }) {
  return (
    <article className="glass-card flex h-full flex-col rounded-[3px] p-7">
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
        <span className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.16em] text-muted">
          <MapPin className="h-3 w-3 text-gold-dark" />
          {asset.market}, {asset.state}
        </span>
        <span className="rounded-[2px] border border-hunter/15 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-hunter/70">
          {asset.strategy}
        </span>
      </div>

      <h3 className="mt-5 font-display text-[24px] font-medium tracking-tight text-hunter">
        {asset.name}
      </h3>

      <p className="mt-3 flex-1 text-[14px] leading-relaxed text-muted">
        {asset.summary}
      </p>

      <div className="mt-6 flex items-center justify-between border-t border-hunter/10 pt-4">
        <span className="text-[13px] text-hunter">
          <span className="font-display text-[18px] font-medium">{asset.units}</span>
          <span className="ml-1.5 text-[12px] text-muted">
            {asset.units === 1 ? "unit" : "units"}
          </span>
        </span>
        <span className="text-[11px] uppercase tracking-[0.14em] text-gold-dark">
          {asset.status}
        </span>
      </div>
    </article>
  );
}
