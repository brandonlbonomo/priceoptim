import { headline, AS_OF } from "@/data/investorModel";
import {
  MonthlyCashFlowChart,
  CashFlowProjectionChart,
  EquityByPropertyChart,
  RevenueByYearChart,
} from "./charts";
import { RequestPacket } from "./RequestPacket";

const tiles: { value: string; label: string; projected?: boolean }[] = [
  { value: "$1.63M", label: "Portfolio value" },
  { value: "$374K", label: "Portfolio equity" },
  { value: "1.39×", label: "Equity multiple on cash" },
  { value: "$28.3K", label: "Revenue run-rate / mo" },
  { value: "22%", label: "Stabilized cash-on-cash", projected: true },
  {
    value: `${headline.units}`,
    label: `Units across ${headline.properties} properties`,
  },
];

function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-[6px] border border-hunter/10 bg-white p-6 sm:p-8">
      <h4 className="font-display text-[17px] font-medium text-hunter">{title}</h4>
      <p className="mt-1 text-[13px] leading-relaxed text-muted">{subtitle}</p>
      <div className="mt-6">{children}</div>
    </div>
  );
}

export function InvestorDashboard() {
  return (
    <div className="space-y-6">
      {/* Headline tiles */}
      <div className="rounded-[6px] bg-white p-8 sm:p-10">
        <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
          {tiles.map((t) => (
            <div key={t.label} className="text-center">
              <div className="font-display text-3xl font-medium text-hunter sm:text-4xl">
                {t.value}
                {t.projected && (
                  <span className="align-super text-[14px] text-gold-dark">*</span>
                )}
              </div>
              <div className="mt-1.5 text-[11px] uppercase tracking-[0.16em] text-muted">
                {t.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Projection — the hero chart */}
      <ChartCard
        title="10-year net cash flow projection"
        subtitle="Current portfolio compounding organically, plus expansion scenarios of one or two new homes per year."
      >
        <CashFlowProjectionChart />
      </ChartCard>

      {/* Two-up */}
      <div className="grid gap-6 lg:grid-cols-2">
        <ChartCard
          title="Monthly net cash flow — 2026"
          subtitle="The ramp to profitability. January–June actual; July–December projected."
        >
          <MonthlyCashFlowChart />
        </ChartCard>
        <ChartCard
          title="Portfolio revenue by year"
          subtitle="Total income. 2025 is a partial year — operations began that September."
        >
          <RevenueByYearChart />
        </ChartCard>
      </div>

      {/* Equity composition */}
      <ChartCard
        title="Equity by property"
        subtitle="Down payments, forced appreciation from redevelopment, and loan paydown across the portfolio."
      >
        <EquityByPropertyChart />
      </ChartCard>

      {/* Tier 2 — higher-intent ask, shown now that they've unlocked */}
      <RequestPacket />

      <p className="border-t border-hunter/10 pt-6 text-center text-[12px] leading-relaxed text-muted/70">
        Figures from BLB Realty&apos;s internal portfolio model, as of {AS_OF}.
        Actuals are unaudited; *projected and forward-year values are
        model forecasts, not guarantees of future results or an offer. Full
        underwriting is shared with qualified investors under definitive
        documentation.
      </p>
    </div>
  );
}
