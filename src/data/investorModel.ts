/**
 * Investor dashboard data — sourced from the BLB Realty portfolio model.
 * Actuals as of June 2026; forward years are model projections.
 *
 * ▼ To refresh: update these values from the spreadsheet. Everything the
 *   gated /invest dashboard renders reads from this file.
 */

export const AS_OF = "June 2026";

/** Headline tiles. */
export const headline = {
  portfolioValue: 1_633_904,
  portfolioEquity: 373_762,
  cashInvested: 268_224,
  equityMultiple: 1.39,
  revenueRunRateMo: 28_346,
  net2026: 59_884,
  net2027: 85_138,
  stabilizedCoC: 0.22, // projected
  trailingCoC: 0.12, // actual, first 9 months incl. startup
  units: 15,
  properties: 4,
  markets: 2,
};

/** Validated categorical palette (see dataviz validator). Fixed order. */
export const SERIES_COLORS = {
  green: "#3f8f4a",
  gold: "#d1a02f",
  teal: "#1f9aa2",
  rust: "#cf5a2e",
} as const;

/** Monthly portfolio net cash flow, 2026. Jan–Jun actual, Jul–Dec projected. */
export const monthlyNetCashFlow2026 = {
  actualThroughIndex: 5, // 0=Jan … 5=Jun are actuals
  points: [
    { month: "Jan", value: -2217 },
    { month: "Feb", value: -1302 },
    { month: "Mar", value: 5785 },
    { month: "Apr", value: 2500 },
    { month: "May", value: 2422 },
    { month: "Jun", value: 10171 },
    { month: "Jul", value: 7640 },
    { month: "Aug", value: 8516 },
    { month: "Sep", value: 6140 },
    { month: "Oct", value: 5520 },
    { month: "Nov", value: 7055 },
    { month: "Dec", value: 7655 },
  ],
};

/** 10-year net cash flow projection with expansion scenarios. */
export const cashFlowProjection = {
  years: [2026, 2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035],
  series: [
    {
      key: "existing",
      label: "Current portfolio",
      color: SERIES_COLORS.green,
      values: [59884, 85138, 88628, 92262, 96045, 99983, 104082, 108349, 112792, 117416],
    },
    {
      key: "plus1",
      label: "+1 home / year",
      color: SERIES_COLORS.gold,
      values: [59884, 97138, 112628, 128262, 144045, 159983, 176082, 192349, 208792, 225416],
    },
    {
      key: "plus2",
      label: "+2 homes / year",
      color: SERIES_COLORS.teal,
      values: [59884, 109138, 136628, 164262, 192045, 219983, 248082, 276349, 304792, 333416],
    },
  ],
};

/** Per-property equity (Equity Snapshot). Fixed color order by entity. */
export const equityByProperty = [
  { name: "Lockwood", market: "Houston, TX", equity: 148513, color: SERIES_COLORS.green },
  { name: "Everton", market: "Houston, TX", equity: 84481, color: SERIES_COLORS.rust },
  { name: "Pierce", market: "Niagara Falls, NY", equity: 70699, color: SERIES_COLORS.teal },
  { name: "B Street", market: "Niagara Falls, NY", equity: 70069, color: SERIES_COLORS.gold },
];

/** Portfolio annual revenue (total income). 2025 partial (ops began Sep). */
export const revenueByYear = [
  { year: "2025", value: 64748, note: "partial — ops began Sep" },
  { year: "2026", value: 271016, note: "actual + forecast" },
  { year: "2027", value: 346391, note: "projected" },
];
