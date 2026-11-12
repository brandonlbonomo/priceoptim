/**
 * Bonomo Capital Group portfolio — residential assets owned, redeveloped, and operated
 * by the firm across Houston, TX and Niagara Falls, NY.
 *
 * We describe strategy and standing only; we do not publish acquisition
 * prices, valuations, or returns here.
 */

export type AssetStrategy =
  | "Short-term rental"
  | "Long-term residential"
  | "Redevelopment"
  | "Development";

export interface PortfolioAsset {
  id: string;
  name: string;
  market: string;
  state: string;
  strategy: AssetStrategy;
  units: number;
  status: string;
  summary: string;
}

export const portfolio: PortfolioAsset[] = [
  {
    id: "lockwood",
    name: "Lockwood",
    market: "Houston",
    state: "TX",
    strategy: "Short-term rental",
    units: 4,
    status: "Operating",
    summary:
      "A four-door residential property in Houston's East End, acquired and repositioned as furnished short-term rentals serving visitors to the Medical Center, downtown, and EaDo.",
  },
  {
    id: "pierce",
    name: "Pierce",
    market: "Niagara Falls",
    state: "NY",
    strategy: "Long-term residential",
    units: 7,
    status: "Operating · long-term tenants",
    summary:
      "A seven-unit residential holding leased to long-term tenants, including participants in the Section 8 program — stable, income-producing housing held for the long run.",
  },
  {
    id: "bstreet",
    name: "B Street",
    market: "Niagara Falls",
    state: "NY",
    strategy: "Short-term rental",
    units: 3,
    status: "Operating",
    summary:
      "A three-unit property minutes from Niagara Falls State Park, redeveloped into hospitality-grade short-term rentals for one of the country's most-visited destinations.",
  },
  {
    id: "everton",
    name: "Everton",
    market: "Houston",
    state: "TX",
    strategy: "Short-term rental",
    units: 1,
    status: "Operating",
    summary:
      "A single-family Houston residence renovated end-to-end and operated as a design-forward short-term rental.",
  },
  {
    id: "omega",
    name: "Omega",
    market: "Houston",
    state: "TX",
    strategy: "Short-term rental",
    units: 2,
    status: "Operating",
    summary:
      "A Houston Heights redevelopment — a main house with a separate studio apartment, both complete and operating as design-forward short-term rentals.",
  },
  {
    id: "beachview",
    name: "Beach View",
    market: "30A",
    state: "FL",
    strategy: "Short-term rental",
    units: 1,
    status: "Operating · Flagship",
    summary:
      "The firm's flagship luxury residence — a design-forward beach home on Scenic 30A in Inlet Beach, Florida, a short walk from sugar-white sand and the shops of Rosemary Beach.",
  },
  {
    id: "independence-heights",
    name: "Independence Heights",
    market: "Houston",
    state: "TX",
    strategy: "Development",
    units: 5,
    status: "Under construction",
    summary:
      "A ground-up build in Houston's Independence Heights — a boutique-hotel-style residence of five rentable rooms, with a main suite and full kitchen on the first floor. Designed and furnished in-house for short-term stays.",
  },
];

/**
 * Units currently under construction — owned and mid-build, included in the
 * property and unit totals above. The Independence Heights boutique build.
 */
export const underConstructionUnits = 5;

export const portfolioStats = {
  assets: portfolio.length,
  units: portfolio.reduce((sum, a) => sum + a.units, 0),
  markets: Array.from(new Set(portfolio.map((a) => a.market))).length,
  underConstruction: underConstructionUnits,
};

/**
 * Operating revenue, annualized from the current monthly run-rate across the
 * operating portfolio — an operating-business figure, in $K. Not a return,
 * valuation, or projection (those stay in the gated investor model).
 */
// Trailing-6-month actual revenue (QuickBooks, as of Nov 2026), annualized.
export const operatingRevenueRunRateAnnualK = 325;
