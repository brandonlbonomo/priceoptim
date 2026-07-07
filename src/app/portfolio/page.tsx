import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { AssetCard } from "@/components/portfolio/AssetCard";
import { PortfolioStatStrip } from "@/components/portfolio/PortfolioStatStrip";
import { portfolio, portfolioStats } from "@/data/portfolio";

export const metadata: Metadata = {
  title: "Portfolio",
  description:
    "The Bonomo Capital Group portfolio — residential property owned, redeveloped, and operated across Houston, TX and Niagara Falls, NY. Short- and long-term rentals held for the long run.",
  alternates: { canonical: "/portfolio" },
};

const stats = [
  { value: portfolioStats.assets, label: "Properties owned" },
  { value: portfolioStats.units, label: "Residential units" },
  { value: portfolioStats.markets, label: "Markets" },
  { value: portfolioStats.underConstruction, label: "Under construction", live: true },
];

export default function PortfolioPage() {
  return (
    <>
      <PageHeader
        tone="dark"
        eyebrow="The Portfolio"
        title="Property we own, redevelop, and hold."
        intro="Bonomo Capital Group builds a portfolio of residential real estate across Houston and Niagara Falls — acquiring, renovating, and operating homes as income-producing assets under management. We hold for the long term, with tenants and guests in place."
        breadcrumbs={[{ label: "Home", href: "/" }, { label: "Portfolio" }]}
      />

      {/* Stat strip — live portfolio status */}
      <PortfolioStatStrip stats={stats} />

      {/* Asset grid */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="max-w-2xl">
              <p className="eyebrow">Holdings</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Assets under management
              </h2>
              <p className="mt-4 text-[16px] leading-relaxed text-muted">
                Each property is sourced, improved, and operated in-house. We
                describe strategy and standing only — acquisition prices,
                valuations, and returns are shared privately with partners.
              </p>
            </div>
          </ScrollReveal>

          <ScrollReveal variant="fade-up" delay={120} stagger={100}>
            <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {portfolio.map((asset) => (
                <AssetCard key={asset.id} asset={asset} />
              ))}
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* Strategy */}
      <section className="border-y border-hunter/10 bg-cream py-20 sm:py-28">
        <Container>
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-20">
            <ScrollReveal>
              <div>
                <p className="eyebrow">Approach</p>
                <h2 className="mt-5 font-display text-3xl font-medium leading-tight tracking-tight text-hunter sm:text-4xl">
                  Buy well. Build carefully. Hold with patience.
                </h2>
              </div>
            </ScrollReveal>
            <ScrollReveal variant="fade-up" delay={120}>
              <div className="space-y-6 text-[16px] leading-relaxed text-muted">
                <p>
                  We acquire residential property in markets we understand,
                  improve it to a standard we would live in ourselves, and hold
                  it as a long-term asset rather than trading it. Some homes serve
                  long-term tenants; others operate as hospitality-grade
                  short-term rentals. All are managed with the same discipline.
                </p>
                <p>
                  The result is a diversified, income-producing portfolio that
                  compounds over time — and a foundation for the private capital
                  we deploy alongside it.
                </p>
                <div className="flex flex-col gap-3 pt-2 sm:flex-row">
                  <Button href="/invest">Invest With Us</Button>
                  <Button href="/book" variant="outline">
                    Book a Stay
                  </Button>
                </div>
              </div>
            </ScrollReveal>
          </div>
        </Container>
      </section>
    </>
  );
}
