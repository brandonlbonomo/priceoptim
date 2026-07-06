import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { AssetCard } from "@/components/portfolio/AssetCard";
import { portfolio } from "@/data/portfolio";

export function PortfolioPreview() {
  return (
    <section className="py-20 sm:py-28">
      <Container>
        <ScrollReveal>
          <div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end">
            <div className="max-w-xl">
              <p className="eyebrow">The Portfolio</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Property we own and operate.
              </h2>
              <p className="mt-4 text-[16px] leading-relaxed text-muted">
                Residential assets across Houston and Niagara Falls — acquired,
                redeveloped, and held for the long term.
              </p>
            </div>
            <div className="shrink-0">
              <Button href="/portfolio" variant="outline">
                View the Portfolio
              </Button>
            </div>
          </div>
        </ScrollReveal>

        <ScrollReveal variant="fade-up" delay={120} stagger={100}>
          <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {portfolio.map((asset) => (
              <AssetCard key={asset.id} asset={asset} />
            ))}
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
