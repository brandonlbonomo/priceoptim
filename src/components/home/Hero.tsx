import Link from "next/link";
import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";
import { portfolioStats } from "@/data/portfolio";

export function Hero() {
  const stats = [
    { value: `${portfolioStats.assets}`, label: "Properties owned" },
    { value: `${portfolioStats.units}`, label: "Residential units" },
    { value: `${portfolioStats.markets}`, label: "Markets" },
  ];

  return (
    <section className="hero-gradient noise relative overflow-hidden py-28 sm:py-36 lg:py-44">
      <Container className="relative z-10">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-[12px] font-semibold uppercase tracking-[0.3em] text-gold-light">
            Real Estate Investment &amp; Development
          </p>
          <div className="mx-auto mt-5 ornament" />
          <h1 className="mt-8 font-display text-4xl font-medium leading-[1.08] tracking-tight text-white sm:text-5xl lg:text-6xl">
            Real estate, acquired
            <br className="hidden sm:block" /> and held for the long term.
          </h1>
          <p className="mx-auto mt-7 max-w-2xl text-[16px] font-light leading-relaxed text-white/60">
            BLB Realty acquires, builds, and redevelops residential property —
            holding a growing portfolio of rental homes with long-term tenants,
            and operating in private credit and private equity.
          </p>

          <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Button href="/portfolio" size="lg" variant="secondary">
              View the Portfolio
            </Button>
            <Button
              href="/invest"
              size="lg"
              variant="outline"
              className="border-white/25 text-white hover:border-white/50 hover:bg-white/[0.06]"
            >
              Investor Inquiry
            </Button>
          </div>

          <p className="mt-6 text-[13px] text-white/45">
            Visiting Houston or Niagara Falls?{" "}
            <Link href="/book" className="text-gold-light underline-offset-4 hover:underline">
              Book a stay direct →
            </Link>
          </p>

          {/* Firm stat strip */}
          <div className="mx-auto mt-14 grid max-w-2xl grid-cols-3 divide-x divide-white/10 border-y border-white/10 py-6">
            {stats.map((s) => (
              <div key={s.label} className="px-2">
                <div className="font-display text-3xl font-medium text-white sm:text-4xl">
                  {s.value}
                </div>
                <div className="mt-1.5 text-[11px] uppercase tracking-[0.16em] text-white/45">
                  {s.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </Container>
    </section>
  );
}
