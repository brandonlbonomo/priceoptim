import Link from "next/link";
import Image from "next/image";
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
    <section className="hero-gradient noise relative overflow-hidden py-24 sm:py-28 lg:py-32">
      <Container className="relative z-10">
        <div className="mx-auto max-w-5xl text-center">
          {/* The logo is the statement — front and center */}
          <Image
            src="/bonomo-mark-light.png"
            alt="Bonomo Capital Group"
            width={1162}
            height={706}
            priority
            className="mx-auto h-auto w-[300px] sm:w-[500px] lg:w-[660px]"
          />

          <h1 className="mx-auto mt-10 max-w-3xl font-display text-2xl font-medium leading-[1.18] tracking-tight text-white/90 sm:text-[28px] lg:text-[34px]">
            Real estate, acquired and held for the long term.
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-[16px] font-light leading-relaxed text-white/55">
            Bonomo Capital Group acquires, builds, and redevelops residential
            property — holding a growing portfolio of rental homes with long-term
            tenants, and operating in private credit and private equity.
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
