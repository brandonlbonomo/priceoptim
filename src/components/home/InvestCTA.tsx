import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

export function InvestCTA() {
  return (
    <section className="hero-gradient noise relative overflow-hidden py-20 sm:py-28">
      <Container className="relative z-10">
        <ScrollReveal variant="fade-up">
          <div className="grid items-center gap-12 lg:grid-cols-2">
            <div>
              <p className="text-[12px] font-semibold uppercase tracking-[0.3em] text-gold-light">
                Private Capital
              </p>
              <div className="mt-5 ornament" />
              <h2 className="mt-7 font-display text-3xl font-medium leading-tight tracking-tight text-white sm:text-4xl">
                Private credit and private equity, backed by real assets.
              </h2>
              <p className="mt-6 max-w-xl text-[16px] font-light leading-relaxed text-white/60">
                Beyond the property we own directly, BLB Realty invests in private
                credit and private equity — deploying patient capital alongside
                partners who value discretion and a long-term horizon. We work
                with a select group of investors by introduction.
              </p>
              <div className="mt-9">
                <Button href="/invest" size="lg" variant="secondary">
                  Speak With the Firm
                </Button>
              </div>
            </div>

            <div className="lg:pl-10">
              <dl className="divide-y divide-white/10 border-y border-white/10">
                {[
                  { k: "Strategy", v: "Real-estate-backed private credit & equity" },
                  { k: "Approach", v: "Patient, long-term, relationship-driven" },
                  { k: "Access", v: "By introduction, for qualified investors" },
                ].map((row) => (
                  <div key={row.k} className="flex items-baseline justify-between gap-6 py-5">
                    <dt className="text-[11px] uppercase tracking-[0.18em] text-gold-light/80">
                      {row.k}
                    </dt>
                    <dd className="text-right text-[14px] text-white/70">{row.v}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
