import { Container } from "@/components/ui/Container";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

const pillars = [
  {
    no: "01",
    title: "Acquisition & Development",
    body:
      "We acquire, build, and redevelop residential property — creating value through disciplined renovation and repositioning of homes in markets we know well.",
  },
  {
    no: "02",
    title: "Rental Portfolio",
    body:
      "We hold and operate a growing portfolio of rental homes, short- and long-term, with tenants in place — income-producing assets under management, held for the long run.",
  },
  {
    no: "03",
    title: "Private Capital",
    body:
      "Through private credit and private equity, we invest alongside partners who share our conviction in patient, real-asset-backed capital.",
  },
];

export function FirmPillars() {
  return (
    <section className="border-y border-hunter/10 bg-cream py-20 sm:py-28">
      <Container>
        <ScrollReveal>
          <div className="mx-auto max-w-3xl text-center">
            <p className="eyebrow">The Firm</p>
            <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
              A vertically integrated real estate investment firm.
            </h2>
            <p className="mx-auto mt-5 max-w-2xl text-[16px] leading-relaxed text-muted">
              Bonomo Capital Group owns what it operates. We source and improve residential
              property, hold it as a long-term rental portfolio, and put private
              capital to work behind real assets.
            </p>
          </div>
        </ScrollReveal>

        <ScrollReveal variant="fade-up" delay={120} stagger={120}>
          <div className="mt-16 grid gap-12 sm:grid-cols-3 sm:gap-8">
            {pillars.map((p) => (
              <div key={p.no}>
                <div className="font-display text-[15px] font-medium text-gold-dark">
                  {p.no}
                </div>
                <div className="mt-4 rule-gold w-full max-w-[64px] sm:mx-0" />
                <h3 className="mt-6 font-display text-[21px] font-medium text-hunter">
                  {p.title}
                </h3>
                <p className="mt-3 text-[15px] leading-relaxed text-muted">
                  {p.body}
                </p>
              </div>
            ))}
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
