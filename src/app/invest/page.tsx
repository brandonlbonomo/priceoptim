import type { Metadata } from "next";
import { Building2, Landmark, ScrollText, HandshakeIcon } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { UnlockGate } from "@/components/ui/UnlockGate";
import { portfolioStats } from "@/data/portfolio";

export const metadata: Metadata = {
  title: "Invest — Private Capital",
  description:
    "BLB Realty operates in private credit and private equity, backed by residential real estate. We work with a select group of investors by introduction. Speak with the firm.",
  alternates: { canonical: "/invest" },
};

const strategies = [
  {
    icon: ScrollText,
    title: "Private Credit",
    body:
      "Secured lending against residential real estate — structured for capital preservation and steady, contractual income, with real assets behind every position.",
  },
  {
    icon: Landmark,
    title: "Private Equity",
    body:
      "Direct equity in acquisition, development, and redevelopment — value created through sourcing, construction, and long-term operation of the property we own.",
  },
  {
    icon: Building2,
    title: "Real Assets",
    body:
      "Every strategy is anchored to tangible property in markets we know. We invest our own capital alongside our partners in the same opportunities.",
  },
];

// ▼▼▼ EDIT THESE — headline figures from the BLB Realty portfolio model.
//     Actuals as of June 2026; items marked projected carry an asterisk.
//     Unit/property counts pull live from the portfolio data. ▼▼▼
const NUMBERS_AS_OF = "June 2026";
const investorNumbers: { value: string; label: string; projected?: boolean }[] = [
  { value: "$1.63M", label: "Portfolio value" },
  { value: "$374K", label: "Portfolio equity" },
  { value: "1.39×", label: "Equity multiple on cash" },
  { value: "$28.3K", label: "Revenue run-rate / mo" },
  { value: "22%", label: "Stabilized cash-on-cash", projected: true },
  {
    value: `${portfolioStats.units}`,
    label: `Units across ${portfolioStats.assets} properties`,
  },
];
// ▲▲▲ END EDITABLE NUMBERS ▲▲▲

const principles = [
  { k: "Horizon", v: "Long-term. We hold and compound rather than trade." },
  { k: "Alignment", v: "The firm invests its own capital beside its partners." },
  { k: "Access", v: "By introduction, for qualified and accredited investors." },
  { k: "Discretion", v: "Relationships are handled privately and personally." },
];

export default function InvestPage() {
  return (
    <>
      <PageHeader
        tone="dark"
        eyebrow="Private Capital"
        title="Patient capital, backed by real assets."
        intro="Alongside the property we own directly, BLB Realty operates in private credit and private equity — deploying capital behind residential real estate for investors who value a long horizon and quiet discipline."
        breadcrumbs={[{ label: "Home", href: "/" }, { label: "Invest" }]}
      />

      {/* Strategies */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="max-w-2xl">
              <p className="eyebrow">What We Do</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Two strategies, one foundation.
              </h2>
              <p className="mt-4 text-[16px] leading-relaxed text-muted">
                We put private capital to work in the same real estate we
                acquire, build, and operate — never further than one step from a
                tangible asset.
              </p>
            </div>
          </ScrollReveal>

          <ScrollReveal variant="fade-up" delay={120} stagger={120}>
            <div className="mt-14 grid gap-6 sm:grid-cols-3">
              {strategies.map((s) => (
                <div key={s.title} className="glass-card rounded-[3px] p-8">
                  <div className="flex h-11 w-11 items-center justify-center rounded-[2px] bg-hunter/[0.05]">
                    <s.icon className="h-5 w-5 text-gold-dark" />
                  </div>
                  <h3 className="mt-6 font-display text-[20px] font-medium text-hunter">
                    {s.title}
                  </h3>
                  <p className="mt-3 text-[15px] leading-relaxed text-muted">
                    {s.body}
                  </p>
                </div>
              ))}
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* Principles */}
      <section className="border-y border-hunter/10 bg-cream py-20 sm:py-28">
        <Container>
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-20">
            <ScrollReveal>
              <div>
                <p className="eyebrow">How We Work</p>
                <h2 className="mt-5 font-display text-3xl font-medium leading-tight tracking-tight text-hunter sm:text-4xl">
                  A small group of partners, over a long horizon.
                </h2>
                <p className="mt-5 text-[16px] leading-relaxed text-muted">
                  We are deliberately selective about who we work with and how we
                  grow. Capital is deployed carefully, positions are backed by
                  real property, and every relationship is handled with
                  discretion.
                </p>
              </div>
            </ScrollReveal>
            <ScrollReveal variant="fade-up" delay={120}>
              <dl className="divide-y divide-hunter/10 border-y border-hunter/10">
                {principles.map((row) => (
                  <div key={row.k} className="grid grid-cols-3 gap-6 py-5">
                    <dt className="text-[11px] font-semibold uppercase tracking-[0.16em] text-gold-dark">
                      {row.k}
                    </dt>
                    <dd className="col-span-2 text-[15px] leading-relaxed text-charcoal">
                      {row.v}
                    </dd>
                  </div>
                ))}
              </dl>
            </ScrollReveal>
          </div>
        </Container>
      </section>

      {/* The Numbers — gated behind email + phone */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="mx-auto max-w-2xl text-center">
              <p className="eyebrow">The Numbers</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                See the performance and the math.
              </h2>
              <p className="mt-4 text-[16px] leading-relaxed text-muted">
                Portfolio performance, target returns, and the underwriting we
                run on every deal — shared with prospective partners. Enter your
                email and phone to unlock the figures.
              </p>
            </div>
          </ScrollReveal>

          <ScrollReveal variant="fade-up" delay={120}>
            <div className="mx-auto mt-12 max-w-4xl">
              <UnlockGate source="invest-numbers">
                <div className="rounded-[6px] bg-white p-8 sm:p-12">
                  <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
                    {investorNumbers.map((n) => (
                      <div key={n.label} className="text-center">
                        <div className="font-display text-3xl font-medium text-hunter sm:text-4xl">
                          {n.value}
                          {n.projected && (
                            <span className="align-super text-[14px] text-gold-dark">
                              *
                            </span>
                          )}
                        </div>
                        <div className="mt-1.5 text-[11px] uppercase tracking-[0.16em] text-muted">
                          {n.label}
                        </div>
                      </div>
                    ))}
                  </div>
                  <p className="mt-10 border-t border-hunter/10 pt-6 text-center text-[12px] leading-relaxed text-muted/70">
                    Actuals from BLB Realty&apos;s internal portfolio model as of{" "}
                    {NUMBERS_AS_OF}. *Projected / stabilized run-rate. Figures are
                    unaudited and are not a guarantee of future results or an
                    offer. Full underwriting is shared with qualified investors
                    under definitive documentation.
                  </p>
                </div>
              </UnlockGate>
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* Contact CTA */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal variant="scale">
            <div className="mx-auto max-w-3xl rounded-[4px] border border-hunter/12 bg-surface p-10 text-center sm:p-14">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-hunter/[0.05]">
                <HandshakeIcon className="h-5 w-5 text-gold-dark" />
              </div>
              <h2 className="mt-6 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Speak with the firm
              </h2>
              <p className="mx-auto mt-4 max-w-xl text-[16px] leading-relaxed text-muted">
                If you are a qualified investor interested in private credit or
                private equity opportunities with BLB Realty, we would welcome a
                conversation. Introductions are personal and confidential.
              </p>
              <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
                <Button href="mailto:blbrealtyllc@gmail.com" size="lg">
                  Email the Firm
                </Button>
                <Button href="/contact" size="lg" variant="outline">
                  Contact Us
                </Button>
              </div>
              <p className="mt-6 text-[13px] text-muted">
                <a href="tel:+15166506653" className="hover:text-hunter">
                  (516) 650-6653
                </a>
                <span className="mx-2 text-muted/40">·</span>
                <a href="mailto:blbrealtyllc@gmail.com" className="hover:text-hunter">
                  blbrealtyllc@gmail.com
                </a>
              </p>
            </div>
          </ScrollReveal>

          {/* Disclosure */}
          <p className="mx-auto mt-10 max-w-3xl text-center text-[12px] leading-relaxed text-muted/70">
            This page is for informational purposes only and does not constitute
            an offer to sell or a solicitation of an offer to buy any security or
            investment product, nor a recommendation of any investment. No
            specific opportunities, terms, or returns are offered here. Any
            investment involves risk, including the possible loss of principal.
            Opportunities, where available, are offered only to qualified
            investors through definitive documentation.
          </p>
        </Container>
      </section>
    </>
  );
}
