import type { Metadata } from "next";
import Link from "next/link";
import { Building2, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { getAllReviews } from "@/data/reviews";
import { portfolioStats } from "@/data/portfolio";

export const metadata: Metadata = {
  title: "About the Firm",
  description:
    "Bonomo Capital Group — a real estate investment firm that acquires, builds, and redevelops residential property, holds a growing rental portfolio, and operates in private credit and private equity.",
  alternates: { canonical: "/about" },
};

export default function AboutPage() {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";
  const reviews = getAllReviews();

  const stats = [
    { label: "Properties owned", value: `${portfolioStats.assets}` },
    { label: "Residential units", value: `${portfolioStats.units}` },
    { label: "Markets", value: `${portfolioStats.markets}` },
    { label: "Guest reviews", value: `${reviews.length}+` },
  ];

  const values = [
    {
      title: "Ownership, not speculation",
      body:
        "We buy to hold. Property is acquired to be improved and operated over the long term, compounding value rather than trading it.",
    },
    {
      title: "Vertical integration",
      body:
        "We source, renovate, and manage in-house. Owning the whole process is how we protect quality and returns alike.",
    },
    {
      title: "Real assets behind capital",
      body:
        "From the rental portfolio to private credit and equity, every dollar we deploy stands one step from a tangible building.",
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: "Bonomo Capital Group",
    legalName: "Bonomo Capital Group",
    url: baseUrl,
    logo: `${baseUrl}/logo.png`,
    description:
      "A real estate investment firm acquiring, building, and redeveloping residential property, holding a growing rental portfolio, and operating in private credit and private equity.",
    foundingDate: "2024",
    telephone: "+1-516-650-6653",
    contactPoint: {
      "@type": "ContactPoint",
      telephone: "+1-516-650-6653",
      contactType: "customer service",
      email: "blbrealtyllc@gmail.com",
      availableLanguage: "English",
    },
    areaServed: [
      { "@type": "City", name: "Houston", containedInPlace: { "@type": "State", name: "Texas" } },
      { "@type": "City", name: "Niagara Falls", containedInPlace: { "@type": "State", name: "New York" } },
    ],
  };

  return (
    <>
      <PageHeader
        tone="dark"
        eyebrow="About the Firm"
        title="A real estate firm built to own."
        intro="Bonomo Capital Group (Bonomo Capital Group) acquires, builds, and redevelops residential property; holds a growing portfolio of rental homes with long-term tenants; and operates in private credit and private equity — all anchored to real assets in markets we know."
        breadcrumbs={[{ label: "Home", href: "/" }, { label: "About" }]}
      />

      {/* Story */}
      <section className="py-20 sm:py-28">
        <Container>
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-20">
            <ScrollReveal>
              <div>
                <p className="eyebrow">Who We Are</p>
                <h2 className="mt-5 font-display text-3xl font-medium leading-tight tracking-tight text-hunter sm:text-4xl">
                  Property, held with patience.
                </h2>
              </div>
            </ScrollReveal>
            <ScrollReveal variant="fade-up" delay={120}>
              <div className="space-y-5 text-[16px] leading-relaxed text-muted">
                <p>
                  Bonomo Capital Group is a privately held real estate investment firm. We
                  acquire residential property, improve it through renovation and
                  redevelopment, and hold it as a long-term, income-producing
                  portfolio across Houston and Niagara Falls.
                </p>
                <p>
                  Some of our homes serve long-term tenants — including
                  participants in the Section 8 program — while others operate as
                  professionally run short-term rentals. Alongside the property we
                  own directly, we deploy private credit and private equity behind
                  the same kind of real assets.
                </p>
                <p>
                  It is a deliberately unhurried way to build: buy well, improve
                  carefully, and hold for the long run.
                </p>
              </div>
            </ScrollReveal>
          </div>
        </Container>
      </section>

      {/* Stats */}
      <section className="border-y border-hunter/10 bg-cream">
        <Container>
          <div className="grid grid-cols-2 divide-x divide-y divide-hunter/10 sm:grid-cols-4 sm:divide-y-0">
            {stats.map((stat) => (
              <div key={stat.label} className="px-4 py-10 text-center">
                <p className="font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                  {stat.value}
                </p>
                <p className="mt-1.5 text-[11px] uppercase tracking-[0.16em] text-muted">
                  {stat.label}
                </p>
              </div>
            ))}
          </div>
        </Container>
      </section>

      {/* Values */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="mx-auto max-w-2xl text-center">
              <p className="eyebrow">How We Operate</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                What guides the firm
              </h2>
            </div>
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={120} stagger={120}>
            <div className="mt-14 grid gap-10 sm:grid-cols-3 sm:gap-8">
              {values.map((v, i) => (
                <div key={v.title}>
                  <div className="font-display text-[15px] font-medium text-gold-dark">
                    0{i + 1}
                  </div>
                  <div className="mt-4 rule-gold w-full max-w-[64px]" />
                  <h3 className="mt-6 font-display text-[20px] font-medium text-hunter">
                    {v.title}
                  </h3>
                  <p className="mt-3 text-[15px] leading-relaxed text-muted">{v.body}</p>
                </div>
              ))}
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* Locations */}
      <section className="border-y border-hunter/10 bg-cream py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="mx-auto max-w-2xl text-center">
              <p className="eyebrow">Where We Operate</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Two markets we know well
              </h2>
            </div>
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={120} stagger={120}>
            <div className="mt-12 grid gap-6 sm:grid-cols-2">
              {[
                {
                  href: "/nomo-collection",
                  city: "Houston, TX",
                  body:
                    "East Downtown and the East End — a growing residential base near the Medical Center, downtown, and the city's sports and entertainment district.",
                  cta: "Explore Houston",
                },
                {
                  href: "/nomo-collection",
                  city: "Niagara Falls, NY",
                  body:
                    "Steps from one of the country's most-visited destinations — residential property redeveloped for both long-term tenants and visitors.",
                  cta: "Explore Niagara Falls",
                },
              ].map((loc) => (
                <Link key={loc.href} href={loc.href} className="glass-card group rounded-[4px] p-8">
                  <div className="flex items-center gap-3">
                    <Building2 className="h-5 w-5 text-gold-dark" />
                    <h3 className="font-display text-[20px] font-medium text-hunter">
                      {loc.city}
                    </h3>
                  </div>
                  <p className="mt-4 text-[15px] leading-relaxed text-muted">{loc.body}</p>
                  <span className="mt-5 inline-flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-[0.14em] text-hunter transition-colors group-hover:text-gold-dark">
                    {loc.cta}
                    <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5" />
                  </span>
                </Link>
              ))}
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* CTA */}
      <section className="py-20 sm:py-28">
        <Container>
          <div className="mx-auto max-w-3xl text-center">
            <p className="eyebrow">Work With Us</p>
            <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
              Explore the firm
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-[16px] leading-relaxed text-muted">
              See what we own, learn how we deploy private capital, or book a stay
              in one of our homes.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Button href="/portfolio">View the Portfolio</Button>
              <Button href="/invest" variant="outline">Invest With Us</Button>
              <Button href="/nomo-collection" variant="ghost">Book a Stay</Button>
            </div>
          </div>
        </Container>
      </section>

      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
    </>
  );
}
