import type { Metadata } from "next";
import Link from "next/link";
import { MapPin, DollarSign, MessageCircle, CalendarCheck, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { PropertyCard } from "@/components/properties/PropertyCard";
import { getFeaturedProperties, getActiveProperties } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Book a Stay",
  description:
    "Book a short-term stay in a BLB Realty home — direct in Houston, TX and Niagara Falls, NY. No platform fees, professionally operated, the best rate every time.",
  alternates: { canonical: "/book" },
};

const cities = [
  {
    href: "/properties/houston",
    name: "Houston, TX",
    body:
      "East Downtown homes near Minute Maid Park, Toyota Center, and the Medical Center — furnished for business and leisure alike.",
  },
  {
    href: "/properties/niagara-falls",
    name: "Niagara Falls, NY",
    body:
      "Comfortable, pet-friendly homes minutes from Niagara Falls State Park, the Maid of the Mist, and Seneca Niagara Casino.",
  },
];

const reasons = [
  {
    icon: DollarSign,
    title: "Best rate, direct",
    body: "No third-party platform fees. Booking with us is always the best price for the same home.",
  },
  {
    icon: MessageCircle,
    title: "Owner-operated",
    body: "You deal directly with the firm that owns and maintains the property — not a middleman.",
  },
  {
    icon: CalendarCheck,
    title: "Professionally run",
    body: "Every stay is held to the same standard we bring to the assets in our portfolio.",
  },
];

export default function BookPage() {
  const featured = getFeaturedProperties();
  const total = getActiveProperties().length;
  const reviews = getAllReviews();
  const avgRating =
    Math.round((reviews.reduce((s, r) => s + r.rating, 0) / reviews.length) * 100) / 100;

  return (
    <>
      <PageHeader
        tone="dark"
        eyebrow="Book a Stay · Direct"
        title="Stay in a home from our portfolio."
        intro={`A number of the properties BLB Realty owns operate as short-term rentals in Houston and Niagara Falls. Book with us directly — ${avgRating}★ across ${reviews.length}+ guest reviews, no platform fees.`}
        breadcrumbs={[{ label: "Home", href: "/" }, { label: "Book a Stay" }]}
      />

      {/* Cities */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="max-w-2xl">
              <p className="eyebrow">Where We Host</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Two destinations
              </h2>
            </div>
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={120} stagger={120}>
            <div className="mt-12 grid gap-6 sm:grid-cols-2">
              {cities.map((c) => (
                <Link key={c.href} href={c.href} className="glass-card group rounded-[4px] p-8">
                  <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.16em] text-gold-dark">
                    <MapPin className="h-3.5 w-3.5" />
                    {c.name}
                  </div>
                  <h3 className="mt-4 font-display text-[24px] font-medium text-hunter">
                    {c.name}
                  </h3>
                  <p className="mt-3 text-[15px] leading-relaxed text-muted">{c.body}</p>
                  <span className="mt-5 inline-flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-[0.14em] text-hunter transition-colors group-hover:text-gold-dark">
                    View homes
                    <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5" />
                  </span>
                </Link>
              ))}
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* Featured stays */}
      <section className="border-y border-hunter/10 bg-cream py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end">
              <div className="max-w-xl">
                <p className="eyebrow">The Homes</p>
                <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                  Featured stays
                </h2>
              </div>
              <Button href="/properties" variant="outline">
                All {total} Homes
              </Button>
            </div>
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={120} stagger={100}>
            <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
              {featured.map((property) => (
                <PropertyCard key={property.id} property={property} />
              ))}
            </div>
          </ScrollReveal>
        </Container>
      </section>

      {/* Why direct */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <div className="mx-auto max-w-2xl text-center">
              <p className="eyebrow">Book Direct</p>
              <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
                Why book with us
              </h2>
            </div>
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={120} stagger={120}>
            <div className="mt-14 grid gap-6 sm:grid-cols-3">
              {reasons.map((r) => (
                <div key={r.title} className="glass-card rounded-[3px] p-8 text-center">
                  <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full bg-hunter/[0.05]">
                    <r.icon className="h-5 w-5 text-gold-dark" />
                  </div>
                  <h3 className="mt-5 font-display text-[18px] font-medium text-hunter">
                    {r.title}
                  </h3>
                  <p className="mt-2 text-[14px] leading-relaxed text-muted">{r.body}</p>
                </div>
              ))}
            </div>
          </ScrollReveal>
          <ScrollReveal delay={200}>
            <div className="mt-12 text-center">
              <Link
                href="/book-direct"
                className="inline-flex items-center gap-1.5 text-[13px] font-semibold uppercase tracking-[0.14em] text-gold-dark transition-colors hover:text-hunter"
              >
                See the full comparison vs. Airbnb
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </ScrollReveal>
        </Container>
      </section>
    </>
  );
}
