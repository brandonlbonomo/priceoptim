import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { PropertyCard } from "@/components/properties/PropertyCard";
import { getFeaturedProperties } from "@/data/properties";

export function BookingSection() {
  const featured = getFeaturedProperties();

  return (
    <section className="border-t border-hunter/10 bg-cream py-20 sm:py-28">
      <Container>
        <ScrollReveal>
          <div className="mx-auto max-w-3xl text-center">
            <p className="eyebrow">Book a Stay · Direct</p>
            <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
              Stay in a home from our portfolio.
            </h2>
            <p className="mx-auto mt-5 max-w-2xl text-[16px] leading-relaxed text-muted">
              A number of our properties operate as short-term rentals in Houston
              and Niagara Falls. Book with us directly — no platform fees, the same
              standard of care we bring to every asset we own.
            </p>
          </div>
        </ScrollReveal>

        <ScrollReveal variant="fade-up" delay={120} stagger={100}>
          <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {featured.map((property) => (
              <PropertyCard key={property.id} property={property} />
            ))}
          </div>
        </ScrollReveal>

        <ScrollReveal delay={300}>
          <div className="mt-12 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Button href="/book">Book a Stay</Button>
            <Button href="/properties" variant="outline">
              Browse All Stays
            </Button>
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
