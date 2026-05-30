import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { PropertyCard } from "@/components/properties/PropertyCard";
import { Button } from "@/components/ui/Button";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { getFeaturedProperties } from "@/data/properties";

export function FeaturedProperties() {
  const featured = getFeaturedProperties();

  return (
    <section className="py-16 sm:py-20">
      <Container>
        <ScrollReveal>
          <SectionHeading
            title="Featured Properties"
            subtitle="Handpicked vacation rentals for your next getaway"
          />
        </ScrollReveal>

        <ScrollReveal variant="fade-up" delay={100} stagger={120}>
          <div className="mt-10 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {featured.map((property) => (
              <PropertyCard key={property.id} property={property} />
            ))}
          </div>
        </ScrollReveal>

        <ScrollReveal delay={400}>
          <div className="mt-10 text-center">
            <Button href="/properties" variant="outline">
              View All Properties
            </Button>
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
