import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { PropertyCard } from "@/components/properties/PropertyCard";
import { Button } from "@/components/ui/Button";
import { getFeaturedProperties } from "@/data/properties";

export function FeaturedProperties() {
  const featured = getFeaturedProperties();

  return (
    <section className="py-20 sm:py-28">
      <Container>
        <SectionHeading
          title="Featured Properties"
          subtitle="Handpicked vacation rentals for your next getaway"
        />

        <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {featured.map((property) => (
            <PropertyCard key={property.id} property={property} />
          ))}
        </div>

        <div className="mt-14 text-center">
          <Button href="/properties" variant="outline">
            View All Properties
          </Button>
        </div>
      </Container>
    </section>
  );
}
