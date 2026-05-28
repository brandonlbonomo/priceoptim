import type { Metadata } from "next";
import { Suspense } from "react";
import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { PropertyFilters } from "@/components/properties/PropertyFilters";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { getActiveProperties } from "@/data/properties";

export const metadata: Metadata = {
  title: "All Properties",
  description:
    "Browse all Properties By BLB vacation rentals. Find your perfect getaway and book directly for the best rates.",
};

interface PropertiesPageProps {
  searchParams: Promise<{ guests?: string; bedrooms?: string }>;
}

export default async function PropertiesPage({ searchParams }: PropertiesPageProps) {
  const { guests, bedrooms } = await searchParams;
  let properties = getActiveProperties();

  if (guests) {
    const minGuests = parseInt(guests, 10);
    properties = properties.filter((p) => p.details.maxGuests >= minGuests);
  }

  if (bedrooms) {
    const minBedrooms = parseInt(bedrooms, 10);
    properties = properties.filter((p) => p.details.bedrooms >= minBedrooms);
  }

  return (
    <section className="py-12 sm:py-16">
      <Container>
        <SectionHeading
          title="Our Properties"
          subtitle="Find your perfect vacation rental and book directly for the best rate"
        />

        <div className="mt-8">
          <Suspense>
            <PropertyFilters />
          </Suspense>
        </div>

        <div className="mt-8">
          <PropertyGrid properties={properties} />
        </div>
      </Container>
    </section>
  );
}
