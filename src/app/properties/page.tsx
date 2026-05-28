import type { Metadata } from "next";
import { Suspense } from "react";
import { Container } from "@/components/ui/Container";
import { PropertyFilters } from "@/components/properties/PropertyFilters";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { getActiveProperties } from "@/data/properties";

export const metadata: Metadata = {
  title: "All Properties",
  description:
    "Browse all Experiences by BLB vacation rentals. Find your perfect getaway and book directly for the best rates.",
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
    <section className="py-14 sm:py-20">
      <Container>
        <div className="text-center">
          <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
            Our Collection
          </p>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            All Properties
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Find your perfect vacation rental and book directly for the best rate
          </p>
        </div>

        <div className="mt-10 flex justify-center">
          <Suspense>
            <PropertyFilters />
          </Suspense>
        </div>

        <div className="mt-10">
          <PropertyGrid properties={properties} />
        </div>
      </Container>
    </section>
  );
}
