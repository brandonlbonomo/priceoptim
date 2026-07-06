import type { Metadata } from "next";
import { Suspense } from "react";
import Link from "next/link";
import { MapPin } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyFilters } from "@/components/properties/PropertyFilters";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { getActiveProperties } from "@/data/properties";

export const metadata: Metadata = {
  title: "All Properties",
  description:
    "Browse all BLB Realty vacation rentals. Find your perfect getaway and book directly for the best rates.",
};

interface PropertiesPageProps {
  searchParams: Promise<{ q?: string; guests?: string; bedrooms?: string }>;
}

export default async function PropertiesPage({ searchParams }: PropertiesPageProps) {
  const { q, guests, bedrooms } = await searchParams;
  let properties = getActiveProperties();

  if (q) {
    const query = q.toLowerCase();
    properties = properties.filter(
      (p) =>
        p.name.toLowerCase().includes(query) ||
        p.tagline.toLowerCase().includes(query) ||
        p.description.toLowerCase().includes(query) ||
        p.location.city.toLowerCase().includes(query) ||
        p.location.state.toLowerCase().includes(query) ||
        p.location.area.toLowerCase().includes(query)
    );
  }

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
          <p className="eyebrow">
            Our Collection
          </p>
          <h1 className="mt-4 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            All Properties
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Find your perfect vacation rental and book directly for the best rate
          </p>

          {/* Location quick-links */}
          <div className="mt-6 flex items-center justify-center gap-3">
            <Link
              href="/properties/houston"
              className="inline-flex items-center gap-1.5 rounded-full border border-black/[0.08] bg-white px-4 py-2 text-[13px] font-medium text-foreground transition-colors duration-200 hover:border-accent hover:text-accent-dark"
            >
              <MapPin className="h-3.5 w-3.5" />
              Houston, TX
            </Link>
            <Link
              href="/properties/niagara-falls"
              className="inline-flex items-center gap-1.5 rounded-full border border-black/[0.08] bg-white px-4 py-2 text-[13px] font-medium text-foreground transition-colors duration-200 hover:border-accent hover:text-accent-dark"
            >
              <MapPin className="h-3.5 w-3.5" />
              Niagara Falls, NY
            </Link>
          </div>
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
