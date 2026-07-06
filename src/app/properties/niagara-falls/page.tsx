import type { Metadata } from "next";
import { MapPin } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { getLocationBySlug } from "@/data/locations";

const location = getLocationBySlug("niagara-falls")!;

export const metadata: Metadata = {
  title: location.title,
  description: location.metaDescription,
  openGraph: {
    title: `${location.title} | BLB Realty`,
    description: location.metaDescription,
  },
};

export default function NiagaraFallsPropertiesPage() {
  const properties = getPropertiesByCity("Niagara Falls");
  const allReviews = getAllReviews();
  const niagaraReviews = allReviews.filter((r) =>
    properties.some((p) => p.id === r.propertyId)
  );
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";

  const avgRating =
    niagaraReviews.length > 0
      ? Math.round(
          (niagaraReviews.reduce((sum, r) => sum + r.rating, 0) /
            niagaraReviews.length) *
            100
        ) / 100
      : 0;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "LodgingBusiness",
    name: "BLB Realty — Niagara Falls, NY",
    description: location.description,
    url: `${baseUrl}/properties/niagara-falls`,
    address: {
      "@type": "PostalAddress",
      addressLocality: "Niagara Falls",
      addressRegion: "NY",
      addressCountry: "US",
    },
    ...(niagaraReviews.length > 0 && {
      aggregateRating: {
        "@type": "AggregateRating",
        ratingValue: avgRating,
        reviewCount: niagaraReviews.length,
        bestRating: 5,
        worstRating: 1,
      },
    }),
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Properties", href: "/properties" },
            { label: "Niagara Falls, NY" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <MapPin className="h-3 w-3" />
            Niagara Falls, New York
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            {location.title}
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            {location.description}
          </p>

          {/* Attractions */}
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {location.attractions.map((attraction) => (
              <span
                key={attraction}
                className="rounded-full border border-black/[0.06] px-3 py-1 text-[12px] text-muted"
              >
                {attraction}
              </span>
            ))}
          </div>
        </div>

        <div className="mt-12">
          <PropertyGrid properties={properties} />
        </div>
      </Container>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
