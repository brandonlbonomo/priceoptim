import type { Metadata } from "next";
import Link from "next/link";
import { MapPin } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { getLocationBySlug } from "@/data/locations";

const location = getLocationBySlug("houston")!;

const houstonLandings = [
  { href: "/properties/houston/astros-season", label: "Astros season" },
  { href: "/properties/houston/rockets-season", label: "Rockets season" },
  { href: "/properties/houston/rodeo", label: "Houston Rodeo" },
  { href: "/properties/houston/concerts", label: "Concerts & events" },
  { href: "/properties/houston/pet-friendly", label: "Pet-friendly stays" },
];

export const metadata: Metadata = {
  title: location.title,
  description: location.metaDescription,
  alternates: { canonical: "/properties/houston" },
  openGraph: {
    title: `${location.title} | BLB Realty`,
    description: location.metaDescription,
  },
};

export default function HoustonPropertiesPage() {
  const properties = getPropertiesByCity("Houston");
  const allReviews = getAllReviews();
  const houstonReviews = allReviews.filter((r) =>
    properties.some((p) => p.id === r.propertyId)
  );
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";

  const avgRating =
    houstonReviews.length > 0
      ? Math.round(
          (houstonReviews.reduce((sum, r) => sum + r.rating, 0) /
            houstonReviews.length) *
            100
        ) / 100
      : 0;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "LodgingBusiness",
    name: "BLB Realty — Houston, TX",
    description: location.description,
    url: `${baseUrl}/properties/houston`,
    address: {
      "@type": "PostalAddress",
      addressLocality: "Houston",
      addressRegion: "TX",
      addressCountry: "US",
    },
    ...(houstonReviews.length > 0 && {
      aggregateRating: {
        "@type": "AggregateRating",
        ratingValue: avgRating,
        reviewCount: houstonReviews.length,
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
            { label: "Houston, TX" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <MapPin className="h-3 w-3" />
            Houston, Texas
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

        {/* Seasonal & event stays — internal links to Houston landing pages */}
        <div className="mt-16">
          <h2 className="text-center font-display text-xl font-medium tracking-tight text-hunter">
            Find a Houston stay for your trip
          </h2>
          <div className="mx-auto mt-6 flex max-w-3xl flex-wrap items-center justify-center gap-2.5">
            {houstonLandings.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                className="rounded-full border border-black/[0.08] px-4 py-2 text-[13px] text-hunter transition-colors duration-200 hover:border-hunter/40 hover:bg-hunter/[0.03]"
              >
                {l.label}
              </Link>
            ))}
          </div>
        </div>
      </Container>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
