import type { Metadata } from "next";
import Link from "next/link";
import { MapPin } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { getLocationBySlug } from "@/data/locations";

const location = getLocationBySlug("niagara-falls")!;

const niagaraLandings = [
  { href: "/properties/niagara-falls/summer", label: "Summer at the Falls" },
  { href: "/properties/niagara-falls/winter", label: "Winter getaways" },
  { href: "/properties/niagara-falls/family", label: "Family stays" },
];

export const metadata: Metadata = {
  title: location.title,
  description: location.metaDescription,
  alternates: { canonical: "/properties/niagara-falls" },
  openGraph: {
    title: `${location.title} | Bonomo Capital Group`,
    description: location.metaDescription,
  },
};

export default function NiagaraFallsPropertiesPage() {
  const properties = getPropertiesByCity("Niagara Falls");
  const allReviews = getAllReviews();
  const niagaraReviews = allReviews.filter((r) =>
    properties.some((p) => p.id === r.propertyId)
  );
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";

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
    name: "Bonomo Capital Group — Niagara Falls, NY",
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

        {/* Seasonal stays — internal links to Niagara Falls landing pages */}
        <div className="mt-16">
          <h2 className="text-center font-display text-xl font-medium tracking-tight text-hunter">
            Find a Niagara Falls stay for your trip
          </h2>
          <div className="mx-auto mt-6 flex max-w-3xl flex-wrap items-center justify-center gap-2.5">
            {niagaraLandings.map((l) => (
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
