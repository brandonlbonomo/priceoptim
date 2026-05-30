import type { Metadata } from "next";
import Link from "next/link";
import { Trophy, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Vacation Rentals Near Toyota Center — Rockets Season 2026",
  description:
    "Book a vacation rental near Toyota Center for the 2026 Houston Rockets season. Walk to games, concerts, and events from our EaDo properties. Free parking, full kitchen, WiFi. No Airbnb fees.",
  alternates: {
    canonical: "/properties/houston/rockets-season",
  },
};

export default function RocketsSeasonPage() {
  const properties = getPropertiesByCity("Houston");
  const allReviews = getAllReviews();
  const houstonReviews = allReviews.filter((r) =>
    properties.some((p) => p.id === r.propertyId)
  );
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";

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
    name: "Experiences by BLB — Rockets Season Rentals",
    description:
      "Vacation rentals within walking distance of Toyota Center in Houston's EaDo neighborhood. Perfect for Rockets games, concerts, UFC events, and more.",
    url: `${baseUrl}/properties/houston/rockets-season`,
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
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Properties", href: "/properties" },
            { label: "Houston, TX", href: "/properties/houston" },
            { label: "Rockets Season" },
          ]}
        />

        <div className="text-center">
          <div className="mx-auto inline-flex items-center gap-1.5 rounded-full bg-accent/10 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent-dark">
            <Trophy className="h-3 w-3" />
            2025–26 NBA Season: Oct – Jun
          </div>
          <h1 className="mt-5 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Vacation Rentals Near Toyota Center
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Stay in Houston&apos;s East Downtown (EaDo) for the 2025–26 Rockets season and
            beyond. Our vacation rentals are within walking distance of Toyota Center — skip
            the $40 event parking, walk to the arena, and enjoy EaDo&apos;s restaurants and
            breweries before and after the game. Toyota Center also hosts world-class concerts,
            UFC fights, and touring shows year-round. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Walk to Toyota Center",
              "Free Parking",
              "Full Kitchen",
              "No Airbnb Fees",
              "Self Check-in",
            ].map((perk) => (
              <span
                key={perk}
                className="rounded-full border border-black/[0.06] px-3 py-1 text-[12px] text-muted"
              >
                {perk}
              </span>
            ))}
          </div>
        </div>

        <div className="mt-12">
          <PropertyGrid properties={properties} />
        </div>

        <div className="mt-12 text-center">
          <p className="text-[14px] text-muted">
            Planning around a Toyota Center event?
          </p>
          <Link
            href="/blog/toyota-center-events-guide-houston"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-accent-dark transition-colors hover:text-accent"
          >
            Read our Toyota Center events guide
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </Container>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
