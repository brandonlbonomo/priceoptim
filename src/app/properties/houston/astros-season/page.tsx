import type { Metadata } from "next";
import Link from "next/link";
import { MapPin, Calendar, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Vacation Rentals Near Minute Maid Park — Astros Season 2026",
  description:
    "Book a vacation rental near Minute Maid Park for the 2026 Houston Astros season. Walk to the ballpark from our EaDo properties. Free parking, full kitchen, WiFi. No Airbnb fees.",
  alternates: {
    canonical: "/properties/houston/astros-season",
  },
};

export default function AstrosSeasonPage() {
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
    name: "Experiences by BLB — Astros Season Rentals",
    description:
      "Vacation rentals within walking distance of Minute Maid Park in Houston's EaDo neighborhood. Perfect for Astros games, concerts, and events.",
    url: `${baseUrl}/properties/houston/astros-season`,
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
            { label: "Astros Season" },
          ]}
        />

        <div className="text-center">
          <div className="mx-auto inline-flex items-center gap-1.5 rounded-full bg-accent/10 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent-dark">
            <Calendar className="h-3 w-3" />
            2026 Season: Mar 27 – Sep 28
          </div>
          <h1 className="mt-5 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Vacation Rentals Near Minute Maid Park
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Stay in Houston&apos;s East Downtown (EaDo) for the 2026 Astros season. Our vacation
            rentals are within walking distance of Minute Maid Park — skip the parking hassle,
            walk to the game, and enjoy the neighborhood&apos;s restaurants and breweries before
            and after the first pitch. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Walk to Minute Maid Park",
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
            Planning a trip beyond game day?
          </p>
          <Link
            href="/blog/top-10-things-to-do-in-houston-eado"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-accent-dark transition-colors hover:text-accent"
          >
            Read our EaDo neighborhood guide
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
