import type { Metadata } from "next";
import Link from "next/link";
import { Music, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Vacation Rentals Near 713 Music Hall — Houston Concerts",
  description:
    "Book a vacation rental near 713 Music Hall in Houston's POST Houston. Walk to concerts from our EaDo properties. Free parking, full kitchen, WiFi. No Airbnb fees — book direct.",
  alternates: {
    canonical: "/properties/houston/concerts",
  },
};

export default function ConcertsPage() {
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
    name: "Experiences by BLB — Concert Night Rentals",
    description:
      "Vacation rentals within walking distance of 713 Music Hall and Toyota Center in Houston's EaDo neighborhood. Perfect for concerts and live music events.",
    url: `${baseUrl}/properties/houston/concerts`,
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
            { label: "Concerts" },
          ]}
        />

        <div className="text-center">
          <div className="mx-auto inline-flex items-center gap-1.5 rounded-full bg-accent/10 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent-dark">
            <Music className="h-3 w-3" />
            713 Music Hall &bull; Toyota Center
          </div>
          <h1 className="mt-5 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            Vacation Rentals Near 713 Music Hall
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Houston&apos;s EaDo neighborhood is the live music capital of Texas. 713 Music Hall
            at POST Houston — a 5,000-capacity venue with outstanding acoustics — hosts
            top-tier touring acts year-round. Toyota Center books major arena concerts, UFC
            events, and spectacles just blocks away. Our vacation rentals put you within
            walking distance of both venues, so you can skip the parking fees, enjoy dinner
            and drinks in the neighborhood before the show, and stroll back to your rental
            after the encore. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Walk to 713 Music Hall",
              "Near Toyota Center",
              "Free Parking",
              "Full Kitchen",
              "No Airbnb Fees",
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
            Exploring the neighborhood before the show?
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
