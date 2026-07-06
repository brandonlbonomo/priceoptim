import type { Metadata } from "next";
import Link from "next/link";
import { Calendar, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Where to Stay for RodeoHouston 2027 — EaDo Vacation Rentals",
  description:
    "Book a vacation rental in Houston's EaDo for RodeoHouston 2027. Take METRORail direct to NRG Stadium. Free parking, full kitchen, WiFi. Skip the hotel price surge — book direct.",
  alternates: {
    canonical: "/properties/houston/rodeo",
  },
};

export default function RodeoPage() {
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
    name: "BLB Realty — RodeoHouston Rentals",
    description:
      "Vacation rentals in Houston's EaDo neighborhood with METRORail access to NRG Stadium for RodeoHouston. Full kitchens, free parking, and no platform fees.",
    url: `${baseUrl}/properties/houston/rodeo`,
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
            { label: "RodeoHouston" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Calendar className="h-3 w-3" />
            RodeoHouston 2027: Feb – Mar
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Where to Stay for RodeoHouston 2027
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Stay in Houston&apos;s East Downtown (EaDo) for RodeoHouston and take the METRORail
            Red Line straight to NRG Stadium — just $1.25 each way and no parking hassle.
            Our vacation rentals put you on the rail line with direct service to the Rodeo,
            surrounded by the best restaurants and breweries in the city. Hotels near NRG double
            their prices during Rodeo season. Our EaDo rentals give you more space, a full
            kitchen, and free parking at a fraction of the cost. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "METRORail to NRG Stadium",
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
            First time at RodeoHouston?
          </p>
          <Link
            href="/blog/houston-rodeo-where-to-stay-vacation-rentals"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Read our complete RodeoHouston guide
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
