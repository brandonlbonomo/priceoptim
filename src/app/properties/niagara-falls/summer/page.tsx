import type { Metadata } from "next";
import Link from "next/link";
import { Sun, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Summer Vacation Rentals Near Niagara Falls, NY",
  description:
    "Book a summer vacation rental near Niagara Falls, NY. Walk to Maid of the Mist, Cave of the Winds, and Niagara Falls State Park. Pet-friendly homes with full kitchens and free parking.",
  alternates: {
    canonical: "/properties/niagara-falls/summer",
  },
};

export default function SummerPage() {
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
    name: "BLB Realty — Summer Niagara Falls Rentals",
    description:
      "Summer vacation rentals near Niagara Falls State Park. Maid of the Mist, Cave of the Winds, gorge trails, and outdoor activities all within minutes. Pet-friendly homes with full kitchens.",
    url: `${baseUrl}/properties/niagara-falls/summer`,
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
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Properties", href: "/properties" },
            { label: "Niagara Falls, NY", href: "/properties/niagara-falls" },
            { label: "Summer" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Sun className="h-3 w-3" />
            Peak Season: May – October
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Summer Vacation Rentals Near Niagara Falls
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Summer is peak season at Niagara Falls — and for good reason. Maid of the Mist
            cruises into the thundering basin of Horseshoe Falls. Cave of the Winds puts you
            feet from Bridal Veil Falls on the Hurricane Deck. The gorge trails are lush and
            green, and the nightly illumination of the Falls lights up warm summer evenings.
            Our vacation rentals are minutes from Niagara Falls State Park with full kitchens
            for picnic prep, free parking, and the space families need after a long day of
            exploring. Book direct and save versus hotels.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Near Niagara Falls State Park",
              "Maid of the Mist Season",
              "Pet-Friendly",
              "Free Parking",
              "Full Kitchen",
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
            Choosing between the top attractions?
          </p>
          <Link
            href="/blog/maid-of-the-mist-vs-cave-of-the-winds"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Maid of the Mist vs Cave of the Winds — our honest comparison
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
