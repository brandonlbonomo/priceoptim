import type { Metadata } from "next";
import Link from "next/link";
import { MapPin, Snowflake, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Winter Vacation Rentals Near Niagara Falls, NY",
  description:
    "Book a cozy vacation rental near Niagara Falls for winter. Walk to the Winter Festival of Lights, frozen Falls views, and indoor attractions. Pet-friendly, free parking, full kitchen.",
  alternates: {
    canonical: "/properties/niagara-falls/winter",
  },
};

export default function NiagaraWinterPage() {
  const properties = getPropertiesByCity("Niagara Falls");
  const allReviews = getAllReviews();
  const nfReviews = allReviews.filter((r) =>
    properties.some((p) => p.id === r.propertyId)
  );
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";

  const avgRating =
    nfReviews.length > 0
      ? Math.round(
          (nfReviews.reduce((sum, r) => sum + r.rating, 0) /
            nfReviews.length) *
            100
        ) / 100
      : 0;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "LodgingBusiness",
    name: "BLB Realty — Niagara Falls Winter Rentals",
    description:
      "Cozy vacation rentals near Niagara Falls, NY for winter getaways. Enjoy the Winter Festival of Lights, frozen Falls, and indoor attractions.",
    url: `${baseUrl}/properties/niagara-falls/winter`,
    address: {
      "@type": "PostalAddress",
      addressLocality: "Niagara Falls",
      addressRegion: "NY",
      addressCountry: "US",
    },
    ...(nfReviews.length > 0 && {
      aggregateRating: {
        "@type": "AggregateRating",
        ratingValue: avgRating,
        reviewCount: nfReviews.length,
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
            { label: "Winter" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Snowflake className="h-3 w-3" />
            Winter Season: Nov – Feb
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Winter Vacation Rentals Near Niagara Falls
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Experience the magic of Niagara Falls in winter. The frozen mist, illuminated
            falls, and Winter Festival of Lights create a breathtaking backdrop for your
            getaway. Our cozy vacation rentals offer heated comfort just minutes from the
            Falls — with full kitchens, pet-friendly policies, and free parking. Book direct
            and save.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Festival of Lights",
              "Heated & Cozy",
              "Pet-Friendly",
              "Free Parking",
              "Full Kitchen",
              "No Platform Fees",
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
            Planning your winter trip?
          </p>
          <Link
            href="/blog/niagara-falls-winter-guide-ice-festivals"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Read our Niagara Falls winter guide
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
