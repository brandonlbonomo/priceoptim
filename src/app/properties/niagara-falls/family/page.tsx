import type { Metadata } from "next";
import Link from "next/link";
import { Users, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Family-Friendly Vacation Rentals Near Niagara Falls, NY",
  description:
    "Book a family-friendly vacation rental near Niagara Falls, NY. Multiple bedrooms, full kitchens, and space for kids. Minutes from Cave of the Winds, Maid of the Mist, and the Aquarium.",
  alternates: {
    canonical: "/properties/niagara-falls/family",
  },
};

export default function FamilyPage() {
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
    name: "Experiences by BLB — Family Niagara Falls Rentals",
    description:
      "Family-friendly vacation rentals near Niagara Falls State Park. Multiple bedrooms, full kitchens, washer/dryer, and space for the whole family. Minutes from kid-friendly attractions.",
    url: `${baseUrl}/properties/niagara-falls/family`,
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
            { label: "Family" },
          ]}
        />

        <div className="text-center">
          <div className="mx-auto inline-flex items-center gap-1.5 rounded-full bg-accent/10 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent-dark">
            <Users className="h-3 w-3" />
            Family-Friendly Stays
          </div>
          <h1 className="mt-5 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            Family-Friendly Vacation Rentals Near Niagara Falls
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Niagara Falls is one of the best family destinations in the Northeast — and a
            vacation rental is the best way to experience it with kids. Our properties offer
            multiple bedrooms so everyone has space, full kitchens for packing picnic lunches
            and preparing breakfast, washer and dryer for managing the inevitable wardrobe
            changes (Cave of the Winds will soak everyone), and quiet residential neighborhoods
            where kids can wind down at the end of the day. All just minutes from Niagara Falls
            State Park, the Aquarium of Niagara, and the Gorge Discovery Center.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Multiple Bedrooms",
              "Full Kitchen",
              "Washer & Dryer",
              "Near Kid-Friendly Attractions",
              "Free Parking",
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
            Planning your family trip?
          </p>
          <Link
            href="/blog/family-vacation-guide-niagara-falls-ny-with-kids"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-accent-dark transition-colors hover:text-accent"
          >
            Read our family vacation guide to Niagara Falls
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
