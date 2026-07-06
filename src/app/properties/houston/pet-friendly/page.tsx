import type { Metadata } from "next";
import Link from "next/link";
import { Dog, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Pet-Friendly Vacation Rentals in Houston EaDo",
  description:
    "Find pet-friendly vacation rentals in Houston's EaDo neighborhood. Dog parks, pet-friendly patios, and spacious rentals that welcome your furry family members. $75/night pet fee — book direct.",
  alternates: {
    canonical: "/properties/houston/pet-friendly",
  },
  openGraph: {
    title: "Pet-Friendly Vacation Rentals in Houston EaDo",
    description:
      "Bring the dog along. Full-home vacation rentals in Houston's EaDo with room to spread out, green space nearby, and self check-in. Book direct for the lowest price.",
    url: "/properties/houston/pet-friendly",
    type: "website",
  },
};

const petFriendlyFaqs = [
  {
    question: "Are pets really allowed in your rentals?",
    answer:
      "Yes — we keep pet-friendly homes available in EaDo so you can bring your dog along instead of leaving them behind. When you book, just let us know you're traveling with a pet so we can confirm the details for your stay.",
  },
  {
    question: "Is there a pet fee?",
    answer:
      "Any pet fee, along with details like size or number of pets, is confirmed at the time of booking. Mention your dog when you reserve and we'll walk you through what applies to the home you choose.",
  },
  {
    question: "Is there space and outdoor area for a dog?",
    answer:
      "Our homes are full residences, not cramped hotel rooms, so your dog has room to spread out. EaDo's walkable streets and nearby green space make for easy morning and evening walks right from the front door.",
  },
  {
    question: "What should I bring for my dog?",
    answer:
      "Pack the essentials — food and bowls, a leash, waste bags, a bed or crate, and any medications. Bringing your own supplies keeps your dog comfortable and makes settling into a new place much easier.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with BLB Realty is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout.",
  },
];

export default function PetFriendlyPage() {
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
    name: "BLB Realty — Pet-Friendly Houston Rentals",
    description:
      "Pet-friendly vacation rentals in Houston's EaDo neighborhood. Dog-friendly breweries, parks, and patios within walking distance. $75/night pet fee.",
    url: `${baseUrl}/properties/houston/pet-friendly`,
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
            { label: "Pet-Friendly" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Dog className="h-3 w-3" />
            Pet-Friendly Properties
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Pet-Friendly Vacation Rentals in Houston EaDo
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Traveling with your dog? Houston&apos;s EaDo neighborhood is one of the most
            pet-friendly areas in the city. Our vacation rentals welcome pets for a $75/night
            pet fee. The neighborhood&apos;s breweries — including 8th Wonder and True Anomaly —
            have dog-friendly patios. Discovery Green park is a short walk away for morning
            walks and off-leash areas. Pet-friendly restaurant patios line Polk Street and
            Navigation Boulevard. Your dog will love EaDo as much as you do.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "$75/Night Pet Fee",
              "Dog-Friendly Breweries",
              "Near Discovery Green",
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
            Exploring Houston with your pet?
          </p>
          <Link
            href="/blog/eado-neighborhood-guide-houston"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Read our EaDo neighborhood guide
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </Container>

      {/* Unique local content — traveling with your dog */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              Traveling to Houston with your dog
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Leaving your dog behind — or paying to board them — takes the
                fun out of a trip. We keep pet-friendly homes available in East
                Downtown so your dog can come along. Each one is a full
                residence, not a cramped hotel room, which means real beds, a
                kitchen, and room for everyone to spread out. EaDo is one of
                Houston&apos;s most walkable neighborhoods, with nearby green
                space and easy streets for morning and evening walks right from
                the front door.
              </p>
              <p>
                Pet-friendly homes are available, and we keep the details simple:
                just let us know you&apos;re bringing a dog when you book, and
                we&apos;ll confirm anything specific — like a pet fee or size
                guidance — for the home you choose. Self check-in means you
                arrive on your own schedule, and booking direct with us is always
                the lowest price for the same home, with no platform service fees
                at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={petFriendlyFaqs} heading="Pet-friendly stays — FAQ" />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
