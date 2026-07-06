import type { Metadata } from "next";
import Link from "next/link";
import { Users, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Family-Friendly Vacation Rentals Near Niagara Falls, NY",
  description:
    "Book a family-friendly vacation rental near Niagara Falls, NY. Multiple bedrooms, full kitchens, and space for kids. Minutes from Cave of the Winds, Maid of the Mist, and the Aquarium.",
  alternates: {
    canonical: "/properties/niagara-falls/family",
  },
  openGraph: {
    title: "Family-Friendly Vacation Rentals Near Niagara Falls, NY",
    description:
      "Full-home vacation rentals near Niagara Falls for families — separate bedrooms, a kitchen, laundry, and room for kids to spread out. Minutes from the Falls. Book direct, no Airbnb fees.",
    url: "/properties/niagara-falls/family",
    type: "website",
  },
};

const familyFaqs = [
  {
    question: "Are your rentals a good fit for kids?",
    answer:
      "Yes — these are full homes, not hotel rooms, so kids get separate bedrooms, a living room to play in, and room to spread out and wind down after a day at the Falls. It's a much calmer setup than a cramped hotel room shared by the whole family.",
  },
  {
    question: "What family attractions are nearby?",
    answer:
      "You're minutes from Niagara Falls State Park, the Maid of the Mist boat ride, the Aquarium of Niagara, and the Niagara Gorge Discovery Center — a full slate of kid-friendly things to do within a short drive of the house.",
  },
  {
    question: "Is there a kitchen and laundry for families?",
    answer:
      "Every home has a full kitchen for family meals, easy breakfasts, and picky-eater dinners, plus a washer and dryer for the inevitable soaked clothes after a day near the Falls. It saves money on eating out and keeps everyone in clean, dry gear.",
  },
  {
    question: "How close are the homes to the Falls?",
    answer:
      "Our homes sit in quiet residential neighborhoods just minutes from Niagara Falls State Park, so you can head to the Falls in the morning and come back to the house for naps or lunch without a long drive.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with BLB Realty is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout — which adds up quickly on a family-length stay.",
  },
];

export default function FamilyPage() {
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
    name: "BLB Realty — Family Niagara Falls Rentals",
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
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Users className="h-3 w-3" />
            Family-Friendly Stays
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
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
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Read our family vacation guide to Niagara Falls
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </Container>

      {/* Unique local content — family base near the Falls */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              A family base near Niagara Falls
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                A trip to Niagara Falls with kids goes better when everyone has
                room to breathe. Our homes give you separate bedrooms so parents
                and kids aren&apos;t sharing one tight hotel room, a living room
                where kids can spread out, and a kitchen for family breakfasts
                and picky-eater dinners instead of a restaurant every night. A
                washer and dryer handles the soaked clothes that come with Cave
                of the Winds and the Maid of the Mist, and quiet residential
                streets give everyone a calm place to wind down after a big day.
              </p>
              <p>
                From the house you&apos;re only minutes from Niagara Falls State
                Park, the Aquarium of Niagara, and the Niagara Gorge Discovery
                Center, so it&apos;s easy to head out in the morning and circle
                back for naps or lunch without a long drive. Self check-in means
                you arrive on your own schedule, even with tired kids in the car,
                and booking direct with us is always the lowest price for the
                same home — no Airbnb service fees added at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={familyFaqs} heading="Family stays near Niagara Falls — FAQ" />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
