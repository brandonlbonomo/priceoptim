import type { Metadata } from "next";
import Link from "next/link";
import { MapPin, Snowflake, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Winter Vacation Rentals Near Niagara Falls, NY",
  description:
    "Book a cozy vacation rental near Niagara Falls for winter. Walk to the Winter Festival of Lights, frozen Falls views, and indoor attractions. Pet-friendly, free parking, full kitchen.",
  alternates: {
    canonical: "/properties/niagara-falls/winter",
  },
  openGraph: {
    title: "Winter Vacation Rentals Near Niagara Falls, NY",
    description:
      "Cozy full homes near Niagara Falls for a winter getaway — Festival of Lights, frozen Falls, fewer crowds, lower rates. Heated, pet-friendly, no platform fees. Book direct.",
    url: "/properties/niagara-falls/winter",
    type: "website",
  },
};

const winterFaqs = [
  {
    question: "Can you visit Niagara Falls in the winter?",
    answer:
      "Yes — the Falls run all year and never fully stop. Winter is one of the most dramatic times to see them, with ice formations along the edges, frozen mist on the railings, and far fewer crowds than the summer season. Niagara Falls State Park stays open, so you can walk right up to the overlooks.",
  },
  {
    question: "What is the Winter Festival of Lights?",
    answer:
      "The Winter Festival of Lights fills the Niagara area with millions of lights and illuminated displays through the colder months. It pairs beautifully with the nightly light show on the Falls themselves — an easy, magical evening out that's just minutes from our homes.",
  },
  {
    question: "Are the homes warm and heated?",
    answer:
      "Every home is a full residence with central heat, a real kitchen, and room to spread out — so you can spend the day out in the cold at the Falls and come back to a warm, cozy place to thaw out and cook dinner.",
  },
  {
    question: "Are there fewer crowds in winter?",
    answer:
      "Far fewer. Winter is the quiet off-season, which means shorter lines at the overlooks, easier parking, and a calmer, more magical visit — plus lower rates than you'll find in the busy summer months.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with Bonomo Capital Group is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout — which matters even more when off-season rates are already lower.",
  },
];

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
    name: "Bonomo Capital Group — Niagara Falls Winter Rentals",
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

      {/* Unique local content — winter getaway guide */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              A winter escape near Niagara Falls
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Winter turns Niagara Falls into something you can&apos;t see
                the rest of the year — ice building up along the banks, mist
                freezing on the railings, and the falls still thundering
                through it all. Niagara Falls State Park stays open through the
                cold months, and in the evening the Winter Festival of Lights
                and the nightly show on the water light up the whole gorge.
                With the summer crowds gone, you get the overlooks nearly to
                yourself, easy parking, and lower rates than the busy season —
                all just minutes from our homes.
              </p>
              <p>
                Each home is a full residence — central heat, a real kitchen,
                laundry, and room to spread out — so you can spend the day out
                in the cold and come back somewhere warm to thaw out and cook
                dinner. Self check-in means you arrive on your own schedule
                even on a snowy night, and booking direct with us is always
                the lowest price for the same home, with no platform service
                fees at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={winterFaqs} heading="Winter stays near Niagara Falls — FAQ" />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
