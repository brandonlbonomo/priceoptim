import type { Metadata } from "next";
import Link from "next/link";
import { Sun, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Summer Vacation Rentals Near Niagara Falls, NY",
  description:
    "Book a summer vacation rental near Niagara Falls, NY. Walk to Maid of the Mist, Cave of the Winds, and Niagara Falls State Park. Pet-friendly homes with full kitchens and free parking.",
  alternates: {
    canonical: "/properties/niagara-falls/summer",
  },
  openGraph: {
    title: "Summer Vacation Rentals Near Niagara Falls, NY",
    description:
      "Full homes minutes from Niagara Falls State Park — room for families and groups, full kitchen and laundry, free parking. Book direct for the lowest price, no Airbnb fees.",
    url: "/properties/niagara-falls/summer",
    type: "website",
  },
};

const summerFaqs = [
  {
    question: "How close are your rentals to Niagara Falls State Park?",
    answer:
      "Our homes are just minutes from Niagara Falls State Park on the American side — close enough to walk to the Falls or make a quick drive, so you can head back to a real house to rest between visits instead of paying for hotel parking every day.",
  },
  {
    question: "What are the best things to do near the Falls in summer?",
    answer:
      "Summer is peak season. Take the Maid of the Mist boat tour into the mist of Horseshoe Falls, get up close on the Cave of the Winds Hurricane Deck, cross the Rainbow Bridge, and walk the gorge trails — all within minutes of your rental in Niagara Falls, NY.",
  },
  {
    question: "Do your homes work for families and groups?",
    answer:
      "Yes. Each home is a full residence with real bedrooms, a full kitchen, and laundry, so families and groups have room to spread out and come back from the Falls to a real house instead of cramped hotel rooms.",
  },
  {
    question: "Is parking included?",
    answer:
      "Every home has its own free parking, so you can leave the car at the house and walk or drive the short distance to the Falls rather than hunting for a lot near the park.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with BLB Realty is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout, and self check-in means you arrive on your own schedule.",
  },
];

export default function SummerPage() {
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

      {/* Unique local content — summer base near the Falls */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              A summer base near Niagara Falls
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Summer is when Niagara Falls is at its best, and our homes are
                minutes from Niagara Falls State Park on the American side. You
                can walk or make a short drive to the Falls, then spend the day
                on the Maid of the Mist, out on the Cave of the Winds Hurricane
                Deck, and along the gorge trails before crossing back to a quiet
                street. Staying this close means you skip the crowded hotel
                strip and the daily parking hunt — the Falls are right there when
                you want them, and a real house is waiting when you don&apos;t.
              </p>
              <p>
                Each home is a full residence with a kitchen, laundry, real
                beds, and room to spread out, which suits families and groups
                exploring the American side together. Cook breakfast before an
                early start, do a load of laundry after a misty afternoon, and
                come back from the Falls to space instead of cramped hotel
                rooms. Self check-in means you arrive on your own schedule, and
                booking direct with us is always the lowest price for the same
                home, with no platform service fees at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={summerFaqs} heading="Summer stays near Niagara Falls — FAQ" />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
