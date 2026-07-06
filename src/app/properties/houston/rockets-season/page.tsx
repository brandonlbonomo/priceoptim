import type { Metadata } from "next";
import Link from "next/link";
import { Trophy, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Vacation Rentals Near Toyota Center — Rockets Season 2026",
  description:
    "Book a vacation rental near Toyota Center for the 2026 Houston Rockets season. Walk to games, concerts, and events from our EaDo properties. Free parking, full kitchen, WiFi. No Airbnb fees.",
  alternates: {
    canonical: "/properties/houston/rockets-season",
  },
  openGraph: {
    title: "Vacation Rentals Near Toyota Center — Rockets Season",
    description:
      "Walk-to-the-arena vacation rentals in Houston's EaDo for the Rockets season. Free parking, full kitchen, no Airbnb fees. Book direct.",
    url: "/properties/houston/rockets-season",
    type: "website",
  },
};

const rocketsFaqs = [
  {
    question: "How close are your rentals to Toyota Center?",
    answer:
      "Our homes are in East Downtown (EaDo), a short walk or quick rideshare from Toyota Center — close enough to walk back after the game, skip arena parking, and beat the post-game traffic.",
  },
  {
    question: "Is parking included on game nights?",
    answer:
      "Yes. Every home has its own parking, so you can leave the car at the house and walk to the arena instead of paying for an event lot.",
  },
  {
    question: "Can we book for a multi-game homestand or road trip?",
    answer:
      "Absolutely — many guests stay several nights to catch a few Rockets games in one trip. Booking direct for multiple nights is the best value, with no third-party platform fees.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with BLB Realty is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout.",
  },
  {
    question: "What's the EaDo neighborhood like?",
    answer:
      "EaDo is Houston's most walkable sports-and-nightlife district — breweries, restaurants, and street murals, with both Toyota Center and Minute Maid Park within a few blocks.",
  },
];

export default function RocketsSeasonPage() {
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
    name: "BLB Realty — Rockets Season Rentals",
    description:
      "Vacation rentals within walking distance of Toyota Center in Houston's EaDo neighborhood. Perfect for Rockets games, concerts, UFC events, and more.",
    url: `${baseUrl}/properties/houston/rockets-season`,
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

  // Event JSON-LD — the season this page is about (mirrors property pages)
  const eventJsonLd = {
    "@context": "https://schema.org",
    "@type": "Event",
    name: "Houston Rockets Basketball Season 2026–27",
    description:
      "Houston Rockets home games at Toyota Center in downtown Houston. BLB Realty offers walk-to-the-arena vacation rentals nearby in EaDo.",
    location: {
      "@type": "Place",
      name: "Toyota Center",
      address: {
        "@type": "PostalAddress",
        addressLocality: "Houston",
        addressRegion: "TX",
        addressCountry: "US",
      },
    },
    startDate: "2026-10-21",
    endDate: "2027-04-12",
    eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
    eventStatus: "https://schema.org/EventScheduled",
    organizer: { "@type": "Organization", name: "Houston Rockets" },
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Properties", href: "/properties" },
            { label: "Houston, TX", href: "/properties/houston" },
            { label: "Rockets Season" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Trophy className="h-3 w-3" />
            2026–27 NBA Season: Oct – Apr
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Vacation Rentals Near Toyota Center
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Stay in Houston&apos;s East Downtown (EaDo) for the 2025–26 Rockets season and
            beyond. Our vacation rentals are within walking distance of Toyota Center — skip
            the $40 event parking, walk to the arena, and enjoy EaDo&apos;s restaurants and
            breweries before and after the game. Toyota Center also hosts world-class concerts,
            UFC fights, and touring shows year-round. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Walk to Toyota Center",
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
            Planning around a Toyota Center event?
          </p>
          <Link
            href="/blog/toyota-center-events-guide-houston"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Read our Toyota Center events guide
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </Container>

      {/* Unique local content — game-night guide */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              Staying near Toyota Center for a Rockets game
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Toyota Center sits on the edge of East Downtown, and our homes
                are a short walk or quick rideshare from the arena — the same
                easy hop as Minute Maid Park a few blocks over. On game nights
                that means no arena parking fees and no post-game traffic crawl:
                you can walk back to the house, or let the garage empty out over
                a drink at a neighborhood brewery first. With the NBA regular
                season running from October into April, staying in EaDo turns a
                couple of Rockets games into a real Houston trip instead of a
                hotel-and-highway shuffle.
              </p>
              <p>
                Each home is a full residence — kitchen, laundry, real beds, and
                room to spread out — which suits families, groups splitting a
                multi-game trip, and anyone in town to watch their team on the
                road. Self check-in means you arrive on your own schedule after a
                late tip-off or a Toyota Center concert, and booking direct with
                us is always the lowest price for the same home, with no platform
                service fees at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={rocketsFaqs} heading="Rockets-season stays — FAQ" />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(eventJsonLd) }}
      />
    </section>
  );
}
