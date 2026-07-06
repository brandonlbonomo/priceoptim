import type { Metadata } from "next";
import Link from "next/link";
import { MapPin, Calendar, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Vacation Rentals Near Minute Maid Park — Astros Season 2026",
  description:
    "Book a vacation rental near Minute Maid Park for the 2026 Houston Astros season. Walk to the ballpark from our EaDo properties. Free parking, full kitchen, WiFi. No Airbnb fees.",
  alternates: {
    canonical: "/properties/houston/astros-season",
  },
  openGraph: {
    title: "Vacation Rentals Near Minute Maid Park — Astros Season",
    description:
      "Walk-to-the-ballpark vacation rentals in Houston's EaDo for the Astros season. Free parking, full kitchen, no Airbnb fees. Book direct.",
    url: "/properties/houston/astros-season",
    type: "website",
  },
};

const astrosFaqs = [
  {
    question: "How close are your rentals to Minute Maid Park?",
    answer:
      "Our homes are in East Downtown (EaDo), a short walk or quick rideshare from Minute Maid Park — close enough to walk back after the game, skip stadium parking, and beat the post-game traffic.",
  },
  {
    question: "Is parking included on game days?",
    answer:
      "Yes. Every home has its own parking, so you can leave the car at the house and walk to the ballpark instead of paying for a stadium lot.",
  },
  {
    question: "Can we book for a full homestand or weekend series?",
    answer:
      "Absolutely — many guests book several nights around a series. Booking direct for multiple nights is the best value, with no third-party platform fees.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with BLB Realty is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout.",
  },
  {
    question: "What's the EaDo neighborhood like?",
    answer:
      "EaDo is Houston's most walkable sports-and-nightlife district — breweries, restaurants, and street murals, with both Minute Maid Park and Toyota Center within a few blocks.",
  },
];

export default function AstrosSeasonPage() {
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
    name: "BLB Realty — Astros Season Rentals",
    description:
      "Vacation rentals within walking distance of Minute Maid Park in Houston's EaDo neighborhood. Perfect for Astros games, concerts, and events.",
    url: `${baseUrl}/properties/houston/astros-season`,
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
    name: "Houston Astros Baseball Season 2026",
    description:
      "Houston Astros home games at Minute Maid Park in East Downtown. BLB Realty offers walk-to-the-ballpark vacation rentals nearby.",
    location: {
      "@type": "Place",
      name: "Minute Maid Park",
      address: {
        "@type": "PostalAddress",
        addressLocality: "Houston",
        addressRegion: "TX",
        addressCountry: "US",
      },
    },
    startDate: "2026-03-27",
    endDate: "2026-09-28",
    eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
    eventStatus: "https://schema.org/EventScheduled",
    organizer: { "@type": "Organization", name: "Houston Astros" },
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Properties", href: "/properties" },
            { label: "Houston, TX", href: "/properties/houston" },
            { label: "Astros Season" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Calendar className="h-3 w-3" />
            2026 Season: Mar 27 – Sep 28
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Vacation Rentals Near Minute Maid Park
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Stay in Houston&apos;s East Downtown (EaDo) for the 2026 Astros season. Our vacation
            rentals are within walking distance of Minute Maid Park — skip the parking hassle,
            walk to the game, and enjoy the neighborhood&apos;s restaurants and breweries before
            and after the first pitch. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Walk to Minute Maid Park",
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
            Planning a trip beyond game day?
          </p>
          <Link
            href="/blog/top-10-things-to-do-in-houston-eado"
            className="mt-2 inline-flex items-center gap-1.5 text-[14px] font-medium text-gold-dark transition-colors hover:text-hunter"
          >
            Read our EaDo neighborhood guide
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </Container>

      {/* Unique local content — game-day guide */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              Staying near Minute Maid Park for an Astros game
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Minute Maid Park sits on the western edge of East Downtown, and
                our homes are a short walk or quick rideshare from the ballpark.
                On game days that means no stadium parking fees and no post-game
                traffic crawl — you can walk back to the house, or let the lot
                empty out over a drink at a neighborhood brewery first. For a
                weekend series, staying in EaDo turns three games into a real
                Houston trip instead of a hotel-and-highway shuffle.
              </p>
              <p>
                Each home is a full residence — kitchen, laundry, real beds, and
                room to spread out — which suits families, groups splitting a
                series, and anyone in town to watch their team on the road.
                Self check-in means you arrive on your own schedule after a night
                game, and booking direct with us is always the lowest price for
                the same home, with no platform service fees at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={astrosFaqs} heading="Astros-season stays — FAQ" />

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
