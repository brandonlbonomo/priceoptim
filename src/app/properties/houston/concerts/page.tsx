import type { Metadata } from "next";
import Link from "next/link";
import { Music, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PropertyGrid } from "@/components/properties/PropertyGrid";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getPropertiesByCity } from "@/data/properties";
import { getAllReviews } from "@/data/reviews";
import { LandingFAQ } from "@/components/properties/LandingFAQ";

export const metadata: Metadata = {
  title: "Vacation Rentals Near 713 Music Hall — Houston Concerts",
  description:
    "Book a vacation rental near 713 Music Hall in Houston's POST Houston. Walk to concerts from our EaDo properties. Free parking, full kitchen, WiFi. No Airbnb fees — book direct.",
  alternates: {
    canonical: "/properties/houston/concerts",
  },
  openGraph: {
    title: "Vacation Rentals Near Houston Concert Venues — EaDo",
    description:
      "Walk-or-short-rideshare vacation rentals in Houston's EaDo near 713 Music Hall, Toyota Center, and POST Houston. Full homes, self check-in, no Airbnb fees. Book direct.",
    url: "/properties/houston/concerts",
    type: "website",
  },
};

const concertsFaqs = [
  {
    question: "Which concert venues are near your rentals?",
    answer:
      "Our EaDo homes are a short walk or quick rideshare from 713 Music Hall at POST Houston, Toyota Center, and the House of Blues and downtown clubs. Minute Maid Park, just a few blocks away, also hosts big stadium shows.",
  },
  {
    question: "How do we get to and from a show?",
    answer:
      "Most nights you can walk to 713 Music Hall or POST Houston, and Toyota Center is a short rideshare away. Leaving from the house means no downtown parking to find and no waiting in a garage line after the encore — you just stroll or grab a quick ride home.",
  },
  {
    question: "Can we check in late after a night show?",
    answer:
      "Yes. Every home has self check-in, so you can arrive on your own schedule after a late set and let yourself in — no front desk, no waiting around.",
  },
  {
    question: "Can we book a full house for a group?",
    answer:
      "Absolutely. Each rental is a full home with a kitchen, laundry, and room to spread out, which suits groups going to a show together far better than a row of hotel rooms. Come back afterward and keep the night going under one roof.",
  },
  {
    question: "Is it cheaper to book direct than on Airbnb?",
    answer:
      "Booking direct with Bonomo Capital Group is always the lowest price for the same home. You skip the service fees Airbnb, VRBO, and Booking.com add at checkout.",
  },
];

export default function ConcertsPage() {
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
    name: "Bonomo Capital Group — Concert Night Rentals",
    description:
      "Vacation rentals within walking distance of 713 Music Hall and Toyota Center in Houston's EaDo neighborhood. Perfect for concerts and live music events.",
    url: `${baseUrl}/properties/houston/concerts`,
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
            { label: "Concerts" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <Music className="h-3 w-3" />
            713 Music Hall &bull; Toyota Center
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Vacation Rentals Near 713 Music Hall
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Houston&apos;s EaDo neighborhood is the live music capital of Texas. 713 Music Hall
            at POST Houston — a 5,000-capacity venue with outstanding acoustics — hosts
            top-tier touring acts year-round. Toyota Center books major arena concerts, UFC
            events, and spectacles just blocks away. Our vacation rentals put you within
            walking distance of both venues, so you can skip the parking fees, enjoy dinner
            and drinks in the neighborhood before the show, and stroll back to your rental
            after the encore. Book direct for the best rates.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              "Walk to 713 Music Hall",
              "Near Toyota Center",
              "Free Parking",
              "Full Kitchen",
              "No Airbnb Fees",
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
            Exploring the neighborhood before the show?
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

      {/* Unique local content — concert-night guide */}
      <section className="mt-4 border-t border-hunter/10 bg-cream py-16 sm:py-20">
        <Container>
          <div className="mx-auto max-w-3xl">
            <h2 className="font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
              Staying near Houston&apos;s concert venues
            </h2>
            <div className="mt-5 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                East Downtown puts you in the middle of Houston&apos;s live music
                scene. 713 Music Hall at POST Houston is a walkable or short
                rideshare away, Toyota Center sits just blocks off for the big
                arena tours, and the House of Blues and downtown clubs round out
                the night. Staying here means you skip the hunt for downtown
                parking, grab dinner and a drink at a neighborhood brewery before
                the doors open, and walk or catch a quick ride back once the
                encore ends instead of crawling out of a garage.
              </p>
              <p>
                Each home is a full residence — kitchen, laundry, real beds, and
                room to spread out — which makes it easy to bring the whole group
                and keep the night going under one roof after the show. Self
                check-in means you can arrive on your own schedule, even after a
                late set, and booking direct with us is always the lowest price
                for the same home, with no platform service fees at checkout.
              </p>
            </div>
          </div>
        </Container>
      </section>

      <LandingFAQ faqs={concertsFaqs} heading="Concert-night stays — FAQ" />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
