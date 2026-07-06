import { Hero } from "@/components/home/Hero";
import { FirmPillars } from "@/components/home/FirmPillars";
import { PortfolioPreview } from "@/components/home/PortfolioPreview";
import { InvestCTA } from "@/components/home/InvestCTA";
import { BookingSection } from "@/components/home/BookingSection";
import { EmailSignupCTA } from "@/components/home/EmailSignupCTA";
import { Testimonials } from "@/components/home/Testimonials";
import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { ScrollReveal } from "@/components/ui/ScrollReveal";
import { getAllReviews } from "@/data/reviews";
import { properties } from "@/data/properties";

export default function HomePage() {
  const reviews = getAllReviews();
  const totalReviews = reviews.length;
  const avgRating =
    Math.round(
      (reviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews) * 100
    ) / 100;

  // Pick the best testimonials — longer, 5-star reviews from both cities
  const fiveStarLong = reviews.filter((r) => r.rating === 5 && r.text.length > 100);
  const houstonIds = new Set(properties.filter((p) => p.location.city === "Houston").map((p) => p.id));
  const houstonReviews = fiveStarLong.filter((r) => houstonIds.has(r.propertyId));
  const niagaraReviews = fiveStarLong.filter((r) => !houstonIds.has(r.propertyId));
  const picked = [...houstonReviews.slice(0, 3), ...niagaraReviews.slice(0, 3)];
  const testimonials = picked.map((r) => {
      const property = properties.find((p) => p.id === r.propertyId);
      return {
        guestName: r.guestName,
        rating: r.rating,
        text: r.text,
        propertyName: property?.name ?? "",
        location: property
          ? `${property.location.city}, ${property.location.state}`
          : "",
      };
    });

  return (
    <>
      <Hero />
      <FirmPillars />
      <PortfolioPreview />
      <InvestCTA />
      <BookingSection />

      {/* Guest testimonials — social proof for the direct-booking offering */}
      <section className="py-20 sm:py-28">
        <Container>
          <ScrollReveal>
            <SectionHeading
              title="What our guests say"
              subtitle="Reviews from recent stays across Houston and Niagara Falls."
            />
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={100}>
            <div className="mt-12">
              <Testimonials testimonials={testimonials} />
            </div>
          </ScrollReveal>
        </Container>
      </section>

      <EmailSignupCTA />

      {/* JSON-LD structured data — the firm */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "RealEstateAgent",
            name: "BLB Realty",
            legalName: "BLB REALTY LLC",
            description:
              "A real estate investment firm acquiring, building, and redeveloping residential property, holding a growing rental portfolio, and operating in private credit and private equity.",
            url: process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com",
            aggregateRating: {
              "@type": "AggregateRating",
              ratingValue: avgRating,
              reviewCount: totalReviews,
              bestRating: 5,
              worstRating: 1,
            },
            areaServed: [
              {
                "@type": "City",
                name: "Houston",
                containedInPlace: { "@type": "State", name: "Texas" },
              },
              {
                "@type": "City",
                name: "Niagara Falls",
                containedInPlace: { "@type": "State", name: "New York" },
              },
            ],
          }),
        }}
      />
    </>
  );
}
