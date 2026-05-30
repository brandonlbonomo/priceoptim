import { Hero } from "@/components/home/Hero";
import { FeaturedProperties } from "@/components/home/FeaturedProperties";
import { WhyBookDirect } from "@/components/home/WhyBookDirect";
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

  // Pick the best testimonials — longer, 5-star reviews from different properties
  const testimonials = reviews
    .filter((r) => r.rating === 5 && r.text.length > 100)
    .slice(0, 6)
    .map((r) => {
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
      <FeaturedProperties />
      <WhyBookDirect />

      {/* Testimonials */}
      <section className="py-16 sm:py-20">
        <Container>
          <ScrollReveal>
            <SectionHeading
              title="What Our Guests Say"
              subtitle="Real reviews from real stays across Houston and Niagara Falls"
            />
          </ScrollReveal>
          <ScrollReveal variant="fade-up" delay={100}>
            <div className="mt-10">
              <Testimonials testimonials={testimonials} />
            </div>
          </ScrollReveal>
        </Container>
      </section>

      <EmailSignupCTA />

      {/* JSON-LD structured data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "LodgingBusiness",
            name: "Experiences by BLB",
            description:
              "Premium vacation rentals in Houston, TX and Niagara Falls, NY. Book direct for the best rates — no Airbnb or Vrbo fees. Properties near Minute Maid Park, Toyota Center, Niagara Falls State Park, and more.",
            url: process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000",
            numberOfRooms: 8,
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
