import type { Metadata } from "next";
import { Star, Quote, ExternalLink } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getAllReviews } from "@/data/reviews";
import { properties } from "@/data/properties";

export const metadata: Metadata = {
  title: "Guest Reviews",
  description:
    "Read what guests say about Experiences by BLB vacation rentals in Houston EaDo and Niagara Falls. Real reviews from real stays.",
};

function formatDate(dateStr: string): string {
  const [year, month] = dateStr.split("-");
  const date = new Date(parseInt(year), parseInt(month) - 1);
  return date.toLocaleDateString("en-US", { month: "long", year: "numeric" });
}

export default function ReviewsPage() {
  const reviews = getAllReviews();
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";

  // Group reviews by property
  const grouped = properties
    .filter((p) => p.active)
    .map((property) => ({
      property,
      reviews: reviews.filter((r) => r.propertyId === property.id),
    }))
    .filter((group) => group.reviews.length > 0);

  const totalReviews = reviews.length;
  const avgRating =
    Math.round(
      (reviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews) * 100
    ) / 100;

  // LodgingBusiness JSON-LD with AggregateRating + Reviews
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "LodgingBusiness",
    name: "Experiences by BLB",
    description:
      "Premium vacation rentals in Houston, TX and Niagara Falls, NY. Book direct for the best rates.",
    url: baseUrl,
    aggregateRating: {
      "@type": "AggregateRating",
      ratingValue: avgRating,
      reviewCount: totalReviews,
      bestRating: 5,
      worstRating: 1,
    },
    review: reviews.map((review) => ({
      "@type": "Review",
      author: { "@type": "Person", name: review.guestName },
      datePublished: `${review.date}-01`,
      reviewBody: review.text,
      reviewRating: {
        "@type": "Rating",
        ratingValue: review.rating,
        bestRating: 5,
        worstRating: 1,
      },
    })),
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Reviews" },
          ]}
        />

        {/* Header */}
        <div className="text-center">
          <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
            Guest Reviews
          </p>
          <h1 className="mt-4 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            What Our Guests Say
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Real reviews from real stays across all our properties
          </p>

          {/* Overall stats */}
          <div className="mx-auto mt-8 inline-flex items-center gap-3 glass-surface rounded-full px-6 py-3">
            <div className="flex items-center gap-1">
              {Array.from({ length: 5 }).map((_, i) => (
                <Star
                  key={i}
                  className="h-4 w-4 fill-accent text-accent"
                />
              ))}
            </div>
            <span className="text-[15px] font-semibold text-foreground">
              {avgRating}
            </span>
            <span className="text-[13px] text-muted">
              from {totalReviews} reviews
            </span>
          </div>

          <div className="mt-5">
            <a
              href="https://g.page/r/CUN6GXD8vohcEBM/review"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-full bg-accent/10 px-5 py-2.5 text-[13px] font-medium text-accent-dark transition-colors duration-200 hover:bg-accent/20"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              Leave a Google Review
            </a>
          </div>
        </div>

        {/* Reviews grouped by property */}
        <div className="mt-16 space-y-16">
          {grouped.map(({ property, reviews: propertyReviews }) => (
            <div key={property.id}>
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-[19px] font-semibold text-foreground">
                    {property.name}
                  </h2>
                  <p className="mt-1 text-[13px] text-muted">
                    {property.location.city}, {property.location.state}
                  </p>
                </div>
                <Button
                  href={`/properties/${property.slug}`}
                  variant="outline"
                  size="sm"
                >
                  View Property
                </Button>
              </div>

              <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {propertyReviews.map((review) => (
                  <div
                    key={review.id}
                    className="glass-card rounded-[18px] p-6"
                  >
                    <Quote className="h-5 w-5 text-accent/40" />
                    <p className="mt-3 text-[14px] leading-relaxed text-primary-light">
                      {review.text}
                    </p>
                    <div className="mt-5 flex items-center justify-between">
                      <div>
                        <p className="text-[13px] font-semibold text-foreground">
                          {review.guestName}
                        </p>
                        <p className="text-[11px] text-muted">
                          {formatDate(review.date)}
                        </p>
                      </div>
                      <div className="flex items-center gap-0.5">
                        {Array.from({ length: review.rating }).map((_, i) => (
                          <Star
                            key={i}
                            className="h-3 w-3 fill-accent text-accent"
                          />
                        ))}
                      </div>
                    </div>
                    {review.hostResponse && (
                      <div className="mt-4 rounded-2xl bg-accent/5 p-4">
                        <p className="text-[12px] font-semibold text-accent-dark">Host Response</p>
                        <p className="mt-1 text-[13px] leading-relaxed text-muted">
                          {review.hostResponse}
                        </p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Google Review CTA */}
        <div className="mt-20 glass-card rounded-[18px] p-8 text-center sm:p-10">
          <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
            Stayed With Us?
          </p>
          <h2 className="mt-4 text-[19px] font-semibold tracking-tight text-foreground sm:text-[22px]">
            Share your experience
          </h2>
          <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
            We&apos;d love to hear about your stay. Leave a review on Google — it
            helps other travelers find us.
          </p>
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <a
              href="https://g.page/r/CUN6GXD8vohcEBM/review"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-full bg-accent px-6 py-3 text-[14px] font-semibold text-white transition-all duration-200 hover:bg-accent-light active:scale-[0.97]"
            >
              <ExternalLink className="h-4 w-4" />
              Leave a Google Review
            </a>
            <Button href="/properties" size="lg" variant="outline">
              Browse Properties
            </Button>
          </div>
        </div>
      </Container>

      {/* JSON-LD: LodgingBusiness with AggregateRating + Reviews */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
