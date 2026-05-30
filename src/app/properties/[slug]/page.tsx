import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { BedDouble, Bath, Users, Clock, ClipboardList, MapPin, Star, Quote, ExternalLink } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PhotoGallery } from "@/components/properties/PhotoGallery";
import { AmenityList } from "@/components/properties/AmenityList";
import { HospitableWidget } from "@/components/properties/HospitableWidget";
import { EmailForm } from "@/components/ui/EmailForm";
import { StarRating } from "@/components/ui/StarRating";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { FAQSection } from "@/components/properties/FAQSection";
import { getPropertyBySlug, getActiveProperties, getPropertiesByCity } from "@/data/properties";
import { PropertyCard } from "@/components/properties/PropertyCard";
import { getReviewsByProperty, getAverageRating } from "@/data/reviews";
import { generatePropertyFAQs } from "@/lib/faq";

interface PropertyPageProps {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return getActiveProperties().map((property) => ({
    slug: property.slug,
  }));
}

export async function generateMetadata({ params }: PropertyPageProps): Promise<Metadata> {
  const { slug } = await params;
  const property = getPropertyBySlug(slug);

  if (!property) {
    return { title: "Property Not Found" };
  }

  return {
    title: property.name,
    description: property.tagline + ". " + property.description.slice(0, 120) + "...",
    alternates: {
      canonical: `/properties/${property.slug}`,
    },
    openGraph: {
      title: property.name,
      description: property.tagline,
      images: property.images[0] ? [property.images[0]] : [],
    },
  };
}

export default async function PropertyPage({ params }: PropertyPageProps) {
  const { slug } = await params;
  const property = getPropertyBySlug(slug);

  if (!property) {
    notFound();
  }

  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
  const propertyReviews = getReviewsByProperty(property.id);
  const avgRating = getAverageRating(property.id);
  const reviewCount = propertyReviews.length;
  const faqs = generatePropertyFAQs(property);

  // VacationRental JSON-LD with AggregateRating + Reviews
  const vacationRentalJsonLd: Record<string, unknown> = {
    "@context": "https://schema.org",
    "@type": "VacationRental",
    name: property.name,
    description: property.description,
    url: `${baseUrl}/properties/${property.slug}`,
    image: property.images.slice(0, 5).map((img) =>
      img.startsWith("http") ? img : `${baseUrl}${img}`
    ),
    address: {
      "@type": "PostalAddress",
      addressLocality: property.location.city,
      addressRegion: property.location.state,
      addressCountry: "US",
    },
    numberOfBedrooms: property.details.bedrooms,
    numberOfBathroomsTotal: property.details.bathrooms,
    occupancy: {
      "@type": "QuantitativeValue",
      maxValue: property.details.maxGuests,
    },
    checkinTime: property.checkIn,
    checkoutTime: property.checkOut,
    amenityFeature: property.amenities.map((a) => ({
      "@type": "LocationFeatureSpecification",
      name: a.name,
      value: true,
    })),
  };

  if (reviewCount > 0) {
    vacationRentalJsonLd.aggregateRating = {
      "@type": "AggregateRating",
      ratingValue: avgRating,
      reviewCount: reviewCount,
      bestRating: 5,
      worstRating: 1,
    };
    vacationRentalJsonLd.review = propertyReviews.map((review) => ({
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
    }));
  }

  // FAQPage JSON-LD
  const faqJsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: faqs.map((faq) => ({
      "@type": "Question",
      name: faq.question,
      acceptedAnswer: {
        "@type": "Answer",
        text: faq.answer,
      },
    })),
  };

  // Event JSON-LD — nearby events relevant to the property
  const eventJsonLd = property.location.city === "Houston"
    ? [
        {
          "@context": "https://schema.org",
          "@type": "Event",
          name: "Houston Astros Baseball Season",
          description: "Catch the Houston Astros at Minute Maid Park, walking distance from our EaDo vacation rentals.",
          location: {
            "@type": "Place",
            name: "Minute Maid Park",
            address: { "@type": "PostalAddress", addressLocality: "Houston", addressRegion: "TX", addressCountry: "US" },
          },
          startDate: "2026-03-27",
          endDate: "2026-09-28",
          eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
          organizer: { "@type": "Organization", name: "Houston Astros" },
        },
        {
          "@context": "https://schema.org",
          "@type": "Event",
          name: "RodeoHouston 2027",
          description: "The world's largest livestock show and rodeo at NRG Stadium, accessible via METRORail from EaDo.",
          location: {
            "@type": "Place",
            name: "NRG Stadium",
            address: { "@type": "PostalAddress", addressLocality: "Houston", addressRegion: "TX", addressCountry: "US" },
          },
          startDate: "2027-02-25",
          endDate: "2027-03-16",
          eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
          organizer: { "@type": "Organization", name: "Houston Livestock Show and Rodeo" },
        },
      ]
    : property.location.city === "Niagara Falls"
    ? [
        {
          "@context": "https://schema.org",
          "@type": "Event",
          name: "Winter Festival of Lights — Niagara Falls",
          description: "Millions of LED lights illuminate Niagara Parks from November through February.",
          location: {
            "@type": "Place",
            name: "Niagara Parks",
            address: { "@type": "PostalAddress", addressLocality: "Niagara Falls", addressRegion: "ON", addressCountry: "CA" },
          },
          startDate: "2026-11-14",
          endDate: "2027-02-28",
          eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
          organizer: { "@type": "Organization", name: "Niagara Parks Commission" },
        },
      ]
    : [];

  return (
    <article className="py-8 sm:py-12">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Properties", href: "/properties" },
            { label: property.name },
          ]}
        />

        {/* Photo Gallery */}
        <PhotoGallery images={property.images} alt={`${property.name} — vacation rental in ${property.location.city}, ${property.location.state}`} />

        <div className="mt-10 grid gap-10 lg:grid-cols-3">
          {/* Main content */}
          <div className="lg:col-span-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-muted">
              <MapPin className="h-3 w-3" />
              {property.location.area} &middot; {property.location.city !== "TBD" ? `${property.location.city}, ${property.location.state}` : "Location details coming soon"}
            </div>
            <h1 className="mt-3 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl sm:leading-tight">
              {property.name}
            </h1>
            <p className="mt-2 text-[15px] text-muted">{property.tagline}</p>
            {reviewCount > 0 && (
              <div className="mt-3">
                <StarRating rating={avgRating} reviewCount={reviewCount} size="md" />
              </div>
            )}

            {/* Quick stats */}
            <div className="mt-8 flex flex-wrap gap-3">
              <span className="glass-surface flex items-center gap-2.5 rounded-full px-5 py-3 text-[13px] font-medium text-foreground">
                <BedDouble className="h-4 w-4 text-muted" />
                {property.details.bedrooms} {property.details.bedrooms === 1 ? "Bedroom" : "Bedrooms"}
              </span>
              <span className="glass-surface flex items-center gap-2.5 rounded-full px-5 py-3 text-[13px] font-medium text-foreground">
                <Bath className="h-4 w-4 text-muted" />
                {property.details.bathrooms} {property.details.bathrooms === 1 ? "Bathroom" : "Bathrooms"}
              </span>
              <span className="glass-surface flex items-center gap-2.5 rounded-full px-5 py-3 text-[13px] font-medium text-foreground">
                <Users className="h-4 w-4 text-muted" />
                Up to {property.details.maxGuests} Guests
              </span>
            </div>

            {/* Description */}
            <div className="mt-10">
              <h2 className="text-[19px] font-semibold text-foreground">About This Property</h2>
              <p className="mt-4 text-[15px] leading-[1.8] text-muted">{property.description}</p>
            </div>

            {/* Amenities */}
            <div className="mt-12">
              <h2 className="mb-6 text-[19px] font-semibold text-foreground">Amenities</h2>
              <AmenityList amenities={property.amenities} />
            </div>

            {/* Check-in / Check-out */}
            <div className="mt-12">
              <h2 className="mb-5 text-[19px] font-semibold text-foreground">Check-in &amp; Check-out</h2>
              <div className="flex flex-wrap gap-3">
                <div className="glass-surface flex items-center gap-2.5 rounded-full px-5 py-3 text-[13px]">
                  <Clock className="h-4 w-4 text-muted" />
                  <span className="font-medium text-foreground">Check-in</span>
                  <span className="text-muted">{property.checkIn}</span>
                </div>
                <div className="glass-surface flex items-center gap-2.5 rounded-full px-5 py-3 text-[13px]">
                  <Clock className="h-4 w-4 text-muted" />
                  <span className="font-medium text-foreground">Check-out</span>
                  <span className="text-muted">{property.checkOut}</span>
                </div>
              </div>
            </div>

            {/* Guest Reviews */}
            {reviewCount > 0 && (
              <div className="mt-12">
                <h2 className="mb-6 text-[19px] font-semibold text-foreground">
                  Guest Reviews
                </h2>
                <div className="space-y-4">
                  {propertyReviews.map((review) => (
                    <div key={review.id} className="glass-card rounded-[18px] p-6">
                      <div className="flex items-center justify-between">
                        <p className="text-[14px] font-semibold text-foreground">
                          {review.guestName}
                        </p>
                        <div className="flex items-center gap-0.5">
                          {Array.from({ length: review.rating }).map((_, i) => (
                            <Star key={i} className="h-3 w-3 fill-accent text-accent" />
                          ))}
                        </div>
                      </div>
                      <p className="mt-3 text-[14px] leading-relaxed text-primary-light">
                        <Quote className="mr-1 inline h-3.5 w-3.5 text-accent/30" />
                        {review.text}
                      </p>
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
                <div className="mt-5">
                  <a
                    href="https://g.page/r/CUN6GXD8vohcEBM/review"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-[13px] font-medium text-accent-dark transition-colors duration-200 hover:text-accent"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    Stayed here? Leave a Google Review
                  </a>
                </div>
              </div>
            )}

            {/* House Rules */}
            <div className="mt-12">
              <h2 className="mb-5 flex items-center gap-2 text-[19px] font-semibold text-foreground">
                <ClipboardList className="h-5 w-5 text-muted" />
                House Rules
              </h2>
              <ul className="space-y-2 pl-1 text-[15px] text-muted">
                {property.houseRules.map((rule) => (
                  <li key={rule} className="flex items-center gap-3">
                    <span className="h-1 w-1 rounded-full bg-accent" />
                    {rule}
                  </li>
                ))}
              </ul>
            </div>

            {/* FAQ Section */}
            <div className="mt-12">
              <h2 className="mb-6 text-[19px] font-semibold text-foreground">
                Frequently Asked Questions
              </h2>
              <FAQSection faqs={faqs} />
            </div>

            {/* Related Properties */}
            {(() => {
              const related = getPropertiesByCity(property.location.city).filter(
                (p) => p.id !== property.id
              );
              if (related.length === 0) return null;
              return (
                <div className="mt-16">
                  <h2 className="mb-6 text-[19px] font-semibold text-foreground">
                    More Rentals in {property.location.city}, {property.location.state}
                  </h2>
                  <div className="grid gap-5 sm:grid-cols-2">
                    {related.slice(0, 4).map((p) => (
                      <PropertyCard key={p.id} property={p} />
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>

          {/* Sidebar: Booking widget + pricing */}
          <div className="lg:col-span-1">
            <div className="sticky top-20 space-y-5">
              {/* Hospitable widget */}
              <HospitableWidget
                widgetId={property.hospitable.widgetId}
                propertyId={property.hospitable.propertyId}
              />

              {/* Email CTA */}
              <div className="glass-card rounded-[20px] p-7">
                <h3 className="text-[15px] font-semibold text-foreground">Get Deal Alerts</h3>
                <p className="mt-2 mb-5 text-[13px] text-muted">
                  Be the first to know about special rates for this property.
                </p>
                <EmailForm source={`property-${property.slug}`} />
              </div>
            </div>
          </div>
        </div>
      </Container>

      {/* JSON-LD: VacationRental with AggregateRating + Reviews */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(vacationRentalJsonLd) }}
      />

      {/* JSON-LD: FAQPage */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }}
      />

      {/* JSON-LD: Events */}
      {eventJsonLd.map((event, i) => (
        <script
          key={i}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(event) }}
        />
      ))}
    </article>
  );
}
