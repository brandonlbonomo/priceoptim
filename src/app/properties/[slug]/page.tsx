import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { BedDouble, Bath, Users, Clock, ClipboardList, MapPin, Star, Quote } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PhotoGallery } from "@/components/properties/PhotoGallery";
import { AmenityList } from "@/components/properties/AmenityList";
import { HospitableWidget } from "@/components/properties/HospitableWidget";
import { EmailForm } from "@/components/ui/EmailForm";
import { getPropertyBySlug, getActiveProperties } from "@/data/properties";
import { getReviewsByProperty } from "@/data/reviews";

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

  return (
    <article className="py-8 sm:py-12">
      <Container>
        {/* Photo Gallery */}
        <PhotoGallery images={property.images} alt={property.name} />

        <div className="mt-10 grid gap-10 lg:grid-cols-3">
          {/* Main content */}
          <div className="lg:col-span-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-muted">
              <MapPin className="h-3 w-3" />
              {property.location.area} &middot; {property.location.city !== "TBD" ? `${property.location.city}, ${property.location.state}` : "Location details coming soon"}
            </div>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-[40px] sm:leading-tight">
              {property.name}
            </h1>
            <p className="mt-3 text-[17px] text-muted">{property.tagline}</p>

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
            {(() => {
              const propertyReviews = getReviewsByProperty(property.id);
              if (propertyReviews.length === 0) return null;
              return (
                <div className="mt-12">
                  <h2 className="mb-6 text-[19px] font-semibold text-foreground">
                    Guest Reviews
                  </h2>
                  <div className="space-y-4">
                    {propertyReviews.map((review) => (
                      <div key={review.id} className="glass-card rounded-[24px] p-6">
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
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}

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
              <div className="glass-card rounded-[28px] p-7">
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

      {/* JSON-LD structured data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "VacationRental",
            name: property.name,
            description: property.description,
            url: `${process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000"}/properties/${property.slug}`,
            numberOfBedrooms: property.details.bedrooms,
            numberOfBathroomsTotal: property.details.bathrooms,
            occupancy: {
              "@type": "QuantitativeValue",
              maxValue: property.details.maxGuests,
            },
            checkinTime: property.checkIn,
            checkoutTime: property.checkOut,
          }),
        }}
      />
    </article>
  );
}
