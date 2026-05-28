import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { BedDouble, Bath, Users, Clock, ClipboardList } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { PhotoGallery } from "@/components/properties/PhotoGallery";
import { AmenityList } from "@/components/properties/AmenityList";
import { HospitableWidget } from "@/components/properties/HospitableWidget";
import { EmailForm } from "@/components/ui/EmailForm";
import { getPropertyBySlug, getActiveProperties } from "@/data/properties";
import { formatCurrency } from "@/lib/utils";

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

        <div className="mt-8 grid gap-8 lg:grid-cols-3">
          {/* Main content */}
          <div className="lg:col-span-2">
            <p className="text-sm font-medium uppercase tracking-wider text-muted">
              {property.location.area} &middot; {property.location.city !== "TBD" ? `${property.location.city}, ${property.location.state}` : "Location details coming soon"}
            </p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
              {property.name}
            </h1>
            <p className="mt-2 text-lg text-accent-dark">{property.tagline}</p>

            {/* Quick stats */}
            <div className="mt-6 flex flex-wrap gap-4">
              <span className="flex items-center gap-2 rounded-full bg-muted-light px-4 py-2 text-sm font-medium text-foreground">
                <BedDouble className="h-4 w-4 text-primary" />
                {property.details.bedrooms} {property.details.bedrooms === 1 ? "Bedroom" : "Bedrooms"}
              </span>
              <span className="flex items-center gap-2 rounded-full bg-muted-light px-4 py-2 text-sm font-medium text-foreground">
                <Bath className="h-4 w-4 text-primary" />
                {property.details.bathrooms} {property.details.bathrooms === 1 ? "Bathroom" : "Bathrooms"}
              </span>
              <span className="flex items-center gap-2 rounded-full bg-muted-light px-4 py-2 text-sm font-medium text-foreground">
                <Users className="h-4 w-4 text-primary" />
                Up to {property.details.maxGuests} Guests
              </span>
            </div>

            {/* Description */}
            <div className="mt-8">
              <h2 className="text-xl font-semibold text-foreground">About This Property</h2>
              <p className="mt-3 leading-relaxed text-muted">{property.description}</p>
            </div>

            {/* Amenities */}
            <div className="mt-10">
              <h2 className="mb-6 text-xl font-semibold text-foreground">Amenities</h2>
              <AmenityList amenities={property.amenities} />
            </div>

            {/* Check-in / Check-out */}
            <div className="mt-10">
              <h2 className="mb-4 text-xl font-semibold text-foreground">Check-in &amp; Check-out</h2>
              <div className="flex flex-wrap gap-6">
                <div className="flex items-center gap-2 text-sm text-muted">
                  <Clock className="h-4 w-4 text-primary" />
                  <span>
                    <strong className="text-foreground">Check-in:</strong> {property.checkIn}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-sm text-muted">
                  <Clock className="h-4 w-4 text-primary" />
                  <span>
                    <strong className="text-foreground">Check-out:</strong> {property.checkOut}
                  </span>
                </div>
              </div>
            </div>

            {/* House Rules */}
            <div className="mt-10">
              <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold text-foreground">
                <ClipboardList className="h-5 w-5 text-primary" />
                House Rules
              </h2>
              <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
                {property.houseRules.map((rule) => (
                  <li key={rule}>{rule}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Sidebar: Booking widget + pricing */}
          <div className="lg:col-span-1">
            <div className="sticky top-20 space-y-6">
              {/* Price card */}
              <div className="rounded-xl border border-gray-200 p-5">
                <div className="text-center">
                  <span className="text-3xl font-bold text-primary">
                    {formatCurrency(property.pricing.baseNight)}
                  </span>
                  <span className="text-muted"> / night</span>
                </div>
                <p className="mt-1 text-center text-xs text-muted">
                  + {formatCurrency(property.pricing.cleaningFee)} cleaning fee
                </p>
              </div>

              {/* Hospitable widget */}
              <HospitableWidget
                widgetId={property.hospitable.widgetId}
                propertyId={property.hospitable.propertyId}
              />

              {/* Email CTA */}
              <div className="rounded-xl border border-gray-200 p-5">
                <h3 className="text-sm font-semibold text-foreground">Get Deal Alerts</h3>
                <p className="mt-1 mb-3 text-xs text-muted">
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
