import type { Metadata } from "next";
import Link from "next/link";
import { Phone, Mail, Clock, Building2 } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";

export const metadata: Metadata = {
  title: "Contact Us",
  description:
    "Get in touch with Experiences by BLB. Questions about our vacation rentals in Houston EaDo or Niagara Falls? We're here to help.",
  alternates: {
    canonical: "/contact",
  },
};

export default function ContactPage() {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "LocalBusiness",
    name: "Experiences by BLB",
    legalName: "BLB REALTY LLC",
    url: baseUrl,
    logo: `${baseUrl}/logo.png`,
    image: `${baseUrl}/logo.png`,
    telephone: "+1-516-650-6653",
    email: "blbrealtyllc@gmail.com",
    geo: {
      "@type": "GeoCoordinates",
      latitude: 29.7544,
      longitude: -95.3401,
    },
    openingHoursSpecification: {
      "@type": "OpeningHoursSpecification",
      dayOfWeek: [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
      ],
      opens: "00:00",
      closes: "23:59",
    },
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Contact" },
          ]}
        />

        {/* Header */}
        <div className="text-center">
          <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
            Contact Us
          </p>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Get in Touch
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Have a question about our vacation rentals or need help with a
            booking? We&apos;re here to help and typically respond within a few
            hours.
          </p>
        </div>

        {/* Contact method cards */}
        <div className="mt-14 grid gap-6 sm:grid-cols-2 max-w-2xl mx-auto">
          {/* Phone */}
          <div className="glass-card rounded-[28px] p-8 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full glass-surface">
              <Phone className="h-5 w-5 text-accent-dark" />
            </div>
            <h2 className="mt-5 text-[15px] font-semibold text-foreground">
              Phone
            </h2>
            <p className="mt-2 text-[13px] text-muted">
              Call or text us anytime
            </p>
            <a
              href="tel:+15166506653"
              className="mt-3 inline-block text-[15px] font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
            >
              (516) 650-6653
            </a>
          </div>

          {/* Email */}
          <div className="glass-card rounded-[28px] p-8 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full glass-surface">
              <Mail className="h-5 w-5 text-accent-dark" />
            </div>
            <h2 className="mt-5 text-[15px] font-semibold text-foreground">
              Email
            </h2>
            <p className="mt-2 text-[13px] text-muted">
              We reply within a few hours
            </p>
            <a
              href="mailto:blbrealtyllc@gmail.com"
              className="mt-3 inline-block text-[15px] font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
            >
              blbrealtyllc@gmail.com
            </a>
          </div>

        </div>

        {/* Business hours */}
        <div className="mx-auto mt-10 flex max-w-sm items-center justify-center gap-3 glass-surface rounded-full px-6 py-3">
          <Clock className="h-4 w-4 text-accent-dark" />
          <span className="text-[13px] font-medium text-foreground">
            Open 24 hours
          </span>
          <span className="text-[13px] text-muted">/ 7 days a week</span>
        </div>

        {/* Our Locations */}
        <div className="mt-20">
          <div className="text-center">
            <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
              Our Locations
            </p>
            <h2 className="mt-4 text-[22px] font-semibold tracking-tight text-foreground sm:text-[28px]">
              Where We Operate
            </h2>
            <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
              We offer premium vacation rentals in two incredible destinations
            </p>
          </div>

          <div className="mt-10 grid gap-6 sm:grid-cols-2">
            <Link
              href="/properties/houston"
              className="glass-card rounded-[28px] p-8 transition-all duration-300 hover:scale-[1.01]"
            >
              <div className="flex items-center gap-3">
                <Building2 className="h-5 w-5 text-accent-dark" />
                <h3 className="text-[17px] font-semibold text-foreground">
                  Houston, TX
                </h3>
              </div>
              <p className="mt-3 text-[14px] leading-relaxed text-muted">
                East Downtown (EaDo) rentals near Minute Maid Park, Toyota
                Center, and 713 Music Hall. Free parking, full kitchens, and
                keyless check-in.
              </p>
              <p className="mt-4 text-[13px] font-medium text-accent-dark">
                View Houston properties &rarr;
              </p>
            </Link>

            <Link
              href="/properties/niagara-falls"
              className="glass-card rounded-[28px] p-8 transition-all duration-300 hover:scale-[1.01]"
            >
              <div className="flex items-center gap-3">
                <Building2 className="h-5 w-5 text-accent-dark" />
                <h3 className="text-[17px] font-semibold text-foreground">
                  Niagara Falls, NY
                </h3>
              </div>
              <p className="mt-3 text-[14px] leading-relaxed text-muted">
                Cozy homes near Niagara Falls State Park, Maid of the Mist, and
                Seneca Niagara Casino. Pet-friendly with free parking.
              </p>
              <p className="mt-4 text-[13px] font-medium text-accent-dark">
                View Niagara Falls properties &rarr;
              </p>
            </Link>
          </div>
        </div>

        {/* CTA */}
        <div className="mt-20 glass-card rounded-[32px] p-10 text-center sm:p-14">
          <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
            Ready to Book?
          </p>
          <h2 className="mt-4 text-[22px] font-semibold tracking-tight text-foreground sm:text-[28px]">
            Browse our properties
          </h2>
          <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
            Skip the platform fees and book directly with us for the best rates
            on every stay.
          </p>
          <div className="mt-8">
            <Button href="/properties" size="lg" variant="secondary">
              Browse Properties
            </Button>
          </div>
        </div>
      </Container>

      {/* JSON-LD: LocalBusiness */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
