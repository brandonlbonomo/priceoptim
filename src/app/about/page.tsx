import type { Metadata } from "next";
import Link from "next/link";
import { DollarSign, MessageCircle, Shield, Building2 } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getAllReviews } from "@/data/reviews";
import { getActiveProperties } from "@/data/properties";
import { getAllPosts } from "@/data/blog";
import { locations } from "@/data/locations";

export const metadata: Metadata = {
  title: "About Us",
  description:
    "Learn about Experiences by BLB — premium vacation rentals in Houston's EaDo and Niagara Falls, NY. Book direct for the best rates with BLB REALTY LLC.",
  alternates: {
    canonical: "/about",
  },
};

export default function AboutPage() {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";

  const reviews = getAllReviews();
  const properties = getActiveProperties();
  const posts = getAllPosts();
  const cityCount = locations.length;

  const stats = [
    { label: "Properties", value: `${properties.length}` },
    { label: "Reviews", value: `${reviews.length}+` },
    { label: "Cities", value: `${cityCount}` },
    { label: "Blog Guides", value: `${posts.length}+` },
  ];

  const benefits = [
    {
      icon: DollarSign,
      title: "No Service Fees",
      description:
        "Book direct and keep more money in your pocket. No Airbnb or Vrbo service fees — just honest, transparent pricing.",
    },
    {
      icon: MessageCircle,
      title: "Direct Communication",
      description:
        "Talk directly with your host before, during, and after your stay. No middleman, no delayed responses.",
    },
    {
      icon: Shield,
      title: "Flexible Policies",
      description:
        "We work with you on cancellations and changes. Real people, real flexibility — not rigid platform rules.",
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: "Experiences by BLB",
    legalName: "BLB REALTY LLC",
    url: baseUrl,
    logo: `${baseUrl}/logo.png`,
    description:
      "Premium vacation rentals in Houston, TX and Niagara Falls, NY. Book direct for the best rates — no Airbnb or Vrbo fees.",
    foundingDate: "2024",
    telephone: "+1-516-650-6653",
    contactPoint: {
      "@type": "ContactPoint",
      telephone: "+1-516-650-6653",
      contactType: "customer service",
      email: "blbrealtyllc@gmail.com",
      availableLanguage: "English",
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
    sameAs: [
      "https://www.instagram.com/experiencesbyblb",
      "https://www.facebook.com/experiencesbyblb",
    ],
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "About" },
          ]}
        />

        {/* Header */}
        <div className="text-center">
          <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
            About Us
          </p>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            About Experiences by BLB
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            We&apos;re BLB REALTY LLC — a team that believes vacation rentals
            should feel like home without the hassle. We operate premium,
            professionally managed properties and offer them directly to guests
            at the best possible rates.
          </p>
        </div>

        {/* Story section */}
        <div className="mx-auto mt-16 max-w-3xl">
          <div className="glass-card rounded-[28px] p-8 sm:p-10">
            <h2 className="text-[19px] font-semibold text-foreground">
              Who We Are
            </h2>
            <div className="mt-4 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Experiences by BLB started with a simple idea: guests deserve
                hotel-quality comfort with the space and value of a real home.
                Every property in our portfolio is hand-picked, thoughtfully
                furnished, and maintained to the highest standards.
              </p>
              <p>
                We believe in booking direct. When you book through us instead of
                a third-party platform, you save on service fees and get a direct
                line to your host. No algorithms, no automated responses — just
                real people who care about your stay.
              </p>
              <p>
                With properties in Houston&apos;s vibrant East Downtown (EaDo)
                neighborhood and near the iconic Niagara Falls in New York, we
                combine local expertise with responsive, hands-on hosting to
                make every trip memorable.
              </p>
            </div>
          </div>
        </div>

        {/* Our Mission */}
        <div className="mx-auto mt-12 max-w-3xl">
          <div className="glass-card rounded-[28px] p-8 sm:p-10">
            <h2 className="text-[19px] font-semibold text-foreground">
              Our Mission
            </h2>
            <div className="mt-4 space-y-4 text-[15px] leading-relaxed text-muted">
              <p>
                Our mission is to provide hotel-quality comfort with the space
                and value of a real home. We cut out the middleman so you get the
                best rates — no platform fees, no hidden charges. Just
                transparent pricing and a direct relationship with your host.
              </p>
              <p>
                Every property comes fully equipped with essentials like fast
                WiFi, full kitchens, free parking, and keyless self check-in. We
                handle the details so you can focus on the experience.
              </p>
            </div>
          </div>
        </div>

        {/* Where We Operate */}
        <div className="mt-20">
          <div className="text-center">
            <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
              Our Locations
            </p>
            <h2 className="mt-4 text-[22px] font-semibold tracking-tight text-foreground sm:text-[28px]">
              Where We Operate
            </h2>
            <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
              Curated vacation rentals in two of the most exciting destinations
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
                East Downtown (EaDo) properties near Minute Maid Park, Toyota
                Center, and 713 Music Hall. The heart of Houston&apos;s sports
                and entertainment district.
              </p>
              <p className="mt-4 text-[13px] font-medium text-accent-dark">
                Explore Houston &rarr;
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
                Cozy, pet-friendly homes minutes from Niagara Falls State Park,
                Maid of the Mist, Cave of the Winds, and Seneca Niagara Casino.
              </p>
              <p className="mt-4 text-[13px] font-medium text-accent-dark">
                Explore Niagara Falls &rarr;
              </p>
            </Link>
          </div>
        </div>

        {/* Stats */}
        <div className="mt-16 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {stats.map((stat) => (
            <div
              key={stat.label}
              className="glass-card rounded-[24px] p-6 text-center"
            >
              <p className="text-[28px] font-bold tracking-tight text-foreground sm:text-[32px]">
                {stat.value}
              </p>
              <p className="mt-1 text-[13px] text-muted">{stat.label}</p>
            </div>
          ))}
        </div>

        {/* Why Book Direct */}
        <div className="mt-20">
          <div className="text-center">
            <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
              The Direct Advantage
            </p>
            <h2 className="mt-4 text-[22px] font-semibold tracking-tight text-foreground sm:text-[28px]">
              Why Book Direct
            </h2>
            <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
              Skip the platforms and enjoy a better booking experience
            </p>
          </div>

          <div className="mt-10 grid gap-6 sm:grid-cols-3">
            {benefits.map((benefit) => (
              <div
                key={benefit.title}
                className="glass-card rounded-[28px] p-8 text-center"
              >
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full glass-surface">
                  <benefit.icon className="h-5 w-5 text-accent-dark" />
                </div>
                <h3 className="mt-5 text-[15px] font-semibold text-foreground">
                  {benefit.title}
                </h3>
                <p className="mt-2 text-[14px] leading-relaxed text-muted">
                  {benefit.description}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="mt-20 glass-card rounded-[32px] p-10 text-center sm:p-14">
          <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
            Start Your Experience
          </p>
          <h2 className="mt-4 text-[22px] font-semibold tracking-tight text-foreground sm:text-[28px]">
            Browse our properties
          </h2>
          <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
            Find your perfect stay and book direct for the best rates — no
            platform fees, ever.
          </p>
          <div className="mt-8">
            <Button href="/properties" size="lg" variant="secondary">
              Browse Properties
            </Button>
          </div>
        </div>
      </Container>

      {/* JSON-LD: Organization */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
