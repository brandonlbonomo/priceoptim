import type { Metadata } from "next";
import Link from "next/link";
import {
  DollarSign,
  MessageSquare,
  CalendarCheck,
  Tag,
  Star,
  ShieldCheck,
  Users,
  ArrowRight,
  Check,
  X,
} from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getAllReviews } from "@/data/reviews";

export const metadata: Metadata = {
  title: "Book Direct & Save — No Airbnb Fees",
  description:
    "Save money by booking your vacation rental directly with Bonomo Capital Group. No Airbnb service fees, better communication, flexible cancellations, and the lowest price guaranteed.",
  alternates: {
    canonical: "/book-direct",
  },
};

const comparisonRows = [
  {
    feature: "Service Fees",
    icon: DollarSign,
    airbnb: "Up to 14% guest fee added at checkout",
    direct: "No service fees — ever",
    airbnbGood: false,
    directGood: true,
  },
  {
    feature: "Communication",
    icon: MessageSquare,
    airbnb: "Messages filtered through Airbnb platform",
    direct: "Direct line to your host — text, email, or call",
    airbnbGood: false,
    directGood: true,
  },
  {
    feature: "Flexibility",
    icon: CalendarCheck,
    airbnb: "Rigid cancellation policies set by platform",
    direct: "Flexible policies — work directly with us",
    airbnbGood: false,
    directGood: true,
  },
  {
    feature: "Pricing",
    icon: Tag,
    airbnb: "Base rate + cleaning fee + service fee + taxes",
    direct: "Best rate guaranteed — no hidden platform fees",
    airbnbGood: false,
    directGood: true,
  },
];

const steps = [
  {
    step: "1",
    title: "Browse Properties",
    description:
      "Explore our vacation rentals in Houston and Niagara Falls. Filter by location, amenities, and guest count.",
  },
  {
    step: "2",
    title: "Select Your Dates",
    description:
      "Pick your check-in and check-out dates. Live availability and pricing update instantly — no waiting for host approval.",
  },
  {
    step: "3",
    title: "Book Securely",
    description:
      "Complete your reservation with secure payment processing. Instant confirmation, no platform middleman.",
  },
];

export default function BookDirectPage() {
  const allReviews = getAllReviews();
  const avgRating =
    allReviews.length > 0
      ? Math.round(
          (allReviews.reduce((sum, r) => sum + r.rating, 0) /
            allReviews.length) *
            100
        ) / 100
      : 0;

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Book Direct" },
          ]}
        />

        {/* Hero */}
        <div className="text-center">
          <p className="eyebrow">
            Save More. Book Smarter.
          </p>
          <h1 className="mt-4 text-2xl font-display font-medium tracking-tight text-hunter sm:text-3xl">
            Skip the Fees. Book Direct.
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            When you book through Airbnb or VRBO, you pay platform service fees
            that can add hundreds to your trip. Book directly with
            Bonomo Capital Group and keep that money in your pocket —
            same properties, same host, better price.
          </p>
        </div>

        {/* Comparison */}
        <div className="mt-14">
          <h2 className="eyebrow text-center">
            Airbnb vs. Book Direct
          </h2>

          <div className="mt-8 grid gap-4 sm:grid-cols-2">
            {/* Airbnb column header */}
            <div className="glass-card rounded-[4px] p-8">
              <div className="text-center">
                <span className="text-[19px] font-display font-medium text-hunter">
                  Airbnb / VRBO
                </span>
                <p className="mt-1 text-[13px] text-muted">
                  Third-party platform
                </p>
              </div>
              <div className="mt-6 space-y-4">
                {comparisonRows.map((row) => (
                  <div
                    key={row.feature}
                    className="rounded-[3px] bg-black/[0.02] px-5 py-4"
                  >
                    <div className="flex items-center gap-2">
                      <X className="h-4 w-4 shrink-0 text-red-400" />
                      <span className="text-[14px] font-medium text-foreground">
                        {row.feature}
                      </span>
                    </div>
                    <p className="mt-1.5 pl-6 text-[13px] leading-relaxed text-muted">
                      {row.airbnb}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Book Direct column */}
            <div className="glass-card rounded-[4px] border-accent/20 p-8">
              <div className="text-center">
                <span className="text-[19px] font-display font-medium text-accent-dark">
                  Book Direct
                </span>
                <p className="mt-1 text-[13px] text-muted">
                  Bonomo Capital Group
                </p>
              </div>
              <div className="mt-6 space-y-4">
                {comparisonRows.map((row) => (
                  <div
                    key={row.feature}
                    className="rounded-[3px] bg-accent/[0.04] px-5 py-4"
                  >
                    <div className="flex items-center gap-2">
                      <Check className="h-4 w-4 shrink-0 text-green-500" />
                      <span className="text-[14px] font-medium text-foreground">
                        {row.feature}
                      </span>
                    </div>
                    <p className="mt-1.5 pl-6 text-[13px] leading-relaxed text-muted">
                      {row.direct}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* How It Works */}
        <div className="mt-16">
          <h2 className="eyebrow text-center">
            How It Works
          </h2>

          <div className="mt-8 grid gap-6 sm:grid-cols-3">
            {steps.map((item) => (
              <div key={item.step} className="glass-card rounded-[4px] p-8 text-center">
                <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-accent/10 text-[15px] font-bold text-accent-dark">
                  {item.step}
                </div>
                <h3 className="mt-4 text-[17px] font-display font-medium text-hunter">
                  {item.title}
                </h3>
                <p className="mt-2 text-[13px] leading-relaxed text-muted">
                  {item.description}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Trust Signals */}
        <div className="mt-16">
          <h2 className="eyebrow text-center">
            Why Guests Trust Us
          </h2>

          <div className="mt-8 grid gap-6 sm:grid-cols-3">
            <div className="glass-card rounded-[4px] p-8 text-center">
              <div className="mx-auto flex h-9 w-9 items-center justify-center rounded-full bg-accent/10">
                <Star className="h-4 w-4 text-accent-dark" />
              </div>
              <p className="mt-4 text-[28px] font-display font-medium text-hunter">
                {allReviews.length}+
              </p>
              <p className="mt-1 text-[13px] text-muted">
                verified reviews with a {avgRating} average
              </p>
            </div>

            <div className="glass-card rounded-[4px] p-8 text-center">
              <div className="mx-auto flex h-9 w-9 items-center justify-center rounded-full bg-accent/10">
                <ShieldCheck className="h-4 w-4 text-accent-dark" />
              </div>
              <p className="mt-4 text-[28px] font-display font-medium text-hunter">
                Secure
              </p>
              <p className="mt-1 text-[13px] text-muted">
                encrypted payments processed through Stripe
              </p>
            </div>

            <div className="glass-card rounded-[4px] p-8 text-center">
              <div className="mx-auto flex h-9 w-9 items-center justify-center rounded-full bg-accent/10">
                <Users className="h-4 w-4 text-accent-dark" />
              </div>
              <p className="mt-4 text-[28px] font-display font-medium text-hunter">
                Real
              </p>
              <p className="mt-1 text-[13px] text-muted">
                every review is from a verified guest who stayed with us
              </p>
            </div>
          </div>
        </div>

        {/* Blog link + CTA */}
        <div className="mt-16 text-center">
          <Link
            href="/blog/airbnb-vs-book-direct-vacation-rentals"
            className="inline-flex items-center gap-1.5 text-[14px] font-medium text-accent-dark transition-colors hover:text-accent"
          >
            Read our full breakdown: Airbnb vs. Book Direct
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>

          <div className="mt-6">
            <Button href="/properties">Browse All Properties</Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
