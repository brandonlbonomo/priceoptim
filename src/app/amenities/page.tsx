import type { Metadata } from "next";
import Link from "next/link";
import {
  Wifi,
  CookingPot,
  Tv,
  Car,
  ShieldCheck,
  Bath,
  Bed,
  ArrowRight,
} from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getActiveProperties } from "@/data/properties";
import type { AmenityCategory } from "@/types/property";

export const metadata: Metadata = {
  title: "Amenities | Every Property Feature at a Glance",
  description:
    "Explore all amenities included with our vacation rentals — free WiFi, full kitchens, free parking, pet-friendly options, streaming TV, and more. Every stay includes hotel-quality essentials at no extra cost.",
  alternates: {
    canonical: "/amenities",
  },
};

const categoryMeta: Record<
  string,
  { label: string; icon: typeof Wifi; description: string }
> = {
  essentials: {
    label: "Essentials",
    icon: Wifi,
    description:
      "The basics you need for a comfortable stay — WiFi, climate control, laundry, and more.",
  },
  kitchen: {
    label: "Kitchen",
    icon: CookingPot,
    description:
      "Fully equipped kitchens so you can cook meals, brew coffee, and feel at home.",
  },
  entertainment: {
    label: "Entertainment",
    icon: Tv,
    description:
      "Smart TVs with streaming services to unwind after a day of exploring.",
  },
  parking: {
    label: "Parking",
    icon: Car,
    description:
      "Free on-site parking at every property — no garage fees, no hunting for spots.",
  },
  safety: {
    label: "Safety",
    icon: ShieldCheck,
    description:
      "Smoke detectors, first aid kits, and secure access for your peace of mind.",
  },
  bathroom: {
    label: "Bathroom",
    icon: Bath,
    description:
      "Fresh towels and hotel-quality toiletries provided for every guest.",
  },
  bedroom: {
    label: "Bedroom",
    icon: Bed,
    description:
      "Premium linens, comfortable mattresses, and blackout-ready rooms for restful sleep.",
  },
};

const categoryOrder: AmenityCategory[] = [
  "essentials",
  "kitchen",
  "entertainment",
  "parking",
  "safety",
  "bathroom",
  "bedroom",
];

export default function AmenitiesPage() {
  const properties = getActiveProperties();

  // Group unique amenities by category across all properties
  const grouped = new Map<string, Set<string>>();

  for (const property of properties) {
    for (const amenity of property.amenities) {
      if (!grouped.has(amenity.category)) {
        grouped.set(amenity.category, new Set());
      }
      grouped.get(amenity.category)!.add(amenity.name);
    }
  }

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Amenities" },
          ]}
        />

        <div className="text-center">
          <p className="eyebrow">
            What&apos;s Included
          </p>
          <h1 className="mt-4 text-2xl font-display font-medium tracking-tight text-hunter sm:text-3xl">
            Every Property Feature at a Glance
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Every Bonomo Capital Group vacation rental comes fully
            equipped with the amenities you need — from free WiFi and parking to
            full kitchens and streaming TV. No surprises, no hidden fees.
          </p>
        </div>

        {/* Amenity category cards */}
        <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {categoryOrder.map((cat) => {
            const meta = categoryMeta[cat];
            const amenities = grouped.get(cat);
            if (!meta || !amenities || amenities.size === 0) return null;

            const Icon = meta.icon;

            return (
              <div key={cat} className="glass-card rounded-[4px] p-8">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-accent/10">
                    <Icon className="h-4 w-4 text-accent-dark" />
                  </div>
                  <h2 className="text-[17px] font-display font-medium text-hunter">
                    {meta.label}
                  </h2>
                </div>

                <p className="mt-3 text-[13px] leading-relaxed text-muted">
                  {meta.description}
                </p>

                <ul className="mt-5 space-y-2">
                  {Array.from(amenities).map((name) => (
                    <li
                      key={name}
                      className="flex items-center gap-2 rounded-[4px] bg-black/[0.02] px-3.5 py-2"
                    >
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-accent-dark/60" />
                      <span className="text-[14px] text-foreground">
                        {name}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>

        {/* Property count + CTA */}
        <div className="mt-16 text-center">
          <p className="text-[14px] text-muted">
            All amenities are included at no extra cost across our{" "}
            {properties.length} properties.
          </p>
          <div className="mt-5">
            <Button href="/nomo-collection">Browse All Properties</Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
