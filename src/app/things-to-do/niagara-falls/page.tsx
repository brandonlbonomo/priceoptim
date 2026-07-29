import type { Metadata } from "next";
import Link from "next/link";
import {
  Waves,
  Compass,
  Baby,
  UtensilsCrossed,
  Map,
  ArrowRight,
  MapPin,
} from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";

export const metadata: Metadata = {
  title: "Things to Do in Niagara Falls, NY",
  description:
    "Plan your Niagara Falls trip — the best attractions, tours, family activities, restaurants, and day trips on the New York side. Local tips from Bonomo Capital Group.",
  alternates: {
    canonical: "/things-to-do/niagara-falls",
  },
};

const sections = [
  {
    title: "Natural Attractions",
    icon: Waves,
    items: [
      {
        name: "Niagara Falls State Park",
        description:
          "America's oldest state park and the best vantage point for all three waterfalls — Horseshoe Falls, American Falls, and Bridal Veil Falls. Free to enter, with paved pathways and observation decks throughout.",
      },
      {
        name: "Cave of the Winds",
        description:
          "Get drenched on the Hurricane Deck just 20 feet from Bridal Veil Falls. Wooden walkways descend into the gorge for an up-close experience you will not forget. Open May through October.",
      },
      {
        name: "Niagara Gorge Trail",
        description:
          "Hike along the dramatic gorge rim for stunning views of the rapids and whirlpool. Multiple trail heads connect to the park and the Robert Moses Parkway trail system.",
      },
      {
        name: "Three Sisters Islands",
        description:
          "A chain of small islands in the upper rapids accessible by footbridges from Goat Island. Peaceful scenery, picnic spots, and views of the Canadian Horseshoe Falls from a unique angle.",
      },
    ],
    blogLink: {
      href: "/blog/maid-of-the-mist-vs-cave-of-the-winds",
      label: "Maid of the Mist vs. Cave of the Winds — which is better?",
    },
  },
  {
    title: "Tours & Experiences",
    icon: Compass,
    items: [
      {
        name: "Maid of the Mist",
        description:
          "The iconic boat tour that takes you into the mist at the base of Horseshoe Falls. Running since 1846, it remains one of North America's most famous tourist experiences. Blue ponchos provided.",
      },
      {
        name: "Niagara Falls Illumination & Fireworks",
        description:
          "Every evening the falls are illuminated in vibrant colors, and on select nights (Fridays and holidays in season) a fireworks display launches from the Canadian side — visible from the New York shore.",
      },
      {
        name: "Whirlpool Jet Boat Tours",
        description:
          "A high-speed boat ride through the Class V Niagara Whirlpool rapids. Available as a wet or dry ride. Departs from Lewiston, a quick drive north of the falls.",
      },
    ],
    blogLink: {
      href: "/blog/ultimate-guide-to-visiting-niagara-falls",
      label: "Read our ultimate Niagara Falls visitor guide",
    },
  },
  {
    title: "Family Activities",
    icon: Baby,
    items: [
      {
        name: "Niagara Falls Aquarium",
        description:
          "Home to sea lions, penguins, sharks, and interactive touch tanks. A great indoor option on rainy days or when you need a break from the mist. Located near the state park entrance.",
      },
      {
        name: "Old Falls Street",
        description:
          "A pedestrian-friendly block just outside the park with shops, restaurants, and seasonal events. Free outdoor concerts and festivals run throughout the summer months.",
      },
      {
        name: "Seneca Niagara Casino & Resort",
        description:
          "For the adults in the group — table games, slots, live entertainment, and several restaurants including Thunder Falls Buffet. Connected to a full-service hotel and spa.",
      },
      {
        name: "Whirlpool State Park",
        description:
          "A short drive north of the main falls, this park offers hiking trails down to the Niagara Whirlpool with picnic areas and scenic overlooks. A quieter alternative to the crowded main park.",
      },
    ],
    blogLink: {
      href: "/blog/family-vacation-guide-niagara-falls-ny-with-kids",
      label: "Family vacation guide: Niagara Falls with kids",
    },
  },
  {
    title: "Dining",
    icon: UtensilsCrossed,
    items: [
      {
        name: "The Red Coach Inn",
        description:
          "An English-style inn and restaurant overlooking the upper rapids. Fine dining in a historic setting with views that rival the food. Reservations recommended.",
      },
      {
        name: "Savor Restaurant",
        description:
          "A modern American restaurant on Old Falls Street with seasonal menus, craft cocktails, and an upscale-casual atmosphere. Walking distance from the park.",
      },
      {
        name: "DiCamillo Bakery",
        description:
          "A Niagara Falls institution since 1920. Known for Italian bread, biscotti, and pastries. Pick up fresh bread for your rental kitchen or grab a quick breakfast before heading to the falls.",
      },
    ],
    blogLink: {
      href: "/blog/niagara-falls-vs-niagara-on-the-lake",
      label: "Niagara Falls vs. Niagara-on-the-Lake — compare",
    },
  },
  {
    title: "Day Trips",
    icon: Map,
    items: [
      {
        name: "Niagara-on-the-Lake, Ontario",
        description:
          "Cross the border into this charming Canadian town known for its wineries, Shaw Festival theatre, and Queen Street boutique shopping. About 20 minutes from the falls.",
      },
      {
        name: "Letchworth State Park",
        description:
          "Dubbed the 'Grand Canyon of the East,' Letchworth is about 90 minutes southeast. Three major waterfalls on the Genesee River, plus 66 miles of hiking trails.",
      },
      {
        name: "Buffalo, NY",
        description:
          "Just 20 miles south, Buffalo offers the original Anchor Bar (birthplace of the buffalo wing), the Albright-Knox Art Gallery, Canalside waterfront, and a revitalized downtown.",
      },
      {
        name: "Fort Niagara State Park",
        description:
          "Historic military fort at the mouth of the Niagara River on Lake Ontario. Guided tours, reenactments, and sweeping lake views. About 15 minutes north of the falls.",
      },
    ],
    blogLink: {
      href: "/blog/nyc-to-niagara-falls-road-trip-guide",
      label: "NYC to Niagara Falls road trip guide",
    },
  },
];

export default function NiagaraFallsThingsToDoPage() {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TouristDestination",
    name: "Niagara Falls, New York",
    description:
      "Discover the best things to do in Niagara Falls, NY — from the iconic waterfalls and Cave of the Winds to family activities, dining, and scenic day trips.",
    url: `${baseUrl}/things-to-do/niagara-falls`,
    touristType: [
      "Nature lovers",
      "Family travelers",
      "Adventure seekers",
      "Couples",
    ],
    geo: {
      "@type": "GeoCoordinates",
      latitude: 43.0962,
      longitude: -79.0377,
    },
    includesAttraction: [
      {
        "@type": "TouristAttraction",
        name: "Niagara Falls State Park",
        description:
          "America's oldest state park with views of all three waterfalls",
      },
      {
        "@type": "TouristAttraction",
        name: "Cave of the Winds",
        description:
          "Wooden walkways descending into the gorge near Bridal Veil Falls",
      },
      {
        "@type": "TouristAttraction",
        name: "Maid of the Mist",
        description:
          "Iconic boat tour into the mist at the base of Horseshoe Falls",
      },
    ],
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Things to Do", href: "/things-to-do/niagara-falls" },
            { label: "Niagara Falls" },
          ]}
        />

        <div className="text-center">
          <div className="eyebrow mx-auto inline-flex items-center gap-1.5">
            <MapPin className="h-3 w-3" />
            Niagara Falls, NY
          </div>
          <h1 className="mt-5 font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Things to Do in Niagara Falls
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            Niagara Falls is more than just the waterfalls. From boat tours and
            gorge hikes to family-friendly attractions and day trips into wine
            country, here is everything worth doing on the New York side — plus a
            few excursions across the border.
          </p>
        </div>

        {/* Sections */}
        <div className="mt-14 space-y-8">
          {sections.map((section) => {
            const Icon = section.icon;

            return (
              <div key={section.title} className="glass-card rounded-[4px] p-8">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-accent/10">
                    <Icon className="h-4 w-4 text-gold-dark" />
                  </div>
                  <h2 className="font-display text-[19px] font-medium text-hunter">
                    {section.title}
                  </h2>
                </div>

                <div className="mt-6 grid gap-4 sm:grid-cols-2">
                  {section.items.map((item) => (
                    <div
                      key={item.name}
                      className="rounded-[3px] bg-black/[0.02] px-5 py-4"
                    >
                      <h3 className="font-display text-[15px] font-medium text-hunter">
                        {item.name}
                      </h3>
                      <p className="mt-1.5 text-[13px] leading-relaxed text-muted">
                        {item.description}
                      </p>
                    </div>
                  ))}
                </div>

                {section.blogLink && (
                  <Link
                    href={section.blogLink.href}
                    className="mt-5 inline-flex items-center gap-1.5 text-[13px] font-semibold text-accent-dark transition-colors duration-200 hover:text-accent"
                  >
                    {section.blogLink.label}
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                )}
              </div>
            );
          })}
        </div>

        {/* CTA */}
        <div className="mt-16 text-center">
          <p className="text-[14px] text-muted">
            Stay minutes from the falls — our Niagara Falls vacation rentals put
            you close to every attraction on this list.
          </p>
          <div className="mt-5">
            <Button href="/nomo-collection">
              Browse Niagara Falls Properties
            </Button>
          </div>
        </div>
      </Container>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
