import type { Metadata } from "next";
import Link from "next/link";
import {
  Trophy,
  UtensilsCrossed,
  Beer,
  Palette,
  TrainFront,
  ArrowRight,
  MapPin,
} from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";

export const metadata: Metadata = {
  title: "Things to Do in Houston EaDo",
  description:
    "Discover the best things to do near Minute Maid Park and East Downtown Houston — sports, dining, breweries, nightlife, and arts. Plan your Houston trip with our local guide.",
  alternates: {
    canonical: "/things-to-do/houston",
  },
};

const sections = [
  {
    title: "Sports & Entertainment",
    icon: Trophy,
    items: [
      {
        name: "Minute Maid Park",
        description:
          "Home of the Houston Astros. Catch a game, enjoy craft beer from the concourse, and watch the iconic train run after every home run. Our EaDo rentals are within walking distance.",
      },
      {
        name: "Toyota Center",
        description:
          "The home court of the Houston Rockets and a top concert venue. From NBA games to world tours, Toyota Center keeps the energy going year-round.",
      },
      {
        name: "713 Music Hall",
        description:
          "Houston's premier mid-size concert venue in the heart of EaDo. Intimate shows, great sound, and a rooftop bar with downtown views.",
      },
      {
        name: "Shell Energy Stadium",
        description:
          "Home of the Houston Dynamo and Houston Dash. Soccer matches here bring a vibrant atmosphere to the EaDo neighborhood, especially on warm evenings.",
      },
    ],
    blogLink: {
      href: "/blog/toyota-center-events-guide-houston",
      label: "Read our Toyota Center events guide",
    },
  },
  {
    title: "Dining & Nightlife",
    icon: UtensilsCrossed,
    items: [
      {
        name: "Original Ninfa's on Navigation",
        description:
          "The birthplace of the fajita. This Houston institution serves Tex-Mex that draws locals and visitors alike. Do not skip the tacos al carbon.",
      },
      {
        name: "El Tiempo Cantina",
        description:
          "Another Tex-Mex heavyweight on Navigation Boulevard. Known for sizzling fajitas, strong margaritas, and generous portions.",
      },
      {
        name: "Nancy's Hustle",
        description:
          "A modern American bistro in EaDo with a daily-changing menu. Reservations fill up fast — book ahead for one of Houston's most talked-about dining experiences.",
      },
      {
        name: "Truck Yard Houston",
        description:
          "An outdoor bar and food truck park in EaDo. Live music, craft beer, and a laid-back vibe make it the perfect post-game hangout.",
      },
    ],
    blogLink: {
      href: "/blog/best-restaurants-near-minute-maid-park",
      label: "Best restaurants near Minute Maid Park",
    },
  },
  {
    title: "Breweries",
    icon: Beer,
    items: [
      {
        name: "8th Wonder Brewery",
        description:
          "EaDo's original craft brewery with a spacious taproom and outdoor patio. Try the Dome Faux'm Cream Ale, an Astrodome-inspired local favorite.",
      },
      {
        name: "True Anomaly Brewing",
        description:
          "Space-themed brewery with inventive IPAs and a cozy taproom just blocks from Minute Maid Park. Great pre-game stop.",
      },
      {
        name: "Sigma Brewing Company",
        description:
          "A hidden gem in a converted warehouse. Rotating taps, a family-friendly patio, and some of the most creative brews in Houston.",
      },
    ],
    blogLink: {
      href: "/blog/best-restaurants-breweries-near-minute-maid-park",
      label: "Full EaDo brewery and restaurant guide",
    },
  },
  {
    title: "Arts & Culture",
    icon: Palette,
    items: [
      {
        name: "HMAAC (Houston Museum of African American Culture)",
        description:
          "Located in EaDo, HMAAC showcases art, history, and culture through rotating exhibitions and community programming.",
      },
      {
        name: "EaDo Street Art & Murals",
        description:
          "Explore vibrant murals and street art installations throughout East Downtown. The neighborhood doubles as an open-air gallery.",
      },
      {
        name: "The Houston Museum District",
        description:
          "Just a short drive from EaDo, the Museum District houses 19 museums including MFAH, the Children's Museum, and the Houston Museum of Natural Science.",
      },
    ],
    blogLink: {
      href: "/blog/eado-neighborhood-guide-houston",
      label: "Explore the EaDo neighborhood guide",
    },
  },
  {
    title: "Getting Around",
    icon: TrainFront,
    items: [
      {
        name: "METRORail",
        description:
          "Houston's light rail system runs through EaDo with stops at EaDo/Stadium and Convention District. Convenient access to Downtown, Midtown, and the Museum District.",
      },
      {
        name: "Walk & Bike EaDo",
        description:
          "EaDo is one of Houston's most walkable neighborhoods. Minute Maid Park, Toyota Center, and dozens of restaurants are all within a 10-minute walk of our properties.",
      },
      {
        name: "Free Parking",
        description:
          "Every one of our Houston vacation rentals includes free on-site parking — no garage fees, no meter anxiety. Drive in and leave the car until you are ready to explore.",
      },
    ],
    blogLink: {
      href: "/blog/top-10-things-to-do-in-houston-eado",
      label: "Top 10 things to do in EaDo",
    },
  },
];

export default function HoustonThingsToDoPage() {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TouristDestination",
    name: "East Downtown Houston (EaDo)",
    description:
      "Discover the best things to do in Houston's East Downtown neighborhood — from Astros games at Minute Maid Park to craft breweries, Tex-Mex restaurants, and live music venues.",
    url: `${baseUrl}/things-to-do/houston`,
    touristType: [
      "Sports fans",
      "Foodies",
      "Music lovers",
      "Family travelers",
    ],
    geo: {
      "@type": "GeoCoordinates",
      latitude: 29.7522,
      longitude: -95.3544,
    },
    includesAttraction: [
      {
        "@type": "TouristAttraction",
        name: "Minute Maid Park",
        description: "Home of the Houston Astros MLB team",
      },
      {
        "@type": "TouristAttraction",
        name: "Toyota Center",
        description: "Home of the Houston Rockets NBA team and concert venue",
      },
      {
        "@type": "TouristAttraction",
        name: "713 Music Hall",
        description: "Premier mid-size concert venue in EaDo",
      },
    ],
  };

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Things to Do", href: "/things-to-do/houston" },
            { label: "Houston" },
          ]}
        />

        <div className="text-center">
          <div className="mx-auto inline-flex items-center gap-1.5 rounded-full bg-accent/10 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent-dark">
            <MapPin className="h-3 w-3" />
            East Downtown (EaDo)
          </div>
          <h1 className="mt-5 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            Things to Do in Houston EaDo
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
            East Downtown Houston is one of the city&apos;s most exciting
            neighborhoods — home to Minute Maid Park, Toyota Center, world-class
            Tex-Mex, craft breweries, and a thriving arts scene. Here&apos;s
            everything worth doing within walking distance of our properties.
          </p>
        </div>

        {/* Sections */}
        <div className="mt-14 space-y-8">
          {sections.map((section) => {
            const Icon = section.icon;

            return (
              <div key={section.title} className="glass-card rounded-[20px] p-8">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-accent/10">
                    <Icon className="h-4 w-4 text-accent-dark" />
                  </div>
                  <h2 className="text-[19px] font-semibold text-foreground">
                    {section.title}
                  </h2>
                </div>

                <div className="mt-6 grid gap-4 sm:grid-cols-2">
                  {section.items.map((item) => (
                    <div
                      key={item.name}
                      className="rounded-[16px] bg-black/[0.02] px-5 py-4"
                    >
                      <h3 className="text-[15px] font-semibold text-foreground">
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
            Stay in the middle of it all — our EaDo vacation rentals put you
            within walking distance of everything on this list.
          </p>
          <div className="mt-5">
            <Button href="/properties/houston">
              Browse Houston Properties
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
