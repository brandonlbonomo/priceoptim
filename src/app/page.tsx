import { Hero } from "@/components/home/Hero";
import { FeaturedProperties } from "@/components/home/FeaturedProperties";
import { WhyBookDirect } from "@/components/home/WhyBookDirect";
import { EmailSignupCTA } from "@/components/home/EmailSignupCTA";

export default function HomePage() {
  return (
    <>
      <Hero />
      <FeaturedProperties />
      <WhyBookDirect />
      <EmailSignupCTA />

      {/* JSON-LD structured data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "LodgingBusiness",
            name: "Experiences by BLB",
            description:
              "Premium vacation rentals in Houston, TX and Niagara Falls, NY. Book direct for the best rates — no Airbnb or Vrbo fees. Properties near Minute Maid Park, Toyota Center, Niagara Falls State Park, and more.",
            url: process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000",
            numberOfRooms: 8,
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
          }),
        }}
      />
    </>
  );
}
