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
            name: "BLB Realty",
            description:
              "Premium vacation rentals with the best direct booking rates.",
            url: process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000",
            numberOfRooms: 8,
            priceRange: "$120 - $195 per night",
          }),
        }}
      />
    </>
  );
}
