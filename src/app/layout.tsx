import type { Metadata } from "next";
import { Inter, Playfair_Display } from "next/font/google";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { getAllReviews } from "@/data/reviews";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const playfair = Playfair_Display({
  variable: "--font-playfair",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: {
    default: "Experiences by BLB | Vacation Rentals – Book Direct & Save",
    template: "%s | Experiences by BLB",
  },
  description:
    "Book vacation rentals in Houston EaDo and Niagara Falls directly with Experiences by BLB. Skip Airbnb fees — best rates near Minute Maid Park, Toyota Center, and Niagara Falls State Park.",
  metadataBase: new URL(process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000"),
  alternates: {
    canonical: "/",
  },
  openGraph: {
    type: "website",
    siteName: "Experiences by BLB",
  },
  twitter: {
    card: "summary_large_image",
    title: "Experiences by BLB | Vacation Rentals – Book Direct & Save",
    description:
      "Book vacation rentals in Houston EaDo and Niagara Falls directly. Skip Airbnb fees — best rates near Minute Maid Park, Toyota Center, and Niagara Falls State Park.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
  const reviews = getAllReviews();
  const totalReviews = reviews.length;
  const avgRating =
    Math.round(
      (reviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews) * 100
    ) / 100;

  const organizationJsonLd = {
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
    aggregateRating: {
      "@type": "AggregateRating",
      ratingValue: avgRating,
      reviewCount: totalReviews,
      bestRating: 5,
      worstRating: 1,
    },
    sameAs: [
      "https://www.instagram.com/experiencesbyblb",
      "https://www.facebook.com/experiencesbyblb",
    ],
  };

  const websiteJsonLd = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: "Experiences by BLB",
    url: baseUrl,
    potentialAction: {
      "@type": "SearchAction",
      target: {
        "@type": "EntryPoint",
        urlTemplate: `${baseUrl}/properties?q={search_term_string}`,
      },
      "query-input": "required name=search_term_string",
    },
  };

  const localBusinessJsonLd = {
    "@context": "https://schema.org",
    "@type": "LodgingBusiness",
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
        "Monday", "Tuesday", "Wednesday", "Thursday",
        "Friday", "Saturday", "Sunday",
      ],
      opens: "00:00",
      closes: "23:59",
    },
    priceRange: "$$",
    ...(totalReviews > 0 && {
      aggregateRating: {
        "@type": "AggregateRating",
        ratingValue: avgRating,
        reviewCount: totalReviews,
        bestRating: 5,
        worstRating: 1,
      },
    }),
  };

  return (
    <html lang="en" className={`${inter.variable} ${playfair.variable} h-full antialiased`}>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link rel="preconnect" href="https://hospitable.com" />
        <link rel="alternate" type="application/rss+xml" title="Experiences by BLB Blog" href="/blog/feed.xml" />
        <script id="mcjs" dangerouslySetInnerHTML={{ __html: `!function(c,h,i,m,p){m=c.createElement(h),p=c.getElementsByTagName(h)[0],m.async=1,m.src=i,p.parentNode.insertBefore(m,p)}(document,"script","https://chimpstatic.com/mcjs-connected/js/users/4b04bf316771ed8107e92913e/db364ec57771e70054ea386ea.js");` }} />
      </head>
      <body className="flex min-h-full flex-col font-sans">
        <Navbar />
        <main className="flex-1">{children}</main>
        <Footer />

        {/* Global JSON-LD: Organization */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationJsonLd) }}
        />
        {/* Global JSON-LD: WebSite with SearchAction */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteJsonLd) }}
        />
        {/* Global JSON-LD: LocalBusiness (ties to Google Business Profile) */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(localBusinessJsonLd) }}
        />
      </body>
    </html>
  );
}
