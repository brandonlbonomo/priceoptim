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
    default: "Bonomo Capital Group | Real Estate Investment, Development & Private Capital",
    template: "%s | Bonomo Capital Group",
  },
  description:
    "Bonomo Capital Group is a real estate investment firm that acquires, builds, and redevelops residential property, holds a growing rental portfolio, and operates in private credit and private equity. Direct stays available in Houston and Niagara Falls.",
  metadataBase: new URL(process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com"),
  alternates: {
    canonical: "/",
  },
  openGraph: {
    type: "website",
    siteName: "Bonomo Capital Group",
    images: [
      {
        url: "/bonomo-logo-horizontal.png",
        width: 1200,
        height: 630,
        alt: "Bonomo Capital Group — Real Estate Investment & Development",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Bonomo Capital Group | Real Estate Investment, Development & Private Capital",
    description:
      "A real estate investment firm — acquisitions, development, a growing rental portfolio, and private capital. Direct stays in Houston and Niagara Falls.",
    images: ["/bonomo-logo-horizontal.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";
  const reviews = getAllReviews();
  const totalReviews = reviews.length;
  const avgRating =
    Math.round(
      (reviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews) * 100
    ) / 100;

  const organizationJsonLd = {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: "Bonomo Capital Group",
    legalName: "Bonomo Capital Group",
    url: baseUrl,
    logo: `${baseUrl}/bonomo-logo-square.png`,
    description:
      "A real estate investment firm acquiring, building, and redeveloping residential property, holding a growing rental portfolio, and operating in private credit and private equity.",
    foundingDate: "2024",
    telephone: "+1-516-650-6653",
    contactPoint: {
      "@type": "ContactPoint",
      telephone: "+1-516-650-6653",
      contactType: "customer service",
      email: "info@bonomocapital.com",
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
    name: "Bonomo Capital Group",
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
    name: "Bonomo Capital Group — Direct Stays",
    legalName: "Bonomo Capital Group",
    url: baseUrl,
    logo: `${baseUrl}/bonomo-logo-square.png`,
    image: `${baseUrl}/bonomo-logo-square.png`,
    telephone: "+1-516-650-6653",
    email: "info@bonomocapital.com",
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
        <link rel="alternate" type="application/rss+xml" title="Bonomo Capital Group Blog" href="/blog/feed.xml" />
        <script id="mcjs" src="https://chimpstatic.com/mcjs-connected/js/users/4b04bf316771ed8107e92913e/db364ec57771e70054ea386ea.js" async />
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-FH3EZPNNZ3" />
        <script dangerouslySetInnerHTML={{ __html: `window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag('js',new Date());gtag('config','G-FH3EZPNNZ3');` }} />
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
