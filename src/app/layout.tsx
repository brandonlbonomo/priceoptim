import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import { getAllReviews } from "@/data/reviews";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
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
    legalName: "BLB Realty",
    url: baseUrl,
    logo: `${baseUrl}/logo.png`,
    description:
      "Premium vacation rentals in Houston, TX and Niagara Falls, NY. Book direct for the best rates — no Airbnb or Vrbo fees.",
    foundingDate: "2024",
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

  return (
    <html lang="en" className={`${inter.variable} h-full antialiased`}>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link rel="preconnect" href="https://hospitable.com" />
        <link rel="alternate" type="application/rss+xml" title="Experiences by BLB Blog" href="/blog/feed.xml" />
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
      </body>
    </html>
  );
}
