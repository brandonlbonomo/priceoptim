import type { Metadata } from "next";
import Link from "next/link";
import Image from "next/image";
import { MapPin, ArrowRight } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { getAllPosts } from "@/data/blog";
import { locations } from "@/data/locations";

export const metadata: Metadata = {
  title: "Destination Guides",
  alternates: { canonical: "/guides" },
  description:
    "Travel guides, neighborhood tips, and local insights for Houston EaDo and Niagara Falls, NY. Plan your perfect trip with Bonomo Capital Group.",
  openGraph: {
    title: "Destination Guides | Bonomo Capital Group",
    description:
      "Travel guides, neighborhood tips, and local insights for Houston and Niagara Falls.",
  },
};

const themes = [
  {
    title: "Houston, TX Guides",
    tag: "Houston",
    location: locations.find((l) => l.slug === "houston")!,
  },
  {
    title: "Niagara Falls, NY Guides",
    tag: "Niagara Falls",
    location: locations.find((l) => l.slug === "niagara-falls")!,
  },
];

export default function GuidesPage() {
  const allPosts = getAllPosts();

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Guides" },
          ]}
        />

        <div className="text-center">
          <p className="eyebrow">
            Destination Guides
          </p>
          <h1 className="mt-4 text-2xl font-display font-medium tracking-tight text-hunter sm:text-3xl">
            Plan Your Trip
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Local insights, neighborhood tips, and travel guides for our
            destinations — everything you need to make the most of your stay
          </p>
        </div>

        {/* Location cards */}
        <div className="mt-12 grid gap-6 sm:grid-cols-2">
          {themes.map(({ title, tag, location }) => {
            const posts = allPosts.filter((p) =>
              p.tags.some((t) => t.toLowerCase() === tag.toLowerCase())
            );

            return (
              <div key={tag} className="glass-card rounded-[4px] p-8">
                <div className="flex items-center gap-2 text-accent-dark">
                  <MapPin className="h-4 w-4" />
                  <span className="eyebrow">
                    {location.city}, {location.state}
                  </span>
                </div>
                <h2 className="mt-3 text-[20px] font-display font-medium text-hunter">
                  {title}
                </h2>
                <p className="mt-2 text-[14px] text-muted line-clamp-2">
                  {location.description.slice(0, 140)}...
                </p>

                {/* Post list */}
                <ul className="mt-6 space-y-3">
                  {posts.map((post) => (
                    <li key={post.slug}>
                      <Link
                        href={`/blog/${post.slug}`}
                        className="group flex items-center justify-between rounded-[3px] bg-black/[0.02] px-4 py-3 transition-colors duration-200 hover:bg-accent/[0.06]"
                      >
                        <span className="text-[14px] font-medium text-foreground group-hover:text-accent-dark transition-colors duration-200">
                          {post.title}
                        </span>
                        <ArrowRight className="h-3.5 w-3.5 shrink-0 text-muted transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-accent-dark" />
                      </Link>
                    </li>
                  ))}
                </ul>

                {/* Link to location properties */}
                <Link
                  href={`/properties/${location.slug}`}
                  className="mt-6 inline-flex items-center gap-1.5 text-[13px] font-semibold text-accent-dark transition-colors duration-200 hover:text-accent"
                >
                  Browse {location.city} rentals
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            );
          })}
        </div>

        {/* All posts grid */}
        <div className="mt-16">
          <h2 className="eyebrow text-center">
            All Guides
          </h2>
          <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {allPosts.map((post) => (
              <Link
                key={post.slug}
                href={`/blog/${post.slug}`}
                className="glass-card group block overflow-hidden rounded-[4px]"
              >
                <div className="relative aspect-[16/9] overflow-hidden">
                  <Image
                    src={post.coverImage}
                    alt={`${post.title} — Bonomo Capital Group travel guide`}
                    fill
                    className="object-cover transition-all duration-700 group-hover:scale-110"
                    sizes="(max-width: 768px) 100vw, (max-width: 1024px) 50vw, 33vw"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-black/5 to-transparent" />
                </div>
                <div className="p-5">
                  <div className="flex flex-wrap gap-1.5">
                    {post.tags.slice(0, 2).map((t) => (
                      <span
                        key={t}
                        className="rounded-full bg-accent/10 px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-accent-dark"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                  <h3 className="mt-2 text-[15px] font-display font-medium leading-snug text-hunter transition-colors duration-300 group-hover:text-accent-dark">
                    {post.title}
                  </h3>
                  <p className="mt-2 text-[13px] text-muted line-clamp-2">
                    {post.excerpt}
                  </p>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </Container>
    </section>
  );
}
