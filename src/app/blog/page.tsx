import type { Metadata } from "next";
import Link from "next/link";
import Image from "next/image";
import { Container } from "@/components/ui/Container";
import { getAllPosts } from "@/data/blog";

export const metadata: Metadata = {
  title: "Blog",
  alternates: { canonical: "/blog" },
  description:
    "Travel guides, tips, and local insights for Houston EaDo and Niagara Falls. Discover the best things to do, where to eat, and how to save on vacation rentals.",
  openGraph: {
    title: "Blog | BLB Realty",
    description:
      "Travel guides, tips, and local insights for Houston EaDo and Niagara Falls.",
  },
};

export default function BlogPage() {
  const posts = getAllPosts();

  return (
    <section className="py-14 sm:py-20">
      <Container>
        <div className="text-center">
          <p className="eyebrow">
            Travel Journal
          </p>
          <h1 className="font-display mt-4 text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
            Blog
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Local guides, travel tips, and insider knowledge for your next
            getaway
          </p>
        </div>

        <div className="mt-12 grid gap-8 sm:grid-cols-2">
          {posts.map((post) => (
            <Link
              key={post.slug}
              href={`/blog/${post.slug}`}
              className="glass-card group block overflow-hidden rounded-[4px]"
            >
              <div className="relative aspect-[16/9] overflow-hidden">
                <Image
                  src={post.coverImage}
                  alt={`${post.title} — BLB Realty travel guide`}
                  fill
                  className="object-cover transition-all duration-700 group-hover:scale-110"
                  sizes="(max-width: 768px) 100vw, 50vw"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-black/5 to-transparent" />
                <div className="absolute bottom-4 left-4 flex flex-wrap gap-2">
                  {post.tags.slice(0, 2).map((tag) => (
                    <span
                      key={tag}
                      className="glass-dark rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.15em] text-white"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-6">
                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted">
                  {new Date(post.publishedAt).toLocaleDateString("en-US", {
                    year: "numeric",
                    month: "long",
                    day: "numeric",
                  })}
                </p>
                <h2 className="font-display mt-2 text-[17px] font-medium leading-snug text-hunter transition-colors duration-300 group-hover:text-gold-dark">
                  {post.title}
                </h2>
                <p className="mt-3 text-[14px] leading-relaxed text-muted line-clamp-3">
                  {post.excerpt}
                </p>
                <span className="mt-4 inline-block text-[13px] font-semibold text-gold-dark">
                  Read More
                </span>
              </div>
            </Link>
          ))}
        </div>
      </Container>
    </section>
  );
}
