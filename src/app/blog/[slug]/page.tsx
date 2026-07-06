import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import { ArrowLeft } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
import { TableOfContents } from "@/components/blog/TableOfContents";
import { getAllPosts, getPostBySlug } from "@/data/blog";

interface BlogPostPageProps {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return getAllPosts().map((post) => ({
    slug: post.slug,
  }));
}

export async function generateMetadata({
  params,
}: BlogPostPageProps): Promise<Metadata> {
  const { slug } = await params;
  const post = getPostBySlug(slug);

  if (!post) {
    return { title: "Post Not Found" };
  }

  return {
    title: post.title,
    description: post.metaDescription,
    alternates: {
      canonical: `/blog/${slug}`,
    },
    openGraph: {
      title: post.title,
      description: post.metaDescription,
      type: "article",
      publishedTime: post.publishedAt,
      authors: [post.author],
      images: post.coverImage ? [post.coverImage] : [],
    },
  };
}

export default async function BlogPostPage({ params }: BlogPostPageProps) {
  const { slug } = await params;
  const post = getPostBySlug(slug);

  if (!post) {
    notFound();
  }

  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";
  const wordCount = post.content.replace(/<[^>]+>/g, "").split(/\s+/).filter(Boolean).length;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: post.title,
    description: post.metaDescription,
    image: post.coverImage.startsWith("http") ? post.coverImage : `${baseUrl}${post.coverImage}`,
    datePublished: post.publishedAt,
    ...(post.updatedAt && { dateModified: post.updatedAt }),
    wordCount,
    author: {
      "@type": "Organization",
      name: post.author,
    },
    publisher: {
      "@type": "Organization",
      name: "BLB Realty",
      url: baseUrl,
    },
    mainEntityOfPage: {
      "@type": "WebPage",
      "@id": `${baseUrl}/blog/${post.slug}`,
    },
  };

  return (
    <article className="py-8 sm:py-12">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Blog", href: "/blog" },
            { label: post.title },
          ]}
        />

        {/* Back link */}
        <Link
          href="/blog"
          className="inline-flex items-center gap-2 text-[13px] font-medium text-muted transition-colors duration-300 hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          All Posts
        </Link>

        {/* Header */}
        <div className="mt-8 max-w-3xl">
          <div className="flex flex-wrap gap-2">
            {post.tags.map((tag) => (
              <span
                key={tag}
                className="rounded-full bg-accent/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.15em] text-accent-dark"
              >
                {tag}
              </span>
            ))}
          </div>
          <h1 className="font-display mt-4 text-3xl font-medium tracking-tight text-hunter sm:text-[40px] sm:leading-tight">
            {post.title}
          </h1>
          <div className="mt-4 flex items-center gap-3 text-[13px] text-muted">
            <span>{post.author}</span>
            <span className="h-1 w-1 rounded-full bg-muted" />
            <time dateTime={post.publishedAt}>
              {new Date(post.publishedAt).toLocaleDateString("en-US", {
                year: "numeric",
                month: "long",
                day: "numeric",
              })}
            </time>
            {post.updatedAt && (
              <>
                <span className="h-1 w-1 rounded-full bg-muted" />
                <span>
                  Updated{" "}
                  <time dateTime={post.updatedAt}>
                    {new Date(post.updatedAt).toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "long",
                      day: "numeric",
                    })}
                  </time>
                </span>
              </>
            )}
          </div>
        </div>

        {/* Cover image */}
        <div className="mt-8 overflow-hidden rounded-[4px]">
          <div className="relative aspect-[21/9]">
            <Image
              src={post.coverImage}
              alt={`Cover image for ${post.title} — BLB Realty blog`}
              fill
              className="object-cover"
              sizes="(max-width: 1280px) 100vw, 1280px"
              priority
            />
          </div>
        </div>

        {/* Table of Contents */}
        <div className="mx-auto mt-10 max-w-3xl">
          <TableOfContents html={post.content} />
        </div>

        {/* Article content */}
        <div className="mx-auto mt-12 max-w-3xl">
          <div
            className="
              text-[16px] leading-[1.85] text-primary-light
              [&>h2]:font-display [&>h2]:mt-10 [&>h2]:mb-4 [&>h2]:text-[22px] [&>h2]:font-medium [&>h2]:tracking-tight [&>h2]:text-hunter
              [&>h3]:font-display [&>h3]:mt-6 [&>h3]:mb-3 [&>h3]:text-[18px] [&>h3]:font-medium [&>h3]:text-hunter
              [&>p]:mb-5
              [&>p>a]:font-medium [&>p>a]:text-gold-dark [&>p>a]:underline [&>p>a]:underline-offset-2 [&>p>a]:decoration-gold/30 hover:[&>p>a]:decoration-gold-dark
              [&>p>strong]:font-semibold [&>p>strong]:text-foreground
              [&>ul]:mb-5 [&>ul]:list-disc [&>ul]:pl-6 [&>ul]:space-y-2
              [&>ol]:mb-5 [&>ol]:list-decimal [&>ol]:pl-6 [&>ol]:space-y-2
            "
            dangerouslySetInnerHTML={{ __html: post.content }}
          />

          {/* CTA */}
          <div className="mt-14 glass-card rounded-[4px] p-8 text-center sm:p-10">
            <p className="eyebrow">
              Plan Your Stay
            </p>
            <h2 className="font-display mt-3 text-[22px] font-medium tracking-tight text-hunter">
              Ready to book your next getaway?
            </h2>
            <p className="mx-auto mt-3 max-w-md text-[15px] text-muted">
              Browse our vacation rentals in Houston EaDo and Niagara Falls. Book
              direct for the best rates — no platform fees.
            </p>
            <div className="mt-6">
              <Button href="/properties" size="md">
                Browse Properties
              </Button>
            </div>
          </div>

          {/* Related Posts */}
          {(() => {
            const relatedPosts = getAllPosts()
              .filter((p) => p.slug !== post.slug)
              .filter((p) => p.tags.some((t) => post.tags.includes(t)))
              .slice(0, 2);
            if (relatedPosts.length === 0) return null;
            return (
              <div className="mt-14">
                <h2 className="font-display mb-6 text-[19px] font-medium text-hunter">
                  Related Posts
                </h2>
                <div className="grid gap-6 sm:grid-cols-2">
                  {relatedPosts.map((related) => (
                    <Link
                      key={related.slug}
                      href={`/blog/${related.slug}`}
                      className="glass-card group block overflow-hidden rounded-[4px]"
                    >
                      <div className="relative aspect-[16/9] overflow-hidden">
                        <Image
                          src={related.coverImage}
                          alt={`${related.title} — BLB Realty blog`}
                          fill
                          className="object-cover transition-all duration-700 group-hover:scale-110"
                          sizes="(max-width: 768px) 100vw, 50vw"
                                    />
                      </div>
                      <div className="p-5">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted">
                          {new Date(related.publishedAt).toLocaleDateString("en-US", {
                            year: "numeric",
                            month: "long",
                            day: "numeric",
                          })}
                        </p>
                        <h3 className="font-display mt-2 text-[15px] font-medium leading-snug text-hunter transition-colors duration-300 group-hover:text-gold-dark">
                          {related.title}
                        </h3>
                      </div>
                    </Link>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>
      </Container>

      {/* JSON-LD structured data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </article>
  );
}
