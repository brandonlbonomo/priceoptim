import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import { ArrowLeft } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";
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

  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
  const wordCount = post.content.replace(/<[^>]+>/g, "").split(/\s+/).filter(Boolean).length;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: post.title,
    description: post.metaDescription,
    image: post.coverImage.startsWith("http") ? post.coverImage : `${baseUrl}${post.coverImage}`,
    datePublished: post.publishedAt,
    wordCount,
    author: {
      "@type": "Organization",
      name: post.author,
    },
    publisher: {
      "@type": "Organization",
      name: "Experiences by BLB",
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
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-foreground sm:text-[40px] sm:leading-tight">
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
          </div>
        </div>

        {/* Cover image */}
        <div className="mt-8 overflow-hidden rounded-[28px]">
          <div className="relative aspect-[21/9]">
            <Image
              src={post.coverImage}
              alt={`Cover image for ${post.title} — Experiences by BLB blog`}
              fill
              className="object-cover"
              sizes="(max-width: 1280px) 100vw, 1280px"
              priority
              unoptimized
            />
          </div>
        </div>

        {/* Article content */}
        <div className="mx-auto mt-12 max-w-3xl">
          <div
            className="
              text-[16px] leading-[1.85] text-primary-light
              [&>h2]:mt-10 [&>h2]:mb-4 [&>h2]:text-[22px] [&>h2]:font-semibold [&>h2]:tracking-tight [&>h2]:text-foreground
              [&>h3]:mt-6 [&>h3]:mb-3 [&>h3]:text-[18px] [&>h3]:font-semibold [&>h3]:text-foreground
              [&>p]:mb-5
              [&>p>a]:font-medium [&>p>a]:text-accent-dark [&>p>a]:underline [&>p>a]:underline-offset-2 [&>p>a]:decoration-accent/30 hover:[&>p>a]:decoration-accent-dark
              [&>p>strong]:font-semibold [&>p>strong]:text-foreground
              [&>ul]:mb-5 [&>ul]:list-disc [&>ul]:pl-6 [&>ul]:space-y-2
              [&>ol]:mb-5 [&>ol]:list-decimal [&>ol]:pl-6 [&>ol]:space-y-2
            "
            dangerouslySetInnerHTML={{ __html: post.content }}
          />

          {/* CTA */}
          <div className="mt-14 glass-card rounded-[28px] p-8 text-center sm:p-10">
            <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
              Plan Your Stay
            </p>
            <h2 className="mt-3 text-[22px] font-semibold tracking-tight text-foreground">
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
