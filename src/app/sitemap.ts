import type { MetadataRoute } from "next";
import { getAllPosts } from "@/data/blog";

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || "https://byblb.com";
  const posts = getAllPosts();

  const blogPages = posts.map((post) => ({
    url: `${baseUrl}/blog/${post.slug}`,
    lastModified: new Date(post.publishedAt),
    changeFrequency: "monthly" as const,
    priority: 0.7,
  }));

  const now = new Date();
  const staticPages: MetadataRoute.Sitemap = [
    { url: baseUrl, lastModified: now, changeFrequency: "weekly", priority: 1 },
    { url: `${baseUrl}/portfolio`, lastModified: now, changeFrequency: "weekly", priority: 0.9 },
    { url: `${baseUrl}/invest`, lastModified: now, changeFrequency: "monthly", priority: 0.9 },
    { url: `${baseUrl}/nomo-collection`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${baseUrl}/reviews`, lastModified: now, changeFrequency: "weekly", priority: 0.8 },
    { url: `${baseUrl}/blog`, lastModified: now, changeFrequency: "weekly", priority: 0.8 },
    { url: `${baseUrl}/guides`, lastModified: now, changeFrequency: "weekly", priority: 0.7 },
    { url: `${baseUrl}/things-to-do/houston`, lastModified: now, changeFrequency: "monthly", priority: 0.7 },
    { url: `${baseUrl}/things-to-do/niagara-falls`, lastModified: now, changeFrequency: "monthly", priority: 0.7 },
    { url: `${baseUrl}/amenities`, lastModified: now, changeFrequency: "monthly", priority: 0.5 },
    { url: `${baseUrl}/subscribe`, lastModified: now, changeFrequency: "monthly", priority: 0.5 },
    { url: `${baseUrl}/contact`, lastModified: now, changeFrequency: "monthly", priority: 0.6 },
    { url: `${baseUrl}/about`, lastModified: now, changeFrequency: "monthly", priority: 0.6 },
    { url: `${baseUrl}/privacy`, lastModified: now, changeFrequency: "yearly", priority: 0.3 },
    { url: `${baseUrl}/terms`, lastModified: now, changeFrequency: "yearly", priority: 0.3 },
  ];

  return [...staticPages, ...blogPages];
}
