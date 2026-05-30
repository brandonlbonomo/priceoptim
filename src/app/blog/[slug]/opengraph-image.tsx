import { ImageResponse } from "next/og";
import { getAllPosts, getPostBySlug } from "@/data/blog";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export function generateStaticParams() {
  return getAllPosts().map((p) => ({ slug: p.slug }));
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const post = getPostBySlug(slug);

  if (!post) {
    return new ImageResponse(
      (
        <div style={{ background: "#1d1d1f", width: "100%", height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "white", fontSize: 48 }}>
          Post Not Found
        </div>
      ),
      { ...size }
    );
  }

  return new ImageResponse(
    (
      <div
        style={{
          background: "linear-gradient(135deg, #1d1d1f 0%, #2a2a2e 100%)",
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: "60px 70px",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div
            style={{
              fontSize: 18,
              fontWeight: 600,
              letterSpacing: "0.15em",
              color: "#bf9b30",
            }}
          >
            EXPERIENCES BY BLB
          </div>
          <div
            style={{
              display: "flex",
              fontSize: 14,
              fontWeight: 600,
              letterSpacing: "0.2em",
              color: "rgba(255,255,255,0.3)",
              background: "rgba(255,255,255,0.06)",
              borderRadius: 100,
              padding: "8px 20px",
            }}
          >
            BLOG
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", gap: 10 }}>
            {post.tags.slice(0, 3).map((tag) => (
              <span
                key={tag}
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  letterSpacing: "0.15em",
                  color: "#bf9b30",
                  background: "rgba(191,155,48,0.12)",
                  borderRadius: 100,
                  padding: "6px 16px",
                }}
              >
                {tag.toUpperCase()}
              </span>
            ))}
          </div>
          <div style={{ display: "flex", fontSize: 48, fontWeight: 700, color: "white", lineHeight: 1.2, marginTop: 16 }}>
            {post.title}
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontSize: 16, color: "rgba(255,255,255,0.5)" }}>{post.author}</span>
          <span style={{ fontSize: 16, color: "rgba(255,255,255,0.2)" }}>|</span>
          <span style={{ fontSize: 16, color: "rgba(255,255,255,0.5)" }}>
            {new Date(post.publishedAt).toLocaleDateString("en-US", {
              year: "numeric",
              month: "long",
              day: "numeric",
            })}
          </span>
        </div>
      </div>
    ),
    { ...size }
  );
}
