import { ImageResponse } from "next/og";
import { getPropertyBySlug, getActiveProperties } from "@/data/properties";
import { getAverageRating, getReviewsByProperty } from "@/data/reviews";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export function generateStaticParams() {
  return getActiveProperties().map((p) => ({ slug: p.slug }));
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const property = getPropertyBySlug(slug);

  if (!property) {
    return new ImageResponse(
      (
        <div style={{ background: "#1d1d1f", width: "100%", height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: "white", fontSize: 48 }}>
          Property Not Found
        </div>
      ),
      { ...size }
    );
  }

  const rating = getAverageRating(property.id);
  const reviewCount = getReviewsByProperty(property.id).length;

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
        <div style={{ display: "flex", alignItems: "center" }}>
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
        </div>

        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", fontSize: 16, color: "#bf9b30", letterSpacing: "0.2em" }}>
            {property.location.city}, {property.location.state}
          </div>
          <div style={{ display: "flex", fontSize: 52, fontWeight: 700, color: "white", lineHeight: 1.15, marginTop: 12 }}>
            {property.name}
          </div>
          <div style={{ display: "flex", fontSize: 22, color: "rgba(255,255,255,0.5)", lineHeight: 1.5, marginTop: 8 }}>
            {property.tagline}
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, background: "rgba(255,255,255,0.08)", borderRadius: 100, padding: "10px 24px" }}>
            <span style={{ fontSize: 18, color: "white" }}>{property.details.bedrooms} Bed</span>
            <span style={{ color: "rgba(255,255,255,0.3)", marginLeft: 4, marginRight: 4 }}>|</span>
            <span style={{ fontSize: 18, color: "white" }}>{property.details.bathrooms} Bath</span>
            <span style={{ color: "rgba(255,255,255,0.3)", marginLeft: 4, marginRight: 4 }}>|</span>
            <span style={{ fontSize: 18, color: "white" }}>Up to {property.details.maxGuests} Guests</span>
          </div>
          {reviewCount > 0 && (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 20, fontWeight: 600, color: "white" }}>{rating}</span>
              <span style={{ fontSize: 16, color: "rgba(255,255,255,0.4)" }}>({reviewCount} reviews)</span>
            </div>
          )}
        </div>
      </div>
    ),
    { ...size }
  );
}
