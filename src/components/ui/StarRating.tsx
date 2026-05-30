import { Star } from "lucide-react";

interface StarRatingProps {
  rating: number;
  reviewCount: number;
  size?: "sm" | "md";
}

export function StarRating({ rating, reviewCount, size = "sm" }: StarRatingProps) {
  if (reviewCount === 0) return null;

  const starSize = size === "sm" ? "h-3 w-3" : "h-4 w-4";
  const textSize = size === "sm" ? "text-[12px]" : "text-[14px]";
  const gap = size === "sm" ? "gap-0.5" : "gap-1";

  return (
    <div className={`flex items-center gap-2 ${textSize}`}>
      <div className={`flex items-center ${gap}`}>
        {Array.from({ length: 5 }).map((_, i) => (
          <Star
            key={i}
            className={`${starSize} ${
              i < Math.round(rating)
                ? "fill-accent text-accent"
                : "fill-black/[0.06] text-black/[0.06]"
            }`}
          />
        ))}
      </div>
      <span className="font-semibold text-foreground">{rating}</span>
      <span className="text-muted">({reviewCount} {reviewCount === 1 ? "review" : "reviews"})</span>
    </div>
  );
}
