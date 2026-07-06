import { cn } from "@/lib/utils";

interface LogoProps {
  /** "dark" for ivory backgrounds, "light" for hunter-green backgrounds */
  tone?: "dark" | "light";
  className?: string;
  /** Show the REALTY line and swoosh (full stacked mark) vs. wordmark only */
  showTagline?: boolean;
}

/**
 * BLB Realty stacked wordmark — serif "BLB" over a muted-gold swoosh and a
 * letter-spaced "REALTY". Rendered in markup so it stays crisp and recolors
 * to sit on either ivory (dark tone) or hunter green (light tone).
 */
export function Logo({ tone = "dark", className, showTagline = true }: LogoProps) {
  const mark = tone === "light" ? "text-white" : "text-hunter";
  const tagline = tone === "light" ? "text-white/80" : "text-hunter/70";

  return (
    <span className={cn("inline-flex flex-col items-center leading-none", className)}>
      <span className={cn("font-display font-bold tracking-tight", mark)}>BLB</span>
      {showTagline && (
        <>
          {/* Gold swoosh */}
          <svg
            viewBox="0 0 120 12"
            className="mt-[0.15em] h-[0.34em] w-[1.9em]"
            fill="none"
            aria-hidden="true"
          >
            <path
              d="M2 9 C 30 2, 90 2, 118 9"
              stroke="url(#blb-gold)"
              strokeWidth="2.5"
              strokeLinecap="round"
            />
            <defs>
              <linearGradient id="blb-gold" x1="0" y1="0" x2="120" y2="0" gradientUnits="userSpaceOnUse">
                <stop stopColor="#a9863f" stopOpacity="0.15" />
                <stop offset="0.5" stopColor="#d8b968" />
                <stop offset="1" stopColor="#a9863f" stopOpacity="0.15" />
              </linearGradient>
            </defs>
          </svg>
          <span
            className={cn(
              "font-display font-medium uppercase tracking-[0.42em] pl-[0.42em]",
              tagline,
            )}
            style={{ fontSize: "0.3em" }}
          >
            Realty
          </span>
        </>
      )}
    </span>
  );
}
