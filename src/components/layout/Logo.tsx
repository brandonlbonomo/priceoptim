import { cn } from "@/lib/utils";

interface LogoProps {
  /** "dark" for ivory backgrounds, "light" for navy backgrounds */
  tone?: "dark" | "light";
  className?: string;
  /** Show the "CAPITAL GROUP" line (full stacked mark) vs. wordmark only */
  showTagline?: boolean;
}

/**
 * Bonomo Capital Group stacked wordmark — serif "BONOMO" over a gold rule and a
 * letter-spaced "CAPITAL GROUP". Rendered in markup so it stays crisp and
 * recolors to sit on either ivory (dark tone) or navy (light tone).
 */
export function Logo({ tone = "dark", className, showTagline = true }: LogoProps) {
  const mark = tone === "light" ? "text-white" : "text-hunter";
  const tagline = tone === "light" ? "text-white/75" : "text-gold-dark";
  const rule = tone === "light" ? "bg-white/40" : "bg-gold/50";

  return (
    <span className={cn("inline-flex flex-col items-center leading-none", className)}>
      <span
        className={cn("font-display font-semibold uppercase", mark)}
        style={{ letterSpacing: "0.06em" }}
      >
        Bonomo
      </span>
      {showTagline && (
        <span className="mt-[0.32em] flex items-center gap-[0.5em]">
          <span className={cn("h-px w-[0.8em]", rule)} aria-hidden="true" />
          <span
            className={cn("font-display uppercase", tagline)}
            style={{ fontSize: "0.26em", letterSpacing: "0.34em" }}
          >
            Capital Group
          </span>
          <span className={cn("h-px w-[0.8em]", rule)} aria-hidden="true" />
        </span>
      )}
    </span>
  );
}
