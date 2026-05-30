/**
 * Generic shimmer blur placeholder for Next.js Image components.
 * Used with `placeholder="blur"` and `blurDataURL={shimmerBlur}`.
 * Provides a subtle loading state to improve perceived performance and CLS.
 */

const shimmer = (w: number, h: number) => `
<svg width="${w}" height="${h}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="g">
      <stop stop-color="#e5e5e5" offset="20%" />
      <stop stop-color="#f0f0f0" offset="50%" />
      <stop stop-color="#e5e5e5" offset="80%" />
    </linearGradient>
  </defs>
  <rect width="${w}" height="${h}" fill="#e5e5e5" />
  <rect id="r" width="${w}" height="${h}" fill="url(#g)" />
  <animate xlink:href="#r" attributeName="x" from="-${w}" to="${w}" dur="1.5s" repeatCount="indefinite" />
</svg>`;

function toBase64(str: string) {
  return typeof window === "undefined"
    ? Buffer.from(str).toString("base64")
    : window.btoa(str);
}

export const shimmerBlur = `data:image/svg+xml;base64,${toBase64(shimmer(700, 475))}`;
