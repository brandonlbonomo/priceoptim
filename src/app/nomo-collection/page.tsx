import type { Metadata } from "next";
import { Sparkles, KeyRound, Palette, Heart, ArrowUpRight } from "lucide-react";
import { Container } from "@/components/ui/Container";

/**
 * The Nomo Collection — branded interstitial / launchpad.
 *
 * Direct booking has moved off this site to its own home:
 *   https://thenomocollection.com
 *
 * This page is the on-site pitch + gateway. It is intentionally built with
 * neutral placeholder branding (styled wordmark, existing design tokens).
 * When the real logo + design land, swap:
 *   1. The <WordmarkPlaceholder /> block for the <Image src="/nomo-collection-logo.png" ... />
 *   2. Colors / copy for the final BOHO-chic brand direction.
 */

const EXTERNAL_URL = "https://thenomocollection.com";

export const metadata: Metadata = {
  title: "The Nomo Collection — Book Direct",
  description:
    "The Nomo Collection — elevated, BOHO-chic short-term stays. Book directly with us for the best rate, thoughtful design, and personal hospitality.",
  alternates: { canonical: "/nomo-collection" },
  openGraph: {
    title: "The Nomo Collection — Book Direct",
    description:
      "Elevated, BOHO-chic short-term stays. Book directly for the best rate and personal hospitality.",
    url: "/nomo-collection",
  },
};

const pillars = [
  {
    icon: Sparkles,
    title: "Elevated stays",
    body: "Homes chosen and finished to a higher standard — spaces that feel considered from the doorway in.",
  },
  {
    icon: Palette,
    title: "BOHO-chic design",
    body: "Warm textures, natural light, and a collected, artful sensibility in every room.",
  },
  {
    icon: KeyRound,
    title: "Book direct, save",
    body: "No platform service fees. The best available rate, straight from us to you.",
  },
  {
    icon: Heart,
    title: "Personal hospitality",
    body: "Real people, quick answers, and the little touches that turn a booking into a stay.",
  },
];

export default function NomoCollectionPage() {
  return (
    <>
      {/* Hero */}
      <section className="hero-gradient noise relative overflow-hidden">
        <Container className="relative z-10">
          <div className="mx-auto max-w-3xl py-24 text-center sm:py-32">
            <p className="text-[12px] font-semibold uppercase tracking-[0.3em] text-gold-light">
              Book Direct
            </p>

            {/* ── LOGO GOES HERE ──────────────────────────────
                Replace this wordmark block with the real logo, e.g.:
                <Image src="/nomo-collection-logo.png" alt="The Nomo Collection"
                       width={880} height={280} priority className="mx-auto h-24 w-auto" />
            */}
            <div className="mt-7">
              <h1 className="font-display text-5xl font-medium leading-[1.05] tracking-tight text-white sm:text-6xl">
                The Nomo
                <br />
                Collection
              </h1>
              <div className="mx-auto mt-6 h-px w-24 bg-gold-light/50" />
            </div>

            <p className="mx-auto mt-8 max-w-xl text-[17px] font-light leading-relaxed text-white/70">
              A curated collection of elevated, BOHO-chic stays. Our vacation
              rentals now live on their own — book directly for the best rate,
              thoughtful design, and hospitality that actually shows up.
            </p>

            <div className="mt-10 flex flex-col items-center gap-4">
              <a
                href={EXTERNAL_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="group inline-flex items-center justify-center gap-2 rounded-[2px] bg-gold px-10 py-4 text-[12px] font-semibold uppercase tracking-[0.16em] text-hunter-dark transition-[transform,background-color] duration-500 ease-[cubic-bezier(0.23,1,0.32,1)] hover:bg-gold-light active:scale-[0.98] focus:outline-none focus-visible:ring-2 focus-visible:ring-gold/50 focus-visible:ring-offset-2 focus-visible:ring-offset-hunter-dark"
              >
                Explore &amp; book at thenomocollection.com
                <ArrowUpRight className="h-4 w-4 transition-transform duration-500 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
              </a>
              <span className="text-[11px] uppercase tracking-[0.2em] text-white/40">
                Opens thenomocollection.com
              </span>
            </div>
          </div>
        </Container>
      </section>

      {/* Pitch pillars */}
      <section className="bg-cream py-20 sm:py-24">
        <Container>
          <div className="mx-auto max-w-2xl text-center">
            <p className="eyebrow">Why The Nomo Collection</p>
            <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
              Elevated stays, booked direct
            </h2>
            <p className="mx-auto mt-5 text-[16px] leading-relaxed text-muted">
              The same homes and hosts you trust — now with their own home online.
              Skip the platform fees and book straight with us.
            </p>
          </div>

          <div className="mx-auto mt-14 grid max-w-5xl gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {pillars.map((p) => (
              <div key={p.title} className="glass-card rounded-[3px] p-7">
                <div className="flex h-11 w-11 items-center justify-center rounded-full bg-hunter/[0.06]">
                  <p.icon className="h-5 w-5 text-gold-dark" strokeWidth={1.6} />
                </div>
                <h3 className="mt-5 font-display text-lg font-medium text-hunter">
                  {p.title}
                </h3>
                <p className="mt-2 text-[14px] leading-relaxed text-muted">{p.body}</p>
              </div>
            ))}
          </div>

          <div className="mt-16 text-center">
            <a
              href={EXTERNAL_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="group inline-flex items-center justify-center gap-2 rounded-[2px] bg-hunter px-9 py-3.5 text-[12px] font-semibold uppercase tracking-[0.16em] text-ivory transition-[transform,background-color] duration-500 ease-[cubic-bezier(0.23,1,0.32,1)] hover:bg-hunter-light active:scale-[0.98] focus:outline-none focus-visible:ring-2 focus-visible:ring-gold/40 focus-visible:ring-offset-2"
            >
              Browse the collection
              <ArrowUpRight className="h-4 w-4 transition-transform duration-500 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </a>
          </div>
        </Container>
      </section>
    </>
  );
}
