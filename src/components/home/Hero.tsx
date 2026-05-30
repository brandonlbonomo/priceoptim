import { Star } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";
import { getAllReviews } from "@/data/reviews";

export function Hero() {
  const reviews = getAllReviews();
  const totalReviews = reviews.length;
  const avgRating =
    Math.round(
      (reviews.reduce((sum, r) => sum + r.rating, 0) / totalReviews) * 100
    ) / 100;

  return (
    <section className="hero-gradient noise relative overflow-hidden py-36 sm:py-44 lg:py-56">
      {/* Ambient light effects */}
      <div className="pointer-events-none absolute left-1/2 top-0 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-accent/[0.09] blur-[120px]" />
      <div className="pointer-events-none absolute -left-40 bottom-0 h-96 w-96 rounded-full bg-blue-500/[0.04] blur-[100px]" />
      <div className="pointer-events-none absolute -right-40 top-20 h-80 w-80 rounded-full bg-purple-500/[0.03] blur-[100px]" />

      <Container className="relative z-10">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
            Experiences by BLB
          </p>
          <div className="mt-4 ornament" />
          <h1 className="mt-8 font-display text-5xl font-medium tracking-tight text-white sm:text-6xl lg:text-8xl">
            Book Direct.
            <br />
            <span className="text-gradient">Save More.</span>
          </h1>
          <p className="mx-auto mt-8 max-w-xl text-[17px] font-normal leading-relaxed text-white/50">
            Premium vacation rentals without the platform markup.
            Book directly for the best rates, every time.
          </p>

          {/* Review badge */}
          <div className="mx-auto mt-8 inline-flex items-center gap-2.5 rounded-full border border-white/[0.08] bg-white/[0.04] px-5 py-2.5 backdrop-blur-xl">
            <div className="flex items-center gap-0.5">
              {Array.from({ length: 5 }).map((_, i) => (
                <Star key={i} className="h-3.5 w-3.5 fill-accent text-accent" />
              ))}
            </div>
            <span className="text-[14px] font-semibold text-white">{avgRating}</span>
            <span className="text-[13px] text-white/40">from {totalReviews} reviews</span>
          </div>

          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <Button href="/properties" size="lg" variant="secondary">
              Browse Properties
            </Button>
            <Button
              href="/subscribe"
              size="lg"
              variant="outline"
              className="border-white/[0.12] bg-white/[0.06] text-white backdrop-blur-xl hover:bg-white/[0.12] hover:text-white"
            >
              Get Exclusive Deals
            </Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
