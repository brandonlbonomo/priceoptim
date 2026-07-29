import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

export function BookingSection() {
  return (
    <section className="border-t border-hunter/10 bg-cream py-20 sm:py-28">
      <Container>
        <ScrollReveal>
          <div className="mx-auto max-w-3xl text-center">
            <p className="eyebrow">The Nomo Collection · Book Direct</p>
            <h2 className="mt-5 font-display text-3xl font-medium tracking-tight text-hunter sm:text-4xl">
              Looking for a place to stay?
            </h2>
            <p className="mx-auto mt-5 max-w-2xl text-[16px] leading-relaxed text-muted">
              Our short-term rentals in Houston and Niagara Falls now live under
              The Nomo Collection — a curated set of elevated, BOHO-chic stays you
              can book directly, with no platform fees.
            </p>
          </div>
        </ScrollReveal>

        <ScrollReveal delay={200}>
          <div className="mt-12 flex justify-center">
            <Button href="/nomo-collection" size="lg">
              Explore The Nomo Collection
            </Button>
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
