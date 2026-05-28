import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";

export function Hero() {
  return (
    <section className="mesh-gradient relative overflow-hidden py-28 sm:py-36 lg:py-44">
      {/* Decorative glass orbs */}
      <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-accent/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-32 bottom-0 h-80 w-80 rounded-full bg-white/5 blur-3xl" />

      <Container className="relative">
        <div className="mx-auto max-w-3xl text-center">
          <div className="glass-dark mx-auto mb-6 inline-block rounded-full px-5 py-2">
            <p className="text-sm font-semibold tracking-widest text-accent">
              Properties By BLB
            </p>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
            Book Direct &amp; Save
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-gray-300 sm:text-xl">
            Skip the platform fees. Get the best rates on premium vacation
            rentals when you book directly with Properties By BLB.
          </p>
          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <Button href="/properties" size="lg" variant="secondary">
              Browse Properties
            </Button>
            <Button
              href="/subscribe"
              size="lg"
              variant="outline"
              className="border-white/20 bg-white/10 text-white backdrop-blur-sm hover:bg-white hover:text-primary"
            >
              Get Exclusive Deals
            </Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
