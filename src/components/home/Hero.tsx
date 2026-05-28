import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";

export function Hero() {
  return (
    <section className="hero-gradient noise relative overflow-hidden py-32 sm:py-40 lg:py-52">
      {/* Ambient light effects */}
      <div className="pointer-events-none absolute left-1/2 top-0 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-accent/[0.07] blur-[120px]" />
      <div className="pointer-events-none absolute -left-40 bottom-0 h-96 w-96 rounded-full bg-blue-500/[0.04] blur-[100px]" />
      <div className="pointer-events-none absolute -right-40 top-20 h-80 w-80 rounded-full bg-purple-500/[0.03] blur-[100px]" />

      <Container className="relative z-10">
        <div className="mx-auto max-w-4xl text-center">
          <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
            Experiences by BLB
          </p>
          <h1 className="mt-6 text-5xl font-semibold tracking-tight text-white sm:text-6xl lg:text-7xl">
            Book Direct.
            <br />
            <span className="text-gradient">Save More.</span>
          </h1>
          <p className="mx-auto mt-8 max-w-xl text-[17px] font-light leading-relaxed text-white/60">
            Premium vacation rentals without the platform markup.
            Book directly for the best rates, every time.
          </p>
          <div className="mt-12 flex flex-col items-center justify-center gap-4 sm:flex-row">
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
