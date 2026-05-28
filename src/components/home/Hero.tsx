import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";

export function Hero() {
  return (
    <section className="relative bg-primary py-24 sm:py-32 lg:py-40">
      {/* Background pattern */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary-dark via-primary to-primary-light opacity-90" />

      <Container className="relative">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-sm font-semibold uppercase tracking-widest text-accent">
            BLB Realty Vacation Rentals
          </p>
          <h1 className="mt-4 text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
            Book Direct &amp; Save
          </h1>
          <p className="mt-6 text-lg leading-relaxed text-gray-200 sm:text-xl">
            Skip the platform fees. Get the best rates on premium vacation
            rentals when you book directly with BLB Realty.
          </p>
          <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <Button href="/properties" size="lg" variant="secondary">
              Browse Properties
            </Button>
            <Button href="/subscribe" size="lg" variant="outline" className="border-white text-white hover:bg-white hover:text-primary">
              Get Exclusive Deals
            </Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
