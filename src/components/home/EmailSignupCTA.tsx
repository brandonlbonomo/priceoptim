import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

export function EmailSignupCTA() {
  return (
    <section className="hero-gradient noise relative overflow-hidden py-20 sm:py-28">
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-[400px] w-[400px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/[0.06] blur-[100px]" />
      <Container className="relative z-10">
        <ScrollReveal variant="scale">
          <div className="mx-auto max-w-xl text-center">
            <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
              Insider Access
            </p>
            <h2 className="mt-4 font-display text-3xl font-medium tracking-tight text-white sm:text-4xl">
              Get Exclusive Deals
            </h2>
            <p className="mt-4 text-[15px] font-light leading-relaxed text-white/50">
              Special rates, last-minute openings, and seasonal promotions
              delivered to your inbox.
            </p>
            <div className="mt-10">
              <EmailForm source="homepage-cta" compact />
            </div>
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
