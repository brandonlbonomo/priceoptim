import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

export function EmailSignupCTA() {
  return (
    <section className="hero-gradient noise relative overflow-hidden py-16 sm:py-20">
      <Container className="relative z-10">
        <ScrollReveal variant="scale">
          <div className="mx-auto max-w-xl text-center">
            <p className="text-[12px] font-semibold uppercase tracking-[0.3em] text-gold-light">
              Stay in Touch
            </p>
            <div className="mx-auto mt-4 ornament" />
            <h2 className="mt-6 font-display text-3xl font-medium tracking-tight text-white sm:text-4xl">
              From the firm
            </h2>
            <p className="mt-4 text-[15px] font-light leading-relaxed text-white/55">
              Occasional notes on the portfolio, new acquisitions, and
              direct-booking availability — sent sparingly.
            </p>
            <div className="mt-8">
              <EmailForm source="homepage-cta" compact />
            </div>
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
