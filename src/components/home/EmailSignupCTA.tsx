import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";

export function EmailSignupCTA() {
  return (
    <section className="mesh-gradient relative overflow-hidden py-16 sm:py-24">
      <div className="pointer-events-none absolute -right-20 top-10 h-64 w-64 rounded-full bg-accent/10 blur-3xl" />
      <Container>
        <div className="glass-dark mx-auto max-w-2xl rounded-3xl px-8 py-12 text-center sm:px-12">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Get Exclusive Deals
          </h2>
          <p className="mt-3 text-lg text-gray-300">
            Join our mailing list for special rates, last-minute openings, and
            seasonal promotions.
          </p>
          <div className="mt-8">
            <EmailForm source="homepage-cta" compact />
          </div>
        </div>
      </Container>
    </section>
  );
}
