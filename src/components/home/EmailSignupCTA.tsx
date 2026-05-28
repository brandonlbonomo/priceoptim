import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";

export function EmailSignupCTA() {
  return (
    <section className="bg-primary py-16 sm:py-20">
      <Container>
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Get Exclusive Deals
          </h2>
          <p className="mt-3 text-lg text-gray-200">
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
