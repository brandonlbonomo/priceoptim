import type { Metadata } from "next";
import { CheckCircle } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";

export const metadata: Metadata = {
  title: "Booking Confirmed",
};

export default function CheckoutSuccessPage() {
  return (
    <section className="py-20 sm:py-28">
      <Container>
        <div className="mx-auto max-w-lg text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-green-100">
            <CheckCircle className="h-8 w-8 text-green-600" />
          </div>
          <h1 className="mt-6 text-3xl font-bold tracking-tight text-foreground">
            Booking Confirmed!
          </h1>
          <p className="mt-4 text-lg text-muted">
            Thank you for your booking. You&apos;ll receive a confirmation email
            shortly with all the details for your stay.
          </p>
          <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Button href="/properties">Browse More Properties</Button>
            <Button href="/" variant="outline">
              Back to Home
            </Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
