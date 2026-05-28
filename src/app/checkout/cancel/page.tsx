import type { Metadata } from "next";
import { XCircle } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";

export const metadata: Metadata = {
  title: "Booking Cancelled",
};

export default function CheckoutCancelPage() {
  return (
    <section className="py-20 sm:py-28">
      <Container>
        <div className="mx-auto max-w-lg text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-red-100">
            <XCircle className="h-8 w-8 text-red-600" />
          </div>
          <h1 className="mt-6 text-3xl font-bold tracking-tight text-foreground">
            Booking Cancelled
          </h1>
          <p className="mt-4 text-lg text-muted">
            Your booking wasn&apos;t completed. No charges were made. Feel free
            to try again or browse other properties.
          </p>
          <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Button href="/properties">Browse Properties</Button>
            <Button href="/" variant="outline">
              Back to Home
            </Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
