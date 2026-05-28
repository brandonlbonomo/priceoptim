import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";

export default function NotFound() {
  return (
    <section className="py-20 sm:py-28">
      <Container>
        <div className="glass-card mx-auto max-w-lg rounded-3xl p-12 text-center">
          <p className="text-6xl font-bold text-primary">404</p>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-foreground">
            Page Not Found
          </h1>
          <p className="mt-3 text-muted">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
          </p>
          <div className="mt-8 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
            <Button href="/">Back to Home</Button>
            <Button href="/properties" variant="outline">
              Browse Properties
            </Button>
          </div>
        </div>
      </Container>
    </section>
  );
}
