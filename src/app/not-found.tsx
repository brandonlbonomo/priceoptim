import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";

export default function NotFound() {
  return (
    <section className="py-24 sm:py-32">
      <Container>
        <div className="glass-card mx-auto max-w-md rounded-[32px] p-14 text-center">
          <p className="text-[64px] font-semibold tracking-tight text-foreground/10">404</p>
          <h1 className="mt-2 text-[22px] font-semibold tracking-tight text-foreground">
            Page Not Found
          </h1>
          <p className="mt-3 text-[15px] text-muted">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
          </p>
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
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
