import Link from "next/link";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Home, Building2, Star, BookOpen, Map } from "lucide-react";

export default function NotFound() {
  const links = [
    { href: "/", label: "Home", icon: Home },
    { href: "/nomo-collection", label: "All Properties", icon: Building2 },
    { href: "/nomo-collection", label: "Houston Rentals", icon: Map },
    { href: "/nomo-collection", label: "Niagara Falls Rentals", icon: Map },
    { href: "/reviews", label: "Guest Reviews", icon: Star },
    { href: "/blog", label: "Travel Blog", icon: BookOpen },
  ];

  return (
    <section className="py-24 sm:py-32">
      <Container>
        <div className="mx-auto max-w-lg text-center">
          <p className="text-[64px] font-display font-medium tracking-tight text-hunter/10">404</p>
          <h1 className="mt-2 text-[22px] font-display font-medium tracking-tight text-hunter">
            Page Not Found
          </h1>
          <p className="mt-3 text-[15px] text-muted">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
            Try one of the links below to find what you need.
          </p>
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <Button href="/">Back to Home</Button>
            <Button href="/nomo-collection" variant="outline">
              Browse Properties
            </Button>
          </div>

          <div className="mt-12 grid grid-cols-2 gap-3 sm:grid-cols-3">
            {links.map(({ href, label, icon: Icon }) => (
              <Link
                key={href}
                href={href}
                className="glass-card flex flex-col items-center gap-2 rounded-[4px] p-4 text-center transition-colors duration-200 hover:border-accent/20"
              >
                <Icon className="h-5 w-5 text-accent-dark" />
                <span className="text-[13px] font-medium text-foreground">{label}</span>
              </Link>
            ))}
          </div>
        </div>
      </Container>
    </section>
  );
}
