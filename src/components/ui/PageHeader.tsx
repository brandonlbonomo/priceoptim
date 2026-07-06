import { Container } from "@/components/ui/Container";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";

interface PageHeaderProps {
  eyebrow: string;
  title: string;
  intro?: string;
  breadcrumbs?: { label: string; href?: string }[];
  /** dark = hunter-green ground, light = ivory ground */
  tone?: "dark" | "light";
}

export function PageHeader({
  eyebrow,
  title,
  intro,
  breadcrumbs,
  tone = "light",
}: PageHeaderProps) {
  if (tone === "dark") {
    return (
      <header className="hero-gradient noise relative overflow-hidden py-20 sm:py-28">
        <Container className="relative z-10">
          {breadcrumbs && (
            <div className="mb-8 [&_*]:!text-white/50 [&_a:hover]:!text-white">
              <Breadcrumbs items={breadcrumbs} />
            </div>
          )}
          <div className="max-w-3xl">
            <p className="text-[12px] font-semibold uppercase tracking-[0.3em] text-gold-light">
              {eyebrow}
            </p>
            <div className="mt-5 ornament" />
            <h1 className="mt-7 font-display text-4xl font-medium leading-[1.1] tracking-tight text-white sm:text-5xl">
              {title}
            </h1>
            {intro && (
              <p className="mt-6 max-w-2xl text-[16px] font-light leading-relaxed text-white/60">
                {intro}
              </p>
            )}
          </div>
        </Container>
      </header>
    );
  }

  return (
    <header className="border-b border-hunter/10 bg-cream py-14 sm:py-20">
      <Container>
        {breadcrumbs && (
          <div className="mb-8">
            <Breadcrumbs items={breadcrumbs} />
          </div>
        )}
        <div className="max-w-3xl">
          <p className="eyebrow">{eyebrow}</p>
          <h1 className="mt-5 font-display text-4xl font-medium leading-[1.1] tracking-tight text-hunter sm:text-5xl">
            {title}
          </h1>
          {intro && (
            <p className="mt-6 max-w-2xl text-[16px] leading-relaxed text-muted">
              {intro}
            </p>
          )}
        </div>
      </Container>
    </header>
  );
}
