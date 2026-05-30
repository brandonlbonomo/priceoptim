import { DollarSign, MessageCircle, CalendarCheck } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

const benefits = [
  {
    icon: DollarSign,
    title: "Best Price Guarantee",
    description:
      "No platform fees means lower prices for you. Our direct rates are always the best available.",
  },
  {
    icon: MessageCircle,
    title: "Direct Communication",
    description:
      "Talk directly with your host before, during, and after your stay. No middleman, no delays.",
  },
  {
    icon: CalendarCheck,
    title: "Flexible Cancellation",
    description:
      "We offer flexible cancellation policies because plans change. Book with confidence.",
  },
];

export function WhyBookDirect() {
  return (
    <section className="py-16 sm:py-20">
      <Container>
        <ScrollReveal>
          <div className="text-center">
            <p className="text-[13px] font-semibold uppercase tracking-[0.3em] text-accent-dark">
              Why Book Direct
            </p>
            <h2 className="mt-4 font-display text-2xl font-medium tracking-tight text-foreground sm:text-3xl">
              Skip the platforms.
              <br className="hidden sm:block" />
              <span className="text-muted"> Keep more in your pocket.</span>
            </h2>
          </div>
        </ScrollReveal>

        <ScrollReveal variant="fade-up" delay={100} stagger={150}>
          <div className="mt-10 grid gap-5 sm:grid-cols-3">
            {benefits.map((benefit) => (
              <div
                key={benefit.title}
                className="glass-card group rounded-[20px] p-7 text-center"
              >
                <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full bg-foreground/[0.04] transition-all duration-500 group-hover:bg-accent/10 group-hover:scale-110">
                  <benefit.icon className="h-5 w-5 text-foreground/70 transition-colors duration-500 group-hover:text-accent-dark" />
                </div>
                <h3 className="mt-5 font-display text-[16px] font-medium text-foreground">
                  {benefit.title}
                </h3>
                <p className="mt-2 text-[14px] leading-relaxed text-muted">
                  {benefit.description}
                </p>
              </div>
            ))}
          </div>
        </ScrollReveal>
      </Container>
    </section>
  );
}
