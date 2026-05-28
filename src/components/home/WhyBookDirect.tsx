import { DollarSign, MessageCircle, CalendarCheck } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";

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
    <section className="py-16 sm:py-24">
      <Container>
        <SectionHeading
          title="Why Book Direct?"
          subtitle="Three great reasons to skip the big platforms"
        />

        <div className="mt-14 grid gap-6 sm:grid-cols-3">
          {benefits.map((benefit) => (
            <div
              key={benefit.title}
              className="glass-card group rounded-3xl p-8 text-center transition-all duration-300"
            >
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary transition-all duration-300 group-hover:bg-primary group-hover:text-white group-hover:shadow-lg group-hover:shadow-primary/20">
                <benefit.icon className="h-7 w-7" />
              </div>
              <h3 className="mt-5 text-lg font-semibold text-foreground">
                {benefit.title}
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-muted">
                {benefit.description}
              </p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  );
}
