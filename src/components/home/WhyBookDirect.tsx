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
    <section className="bg-muted-light py-16 sm:py-20">
      <Container>
        <SectionHeading
          title="Why Book Direct?"
          subtitle="Three great reasons to skip the big platforms"
        />

        <div className="mt-12 grid gap-8 sm:grid-cols-3">
          {benefits.map((benefit) => (
            <div key={benefit.title} className="text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-primary text-white">
                <benefit.icon className="h-6 w-6" />
              </div>
              <h3 className="mt-4 text-lg font-semibold text-foreground">
                {benefit.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">
                {benefit.description}
              </p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  );
}
