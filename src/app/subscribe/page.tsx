import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { Mail, Tag, Bell } from "lucide-react";

export const metadata: Metadata = {
  title: "Get Exclusive Deals",
  description:
    "Sign up for special rates, last-minute openings, and seasonal promotions from Properties By BLB.",
};

const perks = [
  {
    icon: Tag,
    title: "Exclusive Rates",
    description: "Subscribers-only pricing not available anywhere else.",
  },
  {
    icon: Bell,
    title: "Last-Minute Deals",
    description: "Be the first to know about surprise openings and discounts.",
  },
  {
    icon: Mail,
    title: "No Spam",
    description: "Only the good stuff. Unsubscribe anytime with one click.",
  },
];

export default function SubscribePage() {
  return (
    <section className="py-16 sm:py-24">
      <Container>
        <div className="glass-card mx-auto max-w-2xl rounded-3xl px-8 py-12 text-center sm:px-12">
          <h1 className="text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
            Get Exclusive Deals
          </h1>
          <p className="mt-4 text-lg text-muted">
            Join our mailing list and never miss a deal. We send special rates,
            seasonal promotions, and last-minute openings straight to your inbox.
          </p>

          <div className="mx-auto mt-8 max-w-md">
            <EmailForm source="subscribe-page" />
          </div>
        </div>

        <div className="mx-auto mt-14 grid max-w-3xl gap-6 sm:grid-cols-3">
          {perks.map((perk) => (
            <div key={perk.title} className="glass-card group rounded-3xl p-6 text-center transition-all duration-300">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary transition-all duration-300 group-hover:bg-primary group-hover:text-white group-hover:shadow-lg group-hover:shadow-primary/20">
                <perk.icon className="h-6 w-6" />
              </div>
              <h3 className="mt-4 text-sm font-semibold text-foreground">{perk.title}</h3>
              <p className="mt-2 text-sm text-muted">{perk.description}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  );
}
