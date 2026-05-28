import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { Mail, Tag, Bell } from "lucide-react";

export const metadata: Metadata = {
  title: "Get Exclusive Deals",
  description:
    "Sign up for special rates, last-minute openings, and seasonal promotions from BLB Realty.",
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
        <div className="mx-auto max-w-2xl text-center">
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

        <div className="mx-auto mt-16 grid max-w-3xl gap-8 sm:grid-cols-3">
          {perks.map((perk) => (
            <div key={perk.title} className="text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-primary text-white">
                <perk.icon className="h-5 w-5" />
              </div>
              <h3 className="mt-3 text-sm font-semibold text-foreground">{perk.title}</h3>
              <p className="mt-1 text-sm text-muted">{perk.description}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  );
}
