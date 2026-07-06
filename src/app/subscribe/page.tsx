import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { Mail, Tag, Bell } from "lucide-react";

export const metadata: Metadata = {
  title: "Get Exclusive Deals",
  alternates: { canonical: "/subscribe" },
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
    <section className="py-14 sm:py-20">
      <Container>
        <div className="glass-card mx-auto max-w-2xl rounded-[4px] px-8 py-10 text-center sm:px-10">
          <p className="eyebrow">
            Insider Access
          </p>
          <h1 className="mt-4 text-2xl font-display font-medium tracking-tight text-hunter sm:text-3xl">
            Get Exclusive Deals
          </h1>
          <p className="mt-4 text-[15px] leading-relaxed text-muted">
            Join our mailing list and never miss a deal. We send special rates,
            seasonal promotions, and last-minute openings straight to your inbox.
          </p>

          <div className="mx-auto mt-10 max-w-md">
            <EmailForm source="subscribe-page" />
          </div>
        </div>

        <div className="mx-auto mt-14 grid max-w-3xl gap-5 sm:grid-cols-3">
          {perks.map((perk) => (
            <div key={perk.title} className="glass-card group rounded-[4px] p-8 text-center">
              <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full bg-foreground/[0.04] transition-all duration-500 group-hover:bg-accent/10 group-hover:scale-110">
                <perk.icon className="h-5 w-5 text-foreground/70 transition-colors duration-500 group-hover:text-accent-dark" />
              </div>
              <h3 className="mt-5 text-[15px] font-display font-medium text-hunter">{perk.title}</h3>
              <p className="mt-2 text-[13px] text-muted">{perk.description}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  );
}
