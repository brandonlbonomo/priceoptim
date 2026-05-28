import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { Mail, Tag, Bell } from "lucide-react";

export const metadata: Metadata = {
  title: "Get Exclusive Deals",
  description:
    "Sign up for special rates, last-minute openings, and seasonal promotions from Experiences by BLB.",
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
    <section className="py-20 sm:py-28">
      <Container>
        <div className="glass-card mx-auto max-w-2xl rounded-[32px] px-8 py-14 text-center sm:px-14">
          <p className="text-gradient text-[13px] font-semibold uppercase tracking-[0.3em]">
            Insider Access
          </p>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
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
            <div key={perk.title} className="glass-card group rounded-[28px] p-8 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-foreground/[0.04] transition-all duration-500 group-hover:bg-accent/10 group-hover:scale-110">
                <perk.icon className="h-6 w-6 text-foreground/70 transition-colors duration-500 group-hover:text-accent-dark" />
              </div>
              <h3 className="mt-5 text-[15px] font-semibold text-foreground">{perk.title}</h3>
              <p className="mt-2 text-[13px] text-muted">{perk.description}</p>
            </div>
          ))}
        </div>
      </Container>
    </section>
  );
}
