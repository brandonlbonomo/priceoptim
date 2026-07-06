import { Container } from "@/components/ui/Container";

export interface LandingFAQItem {
  question: string;
  answer: string;
}

interface LandingFAQProps {
  faqs: LandingFAQItem[];
  heading?: string;
}

/**
 * Renders a visual FAQ accordion (pure <details>, no JS) AND emits
 * matching FAQPage JSON-LD so the visual content and structured data
 * can never drift apart. Drop-in for landing/hub pages.
 */
export function LandingFAQ({
  faqs,
  heading = "Frequently asked questions",
}: LandingFAQProps) {
  if (faqs.length === 0) return null;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: faqs.map((faq) => ({
      "@type": "Question",
      name: faq.question,
      acceptedAnswer: {
        "@type": "Answer",
        text: faq.answer,
      },
    })),
  };

  return (
    <section className="mt-20">
      <Container>
        <h2 className="text-center font-display text-2xl font-medium tracking-tight text-hunter sm:text-3xl">
          {heading}
        </h2>
        <div className="mx-auto mt-8 max-w-3xl space-y-3">
          {faqs.map((faq, index) => (
            <details
              key={index}
              className="glass-card group overflow-hidden rounded-[4px]"
            >
              <summary className="flex cursor-pointer select-none items-center justify-between gap-4 px-6 py-5 font-display text-[15px] font-medium text-hunter list-none">
                {faq.question}
                <span className="shrink-0 text-[20px] leading-none text-gold transition-transform duration-300 group-open:rotate-45">
                  +
                </span>
              </summary>
              <div className="px-6 pb-5 text-[14px] leading-relaxed text-muted">
                {faq.answer}
              </div>
            </details>
          ))}
        </div>
      </Container>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
    </section>
  );
}
