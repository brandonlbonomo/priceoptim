"use client";

import type { FAQItem } from "@/lib/faq";

interface FAQSectionProps {
  faqs: FAQItem[];
}

export function FAQSection({ faqs }: FAQSectionProps) {
  return (
    <div className="space-y-3">
      {faqs.map((faq, index) => (
        <details
          key={index}
          className="glass-card group rounded-[4px] overflow-hidden"
        >
          <summary className="cursor-pointer select-none px-6 py-5 font-display text-[15px] font-medium text-hunter list-none flex items-center justify-between gap-4">
            {faq.question}
            <span className="text-gold transition-transform duration-300 group-open:rotate-45 text-[20px] leading-none shrink-0">
              +
            </span>
          </summary>
          <div className="px-6 pb-5 text-[14px] leading-relaxed text-muted">
            {faq.answer}
          </div>
        </details>
      ))}
    </div>
  );
}
