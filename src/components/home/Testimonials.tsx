"use client";

import { useState, useEffect } from "react";
import { Star, Quote, ChevronLeft, ChevronRight } from "lucide-react";

interface Testimonial {
  guestName: string;
  rating: number;
  text: string;
  propertyName: string;
  location: string;
}

interface TestimonialsProps {
  testimonials: Testimonial[];
}

export function Testimonials({ testimonials }: TestimonialsProps) {
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrent((prev) => (prev + 1) % testimonials.length);
    }, 6000);
    return () => clearInterval(timer);
  }, [testimonials.length]);

  const goTo = (index: number) => {
    setCurrent(index);
  };

  const prev = () => {
    setCurrent((c) => (c - 1 + testimonials.length) % testimonials.length);
  };

  const next = () => {
    setCurrent((c) => (c + 1) % testimonials.length);
  };

  const testimonial = testimonials[current];

  return (
    <div className="relative mx-auto max-w-3xl">
      {/* Main testimonial */}
      <div className="glass-card rounded-[32px] px-8 py-10 text-center sm:px-12 sm:py-14">
        <Quote className="mx-auto h-8 w-8 text-accent/30" />
        <p className="mt-6 text-[17px] leading-relaxed text-foreground sm:text-[19px]">
          &ldquo;{testimonial.text}&rdquo;
        </p>
        <div className="mt-6 flex items-center justify-center gap-1">
          {Array.from({ length: testimonial.rating }).map((_, i) => (
            <Star key={i} className="h-4 w-4 fill-accent text-accent" />
          ))}
        </div>
        <p className="mt-4 text-[15px] font-semibold text-foreground">
          {testimonial.guestName}
        </p>
        <p className="mt-1 text-[13px] text-muted">
          {testimonial.propertyName} &middot; {testimonial.location}
        </p>
      </div>

      {/* Navigation */}
      <div className="mt-6 flex items-center justify-center gap-4">
        <button
          onClick={prev}
          className="flex h-9 w-9 items-center justify-center rounded-full border border-black/[0.06] bg-white text-muted transition-colors duration-200 hover:border-accent hover:text-accent-dark"
          aria-label="Previous review"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <div className="flex items-center gap-2">
          {testimonials.map((_, i) => (
            <button
              key={i}
              onClick={() => goTo(i)}
              className={`h-2 rounded-full transition-all duration-300 ${
                i === current
                  ? "w-6 bg-accent"
                  : "w-2 bg-black/[0.08] hover:bg-black/[0.15]"
              }`}
              aria-label={`Go to review ${i + 1}`}
            />
          ))}
        </div>
        <button
          onClick={next}
          className="flex h-9 w-9 items-center justify-center rounded-full border border-black/[0.06] bg-white text-muted transition-colors duration-200 hover:border-accent hover:text-accent-dark"
          aria-label="Next review"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
