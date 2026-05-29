"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface ScrollRevealProps {
  children: ReactNode;
  className?: string;
  /** Animation variant */
  variant?: "fade-up" | "fade-in" | "scale";
  /** Delay in ms before animation starts after entering viewport */
  delay?: number;
  /** Stagger children animations by this many ms each */
  stagger?: number;
  /** IntersectionObserver threshold (0-1) */
  threshold?: number;
}

export function ScrollReveal({
  children,
  className,
  variant = "fade-up",
  delay = 0,
  stagger = 0,
  threshold = 0.15,
}: ScrollRevealProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    // Apply stagger delays to direct children
    if (stagger > 0) {
      const children = el.children;
      for (let i = 0; i < children.length; i++) {
        (children[i] as HTMLElement).style.transitionDelay = `${delay + i * stagger}ms`;
      }
    } else if (delay > 0) {
      el.style.transitionDelay = `${delay}ms`;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          el.classList.add("revealed");
          observer.unobserve(el);
        }
      },
      { threshold, rootMargin: "0px 0px -40px 0px" },
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [delay, stagger, threshold]);

  return (
    <div ref={ref} className={cn(`reveal reveal-${variant}`, className)}>
      {children}
    </div>
  );
}
