import Link from "next/link";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";
import { Logo } from "@/components/layout/Logo";

const firmLinks = [
  { href: "/portfolio", label: "Portfolio" },
  { href: "/invest", label: "Invest" },
  { href: "/about", label: "About" },
  { href: "/contact", label: "Contact" },
];

const stayLinks = [
  { href: "/book", label: "Book a Stay" },
  { href: "/properties", label: "All Properties" },
  { href: "/properties/houston", label: "Houston, TX" },
  { href: "/properties/niagara-falls", label: "Niagara Falls, NY" },
  { href: "/reviews", label: "Guest Reviews" },
];

export function Footer() {
  return (
    <footer className="mt-auto bg-hunter-dark text-white">
      <Container className="py-16">
        <div className="grid gap-12 md:grid-cols-4">
          {/* Brand + NAP */}
          <div>
            <Link href="/" aria-label="BLB Realty — home" className="inline-block text-[30px]">
              <Logo tone="light" />
            </Link>
            <p className="mt-6 text-[13px] leading-relaxed text-white/45">
              A real estate investment firm acquiring, building, and
              redeveloping residential property — and holding a growing rental
              portfolio across Houston and Niagara Falls.
            </p>
            <div className="mt-6 space-y-1 text-[12px] text-white/35">
              <p>BLB REALTY LLC</p>
              <p>Houston, TX &amp; Niagara Falls, NY</p>
              <p>
                <a href="tel:+15166506653" className="transition-colors duration-200 hover:text-white/70">
                  (516) 650-6653
                </a>
              </p>
              <p>
                <a href="mailto:blbrealtyllc@gmail.com" className="transition-colors duration-200 hover:text-white/70">
                  blbrealtyllc@gmail.com
                </a>
              </p>
            </div>
          </div>

          {/* The Firm */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gold-light/80">
              The Firm
            </h4>
            <ul className="mt-6 space-y-3">
              {firmLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-[13px] text-white/45 transition-colors duration-300 hover:text-white"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Book a Stay */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gold-light/80">
              Book a Stay
            </h4>
            <ul className="mt-6 space-y-3">
              {stayLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-[13px] text-white/45 transition-colors duration-300 hover:text-white"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Email signup */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gold-light/80">
              Stay in Touch
            </h4>
            <p className="mt-6 mb-5 text-[13px] text-white/45">
              Firm updates and direct-booking rates, delivered on occasion.
            </p>
            <EmailForm source="footer" compact />
          </div>
        </div>

        <div className="mt-14 border-t border-white/[0.08] pt-8 text-center text-[12px] text-white/30">
          <p>&copy; {new Date().getFullYear()} BLB REALTY LLC. All rights reserved.</p>
          <p className="mt-2">
            <Link href="/privacy" className="transition-colors duration-200 hover:text-white/60">Privacy Policy</Link>
            {" "}&middot;{" "}
            <Link href="/terms" className="transition-colors duration-200 hover:text-white/60">Terms of Service</Link>
          </p>
        </div>
      </Container>
    </footer>
  );
}
