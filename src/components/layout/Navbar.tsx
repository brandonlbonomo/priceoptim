"use client";

import { useState } from "react";
import Link from "next/link";
import { Menu, X } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";
import { Logo } from "@/components/layout/Logo";

const navLinks = [
  { href: "/properties", label: "Stays" },
  { href: "/portfolio", label: "Portfolio" },
  { href: "/invest", label: "Invest" },
  { href: "/blog", label: "Journal" },
  { href: "/about", label: "About" },
  { href: "/contact", label: "Contact" },
];

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="glass sticky top-0 z-50">
      <Container>
        <nav className="flex h-20 items-center justify-between">
          <Link href="/" aria-label="BLB Realty — home" className="text-[26px]">
            <Logo tone="dark" />
          </Link>

          {/* Desktop nav */}
          <div className="hidden items-center gap-7 md:flex lg:gap-9">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="text-[13px] font-medium uppercase tracking-[0.14em] text-hunter/70 transition-colors duration-300 hover:text-hunter"
              >
                {link.label}
              </Link>
            ))}
            <Button href="/book" size="sm">
              Book a Stay
            </Button>
          </div>

          {/* Mobile menu button */}
          <button
            className="md:hidden"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
          >
            {mobileOpen ? <X className="h-5 w-5 text-hunter" /> : <Menu className="h-5 w-5 text-hunter" />}
          </button>
        </nav>

        {/* Mobile menu */}
        {mobileOpen && (
          <div className="border-t border-hunter/10 pb-5 md:hidden">
            <div className="flex flex-col gap-1 pt-3">
              {navLinks.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  className="rounded-lg px-4 py-3 text-[15px] font-medium uppercase tracking-[0.12em] text-hunter/70 transition-all duration-300 hover:bg-hunter/[0.04] hover:text-hunter"
                  onClick={() => setMobileOpen(false)}
                >
                  {link.label}
                </Link>
              ))}
              <div className="px-4 pt-3">
                <Button href="/book" size="sm" className="w-full">
                  Book a Stay
                </Button>
              </div>
            </div>
          </div>
        )}
      </Container>
    </header>
  );
}
