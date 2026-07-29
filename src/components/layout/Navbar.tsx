"use client";

import { useState } from "react";
import Link from "next/link";
import Image from "next/image";
import { Menu, X, ChevronDown } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { Button } from "@/components/ui/Button";

type NavChild = { href: string; label: string };
type NavItem = { href: string; label: string; children?: NavChild[] };

const navLinks: NavItem[] = [
  {
    href: "/nomo-collection",
    label: "The Nomo Collection",
    children: [
      { href: "/nomo-collection", label: "Book Direct" },
      { href: "/blog", label: "Journal" },
    ],
  },
  { href: "/portfolio", label: "Portfolio" },
  { href: "/invest", label: "Invest" },
  { href: "/about", label: "About" },
  { href: "/contact", label: "Contact" },
];

const linkClass =
  "text-[13px] font-medium uppercase tracking-[0.14em] text-hunter/70 transition-colors duration-300 hover:text-hunter";

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="glass sticky top-0 z-50">
      <Container>
        <nav className="flex h-20 items-center justify-between">
          <Link href="/" aria-label="Bonomo Capital Group — home" className="flex items-center">
            <Image
              src="/bonomo-mark.png"
              alt="Bonomo Capital Group"
              width={1162}
              height={706}
              priority
              className="h-14 w-auto"
            />
          </Link>

          {/* Desktop nav */}
          <div className="hidden items-center gap-7 md:flex lg:gap-9">
            {navLinks.map((link) =>
              link.children ? (
                <div key={link.label} className="group relative">
                  <Link href={link.href} className={`${linkClass} inline-flex items-center gap-1`}>
                    {link.label}
                    <ChevronDown className="h-3 w-3 transition-transform duration-300 group-hover:rotate-180" />
                  </Link>
                  {/* Dropdown (hover/focus). pt-2 keeps a hover bridge to the menu. */}
                  <div className="invisible absolute left-1/2 top-full z-50 -translate-x-1/2 pt-3 opacity-0 transition-all duration-200 group-hover:visible group-hover:opacity-100 group-focus-within:visible group-focus-within:opacity-100">
                    <div className="min-w-[190px] rounded-md border border-hunter/10 bg-surface p-2 shadow-[0_10px_30px_rgba(13,26,36,0.12)]">
                      {link.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          className="block rounded px-3 py-2.5 text-[12px] font-medium uppercase tracking-[0.12em] text-hunter/70 transition-colors duration-200 hover:bg-hunter/[0.05] hover:text-hunter"
                        >
                          {child.label}
                        </Link>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <Link key={link.href} href={link.href} className={linkClass}>
                  {link.label}
                </Link>
              ),
            )}
            <Button href="https://thenomocollection.com" size="sm">
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
                <div key={link.label}>
                  <Link
                    href={link.href}
                    className="block rounded-lg px-4 py-3 text-[15px] font-medium uppercase tracking-[0.12em] text-hunter/70 transition-all duration-300 hover:bg-hunter/[0.04] hover:text-hunter"
                    onClick={() => setMobileOpen(false)}
                  >
                    {link.label}
                  </Link>
                  {link.children && (
                    <div className="ml-3 flex flex-col gap-1 border-l border-hunter/10 pl-3">
                      {link.children.map((child) => (
                        <Link
                          key={child.href}
                          href={child.href}
                          className="rounded-lg px-4 py-2.5 text-[13px] font-medium uppercase tracking-[0.1em] text-hunter/55 transition-all duration-300 hover:bg-hunter/[0.04] hover:text-hunter"
                          onClick={() => setMobileOpen(false)}
                        >
                          {child.label}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              <div className="px-4 pt-3">
                <Button href="https://thenomocollection.com" size="sm" className="w-full">
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
