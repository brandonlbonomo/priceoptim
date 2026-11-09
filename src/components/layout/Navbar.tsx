"use client";

import { useState } from "react";
import Link from "next/link";
import Image from "next/image";
import { Menu, X } from "lucide-react";
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

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="glass sticky top-0 z-50">
      <Container>
        {/* Hamburger (left) · large centered logo · Book a Stay (right) */}
        <nav className="grid h-24 grid-cols-[1fr_auto_1fr] items-center sm:h-28">
          <button
            className="inline-flex h-11 w-11 items-center justify-center justify-self-start rounded-md border border-hunter/15 text-hunter transition-colors duration-300 hover:bg-hunter/[0.04]"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>

          <Link
            href="/"
            aria-label="Bonomo Capital Group — home"
            className="flex items-center justify-self-center"
          >
            <Image
              src="/bonomo-mark.png"
              alt="Bonomo Capital Group"
              width={1162}
              height={706}
              priority
              className="h-16 w-auto sm:h-20 lg:h-24"
            />
          </Link>

          <div className="hidden justify-self-end sm:block">
            <Button href="https://thenomocollection.com" size="sm">
              Book a Stay
            </Button>
          </div>
        </nav>

        {/* Menu — opens from the hamburger on every screen size */}
        {mobileOpen && (
          <div className="border-t border-hunter/10 pb-5">
            <div className="mx-auto flex max-w-md flex-col gap-1 pt-3">
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
                <Button
                  href="https://thenomocollection.com"
                  size="sm"
                  className="w-full"
                >
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
