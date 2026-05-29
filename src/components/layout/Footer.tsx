import Link from "next/link";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";

const footerLinks = [
  { href: "/", label: "Home" },
  { href: "/properties", label: "Properties" },
  { href: "/reviews", label: "Reviews" },
  { href: "/blog", label: "Blog" },
  { href: "/subscribe", label: "Get Deals" },
];

export function Footer() {
  return (
    <footer className="mt-auto bg-[#1d1d1f] text-white">
      <Container className="py-16">
        <div className="grid gap-12 md:grid-cols-3">
          {/* Brand */}
          <div>
            <h3 className="text-[15px] font-semibold tracking-tight">Experiences by BLB</h3>
            <p className="mt-4 text-[13px] leading-relaxed text-white/40">
              Premium vacation rentals with the best direct booking rates. Skip the
              platform fees and book with us directly.
            </p>
          </div>

          {/* Links */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.2em] text-white/30">
              Quick Links
            </h4>
            <ul className="mt-5 space-y-3">
              {footerLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-[13px] text-white/40 transition-colors duration-300 hover:text-white"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Email signup */}
          <div>
            <h4 className="text-[11px] font-semibold uppercase tracking-[0.2em] text-white/30">
              Exclusive Deals
            </h4>
            <p className="mt-4 mb-5 text-[13px] text-white/40">
              Get special rates and promotions delivered to your inbox.
            </p>
            <EmailForm source="footer" compact />
          </div>
        </div>

        <div className="mt-12 border-t border-white/[0.06] pt-8 text-center text-[12px] text-white/25">
          &copy; {new Date().getFullYear()} Experiences by BLB. Owned and operated by BLB Realty. All rights reserved.
        </div>
      </Container>
    </footer>
  );
}
