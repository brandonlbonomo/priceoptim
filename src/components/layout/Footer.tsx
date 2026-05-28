import Link from "next/link";
import { Container } from "@/components/ui/Container";
import { EmailForm } from "@/components/ui/EmailForm";

const footerLinks = [
  { href: "/", label: "Home" },
  { href: "/properties", label: "Properties" },
  { href: "/subscribe", label: "Get Deals" },
];

export function Footer() {
  return (
    <footer className="mt-auto border-t border-white/5 bg-primary-dark text-white">
      <Container className="py-14">
        <div className="grid gap-10 md:grid-cols-3">
          {/* Brand */}
          <div>
            <h3 className="text-lg font-bold tracking-tight">Properties By BLB</h3>
            <p className="mt-3 text-sm leading-relaxed text-gray-400">
              Premium vacation rentals with the best direct booking rates. Skip the
              platform fees and book with us directly.
            </p>
          </div>

          {/* Links */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-widest text-gray-500">
              Quick Links
            </h4>
            <ul className="mt-4 space-y-3">
              {footerLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-gray-400 transition-colors duration-200 hover:text-white"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Email signup */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-widest text-gray-500">
              Exclusive Deals
            </h4>
            <p className="mt-3 mb-4 text-sm text-gray-400">
              Get special rates and promotions delivered to your inbox.
            </p>
            <EmailForm source="footer" compact />
          </div>
        </div>

        <div className="mt-10 border-t border-white/10 pt-6 text-center text-sm text-gray-500">
          &copy; {new Date().getFullYear()} Properties By BLB. Owned and operated by BLB Realty. All rights reserved.
        </div>
      </Container>
    </footer>
  );
}
