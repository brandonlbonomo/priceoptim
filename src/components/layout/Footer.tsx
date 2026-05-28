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
    <footer className="mt-auto border-t border-gray-100 bg-primary-dark text-white">
      <Container className="py-12">
        <div className="grid gap-8 md:grid-cols-3">
          {/* Brand */}
          <div>
            <h3 className="text-lg font-bold tracking-tight">BLB REALTY</h3>
            <p className="mt-2 text-sm text-gray-300">
              Premium vacation rentals with the best direct booking rates. Skip the
              platform fees and book with us directly.
            </p>
          </div>

          {/* Links */}
          <div>
            <h4 className="text-sm font-semibold uppercase tracking-wider text-gray-300">
              Quick Links
            </h4>
            <ul className="mt-3 space-y-2">
              {footerLinks.map((link) => (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    className="text-sm text-gray-300 transition-colors hover:text-white"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Email signup */}
          <div>
            <h4 className="text-sm font-semibold uppercase tracking-wider text-gray-300">
              Exclusive Deals
            </h4>
            <p className="mt-2 mb-3 text-sm text-gray-300">
              Get special rates and promotions delivered to your inbox.
            </p>
            <EmailForm source="footer" compact />
          </div>
        </div>

        <div className="mt-8 border-t border-gray-600 pt-6 text-center text-sm text-gray-400">
          &copy; {new Date().getFullYear()} BLB Realty. All rights reserved.
        </div>
      </Container>
    </footer>
  );
}
