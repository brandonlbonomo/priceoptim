import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "Privacy Policy for Bonomo Capital Group vacation rentals. Learn how we collect, use, and protect your personal information.",
  alternates: {
    canonical: "/privacy",
  },
};

export default function PrivacyPolicyPage() {
  return (
    <section className="py-14 sm:py-20">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Privacy Policy" },
          ]}
        />

        {/* Header */}
        <div className="text-center">
          <p className="eyebrow">
            Legal
          </p>
          <h1 className="mt-4 text-2xl font-display font-medium tracking-tight text-hunter sm:text-3xl">
            Privacy Policy
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Your privacy matters to us. This policy explains how Bonomo Capital Group
            collects, uses, and protects your personal information.
          </p>
          <p className="mt-3 text-[13px] text-muted">
            Last updated: June 1, 2026
          </p>
        </div>

        {/* Policy Content */}
        <div className="mx-auto mt-14 max-w-3xl">
          {/* Introduction */}
          <div className="glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Introduction
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              Bonomo Capital Group (&ldquo;we,&rdquo; &ldquo;us,&rdquo; or
              &ldquo;our&rdquo;) operates the website{" "}
              <a
                href="https://www.byblb.com"
                className="font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
              >
                www.byblb.com
              </a>{" "}
              and the vacation rental brand &ldquo;Bonomo Capital Group.&rdquo;
              This Privacy Policy describes how we collect, use, disclose, and
              safeguard your information when you visit our website or book a
              stay with us. By using our services, you consent to the practices
              described in this policy.
            </p>
          </div>

          {/* Information We Collect */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Information We Collect
            </h2>

            <h3 className="mt-6 text-[15px] font-display font-medium text-hunter">
              Personal Information You Provide
            </h3>
            <ul className="mt-3 list-disc space-y-2 pl-5 text-[15px] leading-relaxed text-muted">
              <li>
                <span className="font-medium text-foreground">
                  Newsletter sign-up:
                </span>{" "}
                Email address collected via Mailchimp when you subscribe to our
                mailing list.
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Booking information:
                </span>{" "}
                Name, email address, phone number, payment details, and stay
                dates collected through our booking platform, Hospitable, and
                third-party listing sites (Airbnb, Vrbo, Booking.com).
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Communications:
                </span>{" "}
                Any information you provide when you contact us by phone, email,
                or through our website.
              </li>
            </ul>

            <h3 className="mt-6 text-[15px] font-display font-medium text-hunter">
              Information Collected Automatically
            </h3>
            <ul className="mt-3 list-disc space-y-2 pl-5 text-[15px] leading-relaxed text-muted">
              <li>
                <span className="font-medium text-foreground">Cookies:</span> We
                use cookies and similar tracking technologies to improve your
                browsing experience, analyze site traffic, and understand user
                behavior.
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Analytics data:
                </span>{" "}
                IP address, browser type, device information, pages visited, and
                referring URLs collected via Google Analytics.
              </li>
            </ul>
          </div>

          {/* How We Use Your Information */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              How We Use Your Information
            </h2>
            <ul className="mt-4 list-disc space-y-2 pl-5 text-[15px] leading-relaxed text-muted">
              <li>Process and manage your vacation rental bookings.</li>
              <li>
                Send booking confirmations, check-in instructions, and stay
                updates.
              </li>
              <li>
                Send marketing emails, promotions, and newsletters (only with
                your consent).
              </li>
              <li>
                Analyze website traffic and usage patterns to improve our site
                and services.
              </li>
              <li>
                Respond to your inquiries, requests, and customer support needs.
              </li>
              <li>
                Comply with legal obligations and protect against fraudulent
                activity.
              </li>
            </ul>
          </div>

          {/* Third-Party Services */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Third-Party Services
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              We use the following third-party services that may collect or
              process your data in accordance with their own privacy policies:
            </p>
            <ul className="mt-4 list-disc space-y-2 pl-5 text-[15px] leading-relaxed text-muted">
              <li>
                <span className="font-medium text-foreground">Mailchimp:</span>{" "}
                Email marketing and newsletter distribution.
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Hospitable:
                </span>{" "}
                Booking management, guest communication, and reservation
                processing.
              </li>
              <li>
                <span className="font-medium text-foreground">Zapier:</span>{" "}
                Workflow automation connecting our booking and marketing
                platforms.
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Google Analytics:
                </span>{" "}
                Website traffic analysis and visitor behavior tracking.
              </li>
            </ul>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              We do not sell, trade, or rent your personal information to third
              parties. Data shared with the services listed above is limited to
              what is necessary to operate our business and provide our services.
            </p>
          </div>

          {/* Cookies */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Cookies
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              Our website uses cookies to enhance your experience. Cookies are
              small text files stored on your device that help us understand how
              visitors interact with our site. We use both session cookies (which
              expire when you close your browser) and persistent cookies (which
              remain on your device until deleted). You can control cookie
              settings through your browser preferences. Disabling cookies may
              affect certain features of our website.
            </p>
          </div>

          {/* Data Retention */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Data Retention
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              We retain your personal information only for as long as necessary
              to fulfill the purposes outlined in this policy, including
              processing bookings, maintaining records for tax and legal
              compliance, and communicating with you about our services. Booking
              records are retained as required by applicable tax and business
              regulations. Marketing data (such as your email address) is
              retained until you unsubscribe or request deletion.
            </p>
          </div>

          {/* Your Rights */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Your Rights
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              You have the following rights regarding your personal information:
            </p>
            <ul className="mt-4 list-disc space-y-2 pl-5 text-[15px] leading-relaxed text-muted">
              <li>
                <span className="font-medium text-foreground">Opt out:</span>{" "}
                Unsubscribe from marketing emails at any time by clicking the
                &ldquo;unsubscribe&rdquo; link at the bottom of any email or by
                contacting us directly.
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Access and correction:
                </span>{" "}
                Request a copy of the personal data we hold about you or ask us
                to correct inaccurate information.
              </li>
              <li>
                <span className="font-medium text-foreground">Deletion:</span>{" "}
                Request deletion of your personal data, subject to any legal
                obligations that require us to retain certain records.
              </li>
              <li>
                <span className="font-medium text-foreground">
                  Cookie preferences:
                </span>{" "}
                Manage or disable cookies through your browser settings.
              </li>
            </ul>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              To exercise any of these rights, contact us using the information
              below.
            </p>
          </div>

          {/* Data Security */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Data Security
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              We implement reasonable administrative, technical, and physical
              safeguards to protect your personal information. However, no
              method of transmission over the internet or electronic storage is
              completely secure. While we strive to protect your data, we cannot
              guarantee absolute security.
            </p>
          </div>

          {/* Changes to This Policy */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Changes to This Policy
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              We may update this Privacy Policy from time to time. Any changes
              will be posted on this page with an updated &ldquo;Last
              updated&rdquo; date. We encourage you to review this policy
              periodically to stay informed about how we protect your
              information.
            </p>
          </div>

          {/* Contact Us */}
          <div className="mt-10 glass-card rounded-[4px] p-8 sm:p-10">
            <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
              Contact Us
            </h2>
            <p className="mt-4 text-[15px] leading-relaxed text-muted">
              If you have any questions about this Privacy Policy or wish to
              exercise your rights, please contact us:
            </p>
            <div className="mt-4 space-y-2 text-[15px] leading-relaxed text-muted">
              <p>
                <span className="font-medium text-foreground">Company:</span>{" "}
                Bonomo Capital Group
              </p>
              <p>
                <span className="font-medium text-foreground">Email:</span>{" "}
                <a
                  href="mailto:info@bonomocapital.com"
                  className="font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
                >
                  info@bonomocapital.com
                </a>
              </p>
              <p>
                <span className="font-medium text-foreground">Phone:</span>{" "}
                <a
                  href="tel:+15166506653"
                  className="font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
                >
                  (516) 650-6653
                </a>
              </p>
              <p>
                <span className="font-medium text-foreground">Website:</span>{" "}
                <a
                  href="https://www.byblb.com"
                  className="font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
                >
                  www.byblb.com
                </a>
              </p>
            </div>
          </div>
        </div>
      </Container>
    </section>
  );
}
