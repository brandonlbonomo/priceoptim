import type { Metadata } from "next";
import { Container } from "@/components/ui/Container";
import { Breadcrumbs } from "@/components/ui/Breadcrumbs";

export const metadata: Metadata = {
  title: "Terms of Service",
  description:
    "Terms of Service for BLB Realty vacation rentals operated by BLB REALTY LLC.",
  alternates: {
    canonical: "/terms",
  },
};

export default function TermsPage() {
  return (
    <section className="py-14 sm:py-20">
      <Container>
        {/* Breadcrumbs */}
        <Breadcrumbs
          items={[
            { label: "Home", href: "/" },
            { label: "Terms of Service" },
          ]}
        />

        {/* Header */}
        <div className="text-center">
          <p className="eyebrow">
            Legal
          </p>
          <h1 className="mt-4 text-2xl font-display font-medium tracking-tight text-hunter sm:text-3xl">
            Terms of Service
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-[15px] text-muted">
            Please read these terms carefully before using our website or booking
            a vacation rental through BLB Realty.
          </p>
        </div>

        {/* Terms Content */}
        <div className="mx-auto mt-14 max-w-3xl">
          <div className="glass-card rounded-[4px] p-8 sm:p-10">
            <p className="text-[13px] text-muted">
              Last updated: June 1, 2026
            </p>

            {/* 1. Acceptance of Terms */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                1. Acceptance of Terms
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                By accessing or using the website located at{" "}
                <a
                  href="https://www.byblb.com"
                  className="font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
                >
                  www.byblb.com
                </a>{" "}
                (the &ldquo;Site&rdquo;) or booking a vacation rental through
                BLB Realty, operated by BLB REALTY LLC
                (&ldquo;we,&rdquo; &ldquo;us,&rdquo; or &ldquo;our&rdquo;), you
                agree to be bound by these Terms of Service
                (&ldquo;Terms&rdquo;). If you do not agree to these Terms, you
                may not access or use the Site or our services.
              </p>
            </div>

            {/* 2. Bookings and Reservations */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                2. Bookings &amp; Reservations
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                All reservations are subject to availability and confirmation.
                By submitting a booking request, you represent that all
                information provided is accurate and complete. A reservation is
                not confirmed until you receive a written confirmation from us
                via email or through our booking platform. We reserve the right
                to decline or cancel any reservation at our sole discretion.
              </p>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                You must be at least 21 years of age to book a property.
                The individual who makes the reservation must be present for the
                entire duration of the stay.
              </p>
            </div>

            {/* 3. Cancellation Policy */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                3. Cancellation Policy
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                Cancellation policies may vary by property and are communicated
                at the time of booking. If you need to cancel or modify a
                reservation, please contact us directly as soon as possible. We
                will work with you on a case-by-case basis to accommodate
                changes when feasible. Refund eligibility is determined by the
                specific cancellation policy applicable to your reservation as
                stated in your booking confirmation.
              </p>
            </div>

            {/* 4. Payment Terms */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                4. Payment Terms
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                All payments are securely processed through Hospitable, our
                third-party booking and payment platform. By completing a
                booking, you agree to Hospitable&apos;s payment processing terms
                in addition to these Terms. We do not store or directly handle
                your credit card or payment information. Pricing displayed on our
                Site is in U.S. dollars and may be subject to applicable taxes,
                cleaning fees, and service fees as outlined during the booking
                process.
              </p>
            </div>

            {/* 5. Property Rules */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                5. Property Rules
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                Each property has specific house rules that are provided in your
                booking confirmation and/or the property listing. You agree to
                comply with all posted rules during your stay. Violations of
                property rules may result in immediate termination of your
                reservation without refund and may incur additional charges for
                damages, excessive cleaning, or disturbances. You are
                responsible for the conduct of all guests and visitors at the
                property during your reservation.
              </p>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                You agree not to exceed the maximum occupancy stated in the
                listing, host unauthorized events or parties, smoke inside the
                property (unless expressly permitted), or engage in any illegal
                activity on the premises.
              </p>
            </div>

            {/* 6. Liability Limitations */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                6. Limitation of Liability
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                To the fullest extent permitted by law, BLB REALTY LLC, its
                owners, officers, employees, and agents shall not be liable for
                any indirect, incidental, special, consequential, or punitive
                damages arising out of or related to your use of the Site, any
                booking, or your stay at any property. Our total liability for
                any claim arising under these Terms shall not exceed the total
                amount you paid for the applicable reservation.
              </p>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                We are not responsible for any loss of or damage to personal
                property, injuries, or accidents occurring during your stay. You
                acknowledge that vacation rental properties may present inherent
                risks and you assume all responsibility for your safety and the
                safety of your guests.
              </p>
            </div>

            {/* 7. Intellectual Property */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                7. Intellectual Property
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                All content on this Site, including but not limited to text,
                images, graphics, logos, and software, is the property of BLB
                REALTY LLC or its content suppliers and is protected by United
                States and international copyright, trademark, and other
                intellectual property laws. You may not reproduce, distribute,
                modify, or create derivative works from any content on this Site
                without our prior written consent.
              </p>
            </div>

            {/* 8. Modifications to Terms */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                8. Modifications to Terms
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                We reserve the right to update or modify these Terms at any time
                without prior notice. Changes will be effective immediately upon
                posting to the Site. The &ldquo;Last updated&rdquo; date at the
                top of this page reflects the most recent revision. Your
                continued use of the Site or our services after any changes
                constitutes your acceptance of the revised Terms.
              </p>
            </div>

            {/* 9. Governing Law */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                9. Governing Law
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                These Terms shall be governed by and construed in accordance with
                the laws of the State of New York, without regard to its conflict
                of law principles. Any disputes arising under or in connection
                with these Terms shall be subject to the exclusive jurisdiction
                of the state and federal courts located in the State of New York.
              </p>
            </div>

            {/* 10. Contact Information */}
            <div className="mt-10">
              <h2 className="text-[19px] font-display font-medium tracking-tight text-hunter sm:text-[22px]">
                10. Contact Information
              </h2>
              <p className="mt-4 text-[15px] leading-relaxed text-muted">
                If you have any questions about these Terms, please contact us:
              </p>
              <div className="mt-4 space-y-2 text-[15px] leading-relaxed text-muted">
                <p>
                  <span className="font-medium text-foreground">Company:</span>{" "}
                  BLB REALTY LLC
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
                <p>
                  <span className="font-medium text-foreground">Email:</span>{" "}
                  <a
                    href="mailto:blbrealtyllc@gmail.com"
                    className="font-medium text-accent-dark transition-colors duration-200 hover:text-foreground"
                  >
                    blbrealtyllc@gmail.com
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
              </div>
            </div>
          </div>
        </div>
      </Container>
    </section>
  );
}
