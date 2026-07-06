import { NextRequest, NextResponse } from "next/server";
import { addSubscriber } from "@/lib/db";
import { routeLeadToCrm } from "@/lib/crm";

// Simple in-memory rate limiting
const rateLimit = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const window = 60 * 1000; // 1 minute
  const maxRequests = 5;

  const entry = rateLimit.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimit.set(ip, { count: 1, resetAt: now + window });
    return true;
  }

  if (entry.count >= maxRequests) {
    return false;
  }

  entry.count++;
  return true;
}

export async function POST(request: NextRequest) {
  try {
    const ip = request.headers.get("x-forwarded-for") || "unknown";

    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: "Too many requests. Please try again later." },
        { status: 429 },
      );
    }

    const body = await request.json();
    const { email, source, phone } = body;

    if (!email || typeof email !== "string") {
      return NextResponse.json(
        { error: "A valid email address is required." },
        { status: 400 },
      );
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { error: "Please enter a valid email address." },
        { status: 400 },
      );
    }

    // Phone validation — required only when the caller expects it (gated content).
    let normalizedPhone: string | undefined;
    if (body.requirePhone || phone) {
      const digits = typeof phone === "string" ? phone.replace(/\D/g, "") : "";
      if (digits.length < 10) {
        return NextResponse.json(
          { error: "Please enter a valid phone number." },
          { status: 400 },
        );
      }
      normalizedPhone = phone.trim();
    }

    const result = addSubscriber(
      email,
      source || "unknown",
      body.firstName,
      normalizedPhone,
    );

    // Route the lead into the CRM (Mailchimp / webhook). Best-effort — a CRM
    // failure must not fail the request or block the visitor.
    await routeLeadToCrm({
      email,
      phone: normalizedPhone,
      source: source || "unknown",
      firstName: body.firstName,
    });

    return NextResponse.json({ message: result.message }, { status: 200 });
  } catch (error) {
    console.error("Subscribe error:", error);
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 },
    );
  }
}
