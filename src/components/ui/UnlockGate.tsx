"use client";

import { useEffect, useState } from "react";
import { Lock, Loader2, ArrowRight } from "lucide-react";

interface UnlockGateProps {
  /** Lead-source tag stored with the subscriber (e.g. "invest-numbers"). */
  source: string;
  /** The gated content, revealed once the visitor unlocks. */
  children: React.ReactNode;
  eyebrow?: string;
  title?: string;
  blurb?: string;
}

const UNLOCK_PREFIX = "blb-unlocked:";
const LEAD_PREFIX = "blb-lead:";

export function UnlockGate({
  source,
  children,
  eyebrow = "Investor access",
  title = "Enter the investor room",
  blurb = "Portfolio performance, target returns, and the underwriting behind every deal. Tell us who you are to unlock the figures — we'll follow up personally about partnering.",
}: UnlockGateProps) {
  const [unlocked, setUnlocked] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [intent, setIntent] = useState(false);
  const [status, setStatus] = useState<"idle" | "loading" | "error">("idle");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (localStorage.getItem(UNLOCK_PREFIX + source) === "true") {
      setUnlocked(true);
    }
  }, [source]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name || !email || !phone || !intent) return;
    setStatus("loading");
    setMessage("");

    try {
      const res = await fetch("/api/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          phone,
          source,
          intent,
          requirePhone: true,
        }),
      });
      const data = await res.json();

      if (res.ok) {
        localStorage.setItem(UNLOCK_PREFIX + source, "true");
        // Remember the lead so higher-intent follow-ups (tier 2) can reuse it.
        localStorage.setItem(
          LEAD_PREFIX + source,
          JSON.stringify({ email, name }),
        );
        setUnlocked(true);
      } else {
        setStatus("error");
        setMessage(data.error || "Something went wrong. Please try again.");
      }
    } catch {
      setStatus("error");
      setMessage("Something went wrong. Please try again.");
    }
  }

  if (unlocked) {
    return <>{children}</>;
  }

  const inputClass =
    "w-full rounded-[4px] border border-hunter/15 bg-white px-4 py-3 text-[14px] text-foreground placeholder-muted transition focus:border-transparent focus:outline-none focus:ring-2 focus:ring-gold/30";

  return (
    <div className="relative overflow-hidden rounded-[6px] border border-hunter/10">
      {/* Blurred preview of the real content behind the gate */}
      <div
        aria-hidden="true"
        className="pointer-events-none max-h-[520px] select-none overflow-hidden blur-md saturate-[0.85]"
      >
        {children}
      </div>

      {/* Lock overlay */}
      <div className="absolute inset-0 flex items-center justify-center bg-cream/80 backdrop-blur-[3px]">
        <div className="mx-auto w-full max-w-md px-6 py-10 text-center">
          <div className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-full bg-hunter/[0.06]">
            <Lock className="h-4 w-4 text-hunter" />
          </div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gold-dark">
            {eyebrow}
          </p>
          <h3 className="mt-2 font-display text-2xl font-medium tracking-tight text-hunter">
            {title}
          </h3>
          <p className="mx-auto mt-3 max-w-sm text-[14px] leading-relaxed text-muted">
            {blurb}
          </p>

          <form onSubmit={handleSubmit} className="mt-6 space-y-3 text-left">
            <input
              type="text"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                if (status === "error") setStatus("idle");
              }}
              placeholder="Full name"
              required
              autoComplete="name"
              className={inputClass}
            />
            <input
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                if (status === "error") setStatus("idle");
              }}
              placeholder="you@email.com"
              required
              autoComplete="email"
              className={inputClass}
            />
            <input
              type="tel"
              value={phone}
              onChange={(e) => {
                setPhone(e.target.value);
                if (status === "error") setStatus("idle");
              }}
              placeholder="(555) 123-4567"
              required
              autoComplete="tel"
              className={inputClass}
            />
            <label className="flex cursor-pointer items-start gap-2.5 pt-1 text-left">
              <input
                type="checkbox"
                checked={intent}
                onChange={(e) => setIntent(e.target.checked)}
                required
                className="mt-0.5 h-4 w-4 shrink-0 accent-[#856831]"
              />
              <span className="text-[12px] leading-relaxed text-muted">
                I&apos;m a prospective or accredited investor interested in
                partnering with BLB Realty.
              </span>
            </label>
            <button
              type="submit"
              disabled={status === "loading"}
              className="inline-flex w-full items-center justify-center gap-2 rounded-[4px] bg-hunter px-6 py-3 text-[14px] font-medium text-cream transition hover:bg-hunter-dark active:scale-[0.99] disabled:opacity-60"
            >
              {status === "loading" ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Unlocking…
                </>
              ) : (
                <>
                  Unlock the numbers
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
            {status === "error" && (
              <p className="text-[13px] text-red-600">{message}</p>
            )}
            <p className="text-center text-[11px] leading-relaxed text-muted">
              Private and confidential. We&apos;ll only reach out about
              partnering — never shared or sold.
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
