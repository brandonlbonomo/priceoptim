"use client";

import { useEffect, useState } from "react";
import { FileText, Loader2, Check } from "lucide-react";

const LEAD_PREFIX = "blb-lead:";

/**
 * Tier-2, higher-intent ask shown after a visitor has unlocked the dashboard.
 * Reuses the lead captured at unlock (email/name) to request the full
 * underwriting model, tagging them as a serious prospect in the CRM.
 */
export function RequestPacket({ source = "invest-numbers" }: { source?: string }) {
  const [lead, setLead] = useState<{ email: string; name?: string } | null>(null);
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const raw = localStorage.getItem(LEAD_PREFIX + source);
      if (raw) setLead(JSON.parse(raw));
    } catch {
      /* ignore */
    }
  }, [source]);

  async function requestPacket(e: React.FormEvent) {
    e.preventDefault();
    const useEmail = lead?.email || email;
    if (!useEmail) return;
    setStatus("loading");
    setMessage("");
    try {
      const res = await fetch("/api/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: useEmail,
          name: lead?.name,
          source: "investor-packet",
          tags: ["investor-packet-request"],
        }),
      });
      if (res.ok) {
        setStatus("done");
      } else {
        const data = await res.json();
        setStatus("error");
        setMessage(data.error || "Something went wrong. Please try again.");
      }
    } catch {
      setStatus("error");
      setMessage("Something went wrong. Please try again.");
    }
  }

  return (
    <div className="rounded-[6px] border border-hunter/12 bg-hunter px-6 py-8 text-center text-cream sm:px-10 sm:py-10">
      <div className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-full bg-white/10">
        <FileText className="h-4 w-4 text-gold-light" />
      </div>
      <h3 className="font-display text-2xl font-medium tracking-tight">
        Want the full underwriting model?
      </h3>
      <p className="mx-auto mt-3 max-w-md text-[14px] leading-relaxed text-cream/70">
        Serious partners can request the complete deal-by-deal model and our
        current investor packet. We&apos;ll review and reach out personally.
      </p>

      {status === "done" ? (
        <div className="mt-6 inline-flex items-center gap-2 rounded-[4px] bg-white/10 px-5 py-3 text-[14px] font-medium">
          <Check className="h-4 w-4 text-gold-light" />
          Request received — we&apos;ll be in touch.
        </div>
      ) : (
        <form
          onSubmit={requestPacket}
          className="mx-auto mt-6 flex max-w-md flex-col items-center gap-3 sm:flex-row sm:justify-center"
        >
          {!lead?.email && (
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@email.com"
              required
              className="w-full rounded-[4px] border border-white/15 bg-white/[0.08] px-4 py-3 text-[14px] text-cream placeholder-cream/40 focus:outline-none focus:ring-2 focus:ring-gold/40 sm:w-auto sm:flex-1"
            />
          )}
          <button
            type="submit"
            disabled={status === "loading"}
            className="inline-flex w-full items-center justify-center gap-2 rounded-[4px] bg-gold px-6 py-3 text-[14px] font-semibold text-hunter transition hover:bg-gold-light active:scale-[0.99] disabled:opacity-60 sm:w-auto"
          >
            {status === "loading" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Sending…
              </>
            ) : (
              "Request the investor packet"
            )}
          </button>
        </form>
      )}
      {status === "error" && (
        <p className="mt-3 text-[13px] text-red-300">{message}</p>
      )}
    </div>
  );
}
