"use client";

import { useState } from "react";
import { ArrowRight, CheckCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmailFormProps {
  source: string;
  compact?: boolean;
  className?: string;
}

export function EmailForm({ source, compact = false, className }: EmailFormProps) {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [message, setMessage] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email) return;

    setStatus("loading");

    try {
      const res = await fetch("/api/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, source }),
      });

      const data = await res.json();

      if (res.ok) {
        setStatus("success");
        setMessage(data.message || "You're on the list!");
        setEmail("");
      } else {
        setStatus("error");
        setMessage(data.error || "Something went wrong. Try again.");
      }
    } catch {
      setStatus("error");
      setMessage("Something went wrong. Try again.");
    }
  }

  if (status === "success") {
    return (
      <div className={cn("flex items-center justify-center gap-2 text-[15px]", compact ? "text-gold-light" : "text-gold-dark", className)}>
        <CheckCircle className="h-4 w-4" />
        <span>{message}</span>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className={cn("flex gap-2", compact ? "flex-col sm:flex-row" : "flex-col sm:flex-row", className)}>
      <input
        type="email"
        value={email}
        onChange={(e) => {
          setEmail(e.target.value);
          if (status === "error") setStatus("idle");
        }}
        placeholder="Enter your email"
        required
        className={cn(
          "flex-1 rounded-[4px] px-5 py-2.5 text-[14px] transition-all duration-300 focus:outline-none focus:ring-2",
          compact
            ? "border-0 bg-white/[0.08] text-white placeholder-white/30 focus:bg-white/[0.12] focus:ring-gold/30"
            : "border border-hunter/10 bg-white text-foreground placeholder-muted focus:border-transparent focus:ring-gold/30",
        )}
      />
      <button
        type="submit"
        disabled={status === "loading"}
        className={cn(
          "inline-flex items-center justify-center gap-2 rounded-[4px] px-6 py-2.5 text-[14px] font-medium active:scale-[0.97]",
          compact
            ? "bg-gold text-hunter hover:bg-gold-light"
            : "bg-hunter text-ivory hover:bg-hunter-light",
          status === "loading" && "cursor-not-allowed opacity-60",
        )}
      >
        {status === "loading" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <ArrowRight className="h-4 w-4" />
        )}
        Subscribe
      </button>
      {status === "error" && (
        <p className="text-[13px] text-red-400">{message}</p>
      )}
    </form>
  );
}
