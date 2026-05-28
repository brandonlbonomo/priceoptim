"use client";

import { useState } from "react";
import { Send, CheckCircle, Loader2 } from "lucide-react";
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
      <div className={cn("flex items-center gap-2 text-sm", compact ? "text-green-300" : "text-green-600", className)}>
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
          "flex-1 rounded-2xl border px-5 py-3 text-sm transition-all duration-200 focus:outline-none focus:ring-2",
          compact
            ? "border-white/10 bg-white/10 text-white placeholder-gray-400 focus:border-accent/50 focus:ring-accent/20"
            : "border-gray-200 bg-white text-foreground placeholder-muted focus:border-primary/50 focus:ring-primary/20",
        )}
      />
      <button
        type="submit"
        disabled={status === "loading"}
        className={cn(
          "inline-flex items-center justify-center gap-2 rounded-2xl px-6 py-3 text-sm font-semibold transition-all duration-300",
          compact
            ? "bg-accent text-primary-dark shadow-lg shadow-accent/20 hover:bg-accent-light hover:-translate-y-0.5"
            : "bg-primary text-white shadow-lg shadow-primary/20 hover:bg-primary-light hover:-translate-y-0.5",
          status === "loading" && "cursor-not-allowed opacity-70",
        )}
      >
        {status === "loading" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Send className="h-4 w-4" />
        )}
        Subscribe
      </button>
      {status === "error" && (
        <p className="text-sm text-red-400">{message}</p>
      )}
    </form>
  );
}
