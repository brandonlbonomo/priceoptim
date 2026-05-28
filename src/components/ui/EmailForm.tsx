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
          "flex-1 rounded-lg border px-4 py-2.5 text-sm transition-colors focus:outline-none focus:ring-2",
          compact
            ? "border-gray-500 bg-white/10 text-white placeholder-gray-400 focus:border-accent focus:ring-accent/20"
            : "border-gray-300 text-foreground placeholder-muted focus:border-primary focus:ring-primary/20",
        )}
      />
      <button
        type="submit"
        disabled={status === "loading"}
        className={cn(
          "inline-flex items-center justify-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold transition-colors",
          compact
            ? "bg-accent text-primary-dark hover:bg-accent-light"
            : "bg-primary text-white hover:bg-primary-light",
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
        <p className="text-sm text-red-500">{message}</p>
      )}
    </form>
  );
}
