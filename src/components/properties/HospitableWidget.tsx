"use client";

import { CalendarDays } from "lucide-react";

interface HospitableWidgetProps {
  widgetId: string;
  propertyId: string;
  variant?: "compact" | "card";
}

export function HospitableWidget({ widgetId, propertyId, variant = "card" }: HospitableWidgetProps) {
  const src = `https://booking.hospitable.com/widget/${widgetId}/${propertyId}`;

  if (variant === "compact") {
    return (
      <iframe
        id="booking-iframe-mobile"
        sandbox="allow-top-navigation allow-scripts allow-same-origin"
        src={src}
        title="Book this property"
        className="h-[480px] w-full border-0"
        loading="lazy"
      />
    );
  }

  return (
    <div>
      <div className="mb-3 flex flex-col items-center gap-1">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-accent/10">
            <CalendarDays className="h-3 w-3 text-accent-dark" />
          </div>
          <h3 className="text-[13px] font-semibold text-foreground">Check Availability</h3>
        </div>
        <p className="text-[11px] text-muted">Select dates to book directly</p>
      </div>
      <iframe
        id="booking-iframe"
        sandbox="allow-top-navigation allow-scripts allow-same-origin"
        src={src}
        title="Book this property"
        className="h-[660px] w-full border-0"
        loading="lazy"
      />
    </div>
  );
}
