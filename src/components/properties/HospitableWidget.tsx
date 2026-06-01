"use client";

import { CalendarDays } from "lucide-react";

interface HospitableWidgetProps {
  widgetId: string;
  propertyId: string;
}

export function HospitableWidget({ widgetId, propertyId }: HospitableWidgetProps) {
  const src = `https://booking.hospitable.com/widget/${widgetId}/${propertyId}`;

  return (
    <div className="overflow-hidden rounded-2xl border border-black/[0.06] bg-white shadow-sm shadow-black/[0.03]">
      <div className="glass flex items-center gap-2.5 px-5 py-3.5">
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-accent/10">
          <CalendarDays className="h-3.5 w-3.5 text-accent-dark" />
        </div>
        <div>
          <h3 className="text-[13px] font-semibold text-foreground">Check Availability</h3>
          <p className="text-[11px] text-muted">Select dates to book directly</p>
        </div>
      </div>
      <div className="border-t border-black/[0.04]">
        <iframe
          id="booking-iframe"
          sandbox="allow-top-navigation allow-scripts allow-same-origin"
          src={src}
          title="Book this property"
          className="h-[600px] w-full border-0 sm:h-[900px]"
          loading="lazy"
        />
      </div>
    </div>
  );
}
