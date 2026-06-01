"use client";

interface HospitableWidgetProps {
  widgetId: string;
  propertyId: string;
}

export function HospitableWidget({ widgetId, propertyId }: HospitableWidgetProps) {
  const src = `https://booking.hospitable.com/widget/${widgetId}/${propertyId}`;

  return (
    <div className="glass-card overflow-hidden rounded-[20px]">
      <div className="hero-gradient px-6 py-4">
        <h3 className="text-[13px] font-semibold text-white/90">Check Availability &amp; Book</h3>
      </div>
      <iframe
        id="booking-iframe"
        sandbox="allow-top-navigation allow-scripts allow-same-origin"
        src={src}
        title="Book this property"
        className="h-[600px] w-full border-0 sm:h-[900px]"
        loading="lazy"
      />
    </div>
  );
}
