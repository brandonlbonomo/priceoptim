"use client";

interface HospitableWidgetProps {
  widgetId: string;
  propertyId: string;
}

export function HospitableWidget({ widgetId, propertyId }: HospitableWidgetProps) {
  const src = `https://booking.hospitable.com/widget/${widgetId}/${propertyId}`;

  return (
    <div className="overflow-hidden rounded-3xl border border-gray-200/60 bg-white/70 backdrop-blur-sm">
      <div className="mesh-gradient px-5 py-3.5">
        <h3 className="text-sm font-semibold text-white">Check Availability &amp; Book</h3>
      </div>
      <iframe
        id="booking-iframe"
        sandbox="allow-top-navigation allow-scripts allow-same-origin"
        src={src}
        title="Book this property"
        className="h-[900px] w-full border-0"
        loading="lazy"
      />
    </div>
  );
}
