"use client";

interface HospitableWidgetProps {
  widgetId: string;
  propertyId: string;
}

export function HospitableWidget({ widgetId, propertyId }: HospitableWidgetProps) {
  const src = `https://www.hospitable.com/widget/${widgetId}/${propertyId}`;

  return (
    <div className="overflow-hidden rounded-xl border border-gray-200">
      <div className="bg-primary px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Check Availability &amp; Book</h3>
      </div>
      <iframe
        src={src}
        title="Book this property"
        className="h-[600px] w-full border-0"
        loading="lazy"
        allow="payment"
      />
    </div>
  );
}
