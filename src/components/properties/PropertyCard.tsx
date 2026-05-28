import Link from "next/link";
import Image from "next/image";
import { BedDouble, Bath, Users, MapPin, ArrowRight } from "lucide-react";
import type { Property } from "@/types/property";

interface PropertyCardProps {
  property: Property;
}

export function PropertyCard({ property }: PropertyCardProps) {
  return (
    <Link
      href={`/properties/${property.slug}`}
      className="glass-card group block overflow-hidden rounded-[28px]"
    >
      <div className="relative aspect-[4/3] overflow-hidden">
        <Image
          src={property.images[0]}
          alt={property.name}
          fill
          className="object-cover transition-all duration-700 group-hover:scale-110"
          sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 25vw"
          unoptimized
        />
        <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-black/5 to-transparent" />
      </div>

      <div className="p-5">
        <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.15em] text-muted">
          <MapPin className="h-3 w-3" />
          {property.location.city}, {property.location.state}
        </div>
        <h3 className="mt-2 text-[17px] font-semibold leading-snug text-foreground transition-colors duration-300 group-hover:text-accent-dark">
          {property.name}
        </h3>

        <div className="mt-4 flex items-center justify-between border-t border-black/[0.04] pt-4">
          <div className="flex items-center gap-4 text-[13px] text-muted">
            <span className="flex items-center gap-1.5">
              <BedDouble className="h-3.5 w-3.5" />
              {property.details.bedrooms}
            </span>
            <span className="flex items-center gap-1.5">
              <Bath className="h-3.5 w-3.5" />
              {property.details.bathrooms}
            </span>
            <span className="flex items-center gap-1.5">
              <Users className="h-3.5 w-3.5" />
              {property.details.maxGuests}
            </span>
          </div>
          <span className="flex items-center gap-1 text-[13px] font-medium text-accent-dark transition-colors duration-300 group-hover:text-accent">
            View
            <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5" />
          </span>
        </div>
      </div>
    </Link>
  );
}
