import Link from "next/link";
import Image from "next/image";
import { BedDouble, Bath, Users } from "lucide-react";
import { formatCurrency } from "@/lib/utils";
import type { Property } from "@/types/property";

interface PropertyCardProps {
  property: Property;
}

export function PropertyCard({ property }: PropertyCardProps) {
  return (
    <Link
      href={`/properties/${property.slug}`}
      className="group block overflow-hidden rounded-xl border border-gray-200 bg-white transition-shadow hover:shadow-lg"
    >
      <div className="relative aspect-[4/3] overflow-hidden bg-gray-100">
        <Image
          src={property.images[0]}
          alt={property.name}
          fill
          className="object-cover transition-transform duration-300 group-hover:scale-105"
          sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
          unoptimized
        />
      </div>

      <div className="p-5">
        <p className="text-xs font-medium uppercase tracking-wider text-muted">
          {property.location.area}
        </p>
        <h3 className="mt-1 text-lg font-semibold text-foreground group-hover:text-primary">
          {property.name}
        </h3>
        <p className="mt-1 text-sm text-muted line-clamp-2">{property.tagline}</p>

        <div className="mt-4 flex items-center gap-4 text-sm text-muted">
          <span className="flex items-center gap-1">
            <BedDouble className="h-4 w-4" />
            {property.details.bedrooms} {property.details.bedrooms === 1 ? "bed" : "beds"}
          </span>
          <span className="flex items-center gap-1">
            <Bath className="h-4 w-4" />
            {property.details.bathrooms} {property.details.bathrooms === 1 ? "bath" : "baths"}
          </span>
          <span className="flex items-center gap-1">
            <Users className="h-4 w-4" />
            {property.details.maxGuests} guests
          </span>
        </div>

        <div className="mt-4 border-t border-gray-100 pt-3">
          <span className="text-lg font-bold text-primary">
            {formatCurrency(property.pricing.baseNight)}
          </span>
          <span className="text-sm text-muted"> / night</span>
        </div>
      </div>
    </Link>
  );
}
