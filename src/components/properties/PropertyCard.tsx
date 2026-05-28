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
      className="glass-card group block overflow-hidden rounded-3xl transition-all duration-300"
    >
      <div className="relative aspect-[4/3] overflow-hidden">
        <Image
          src={property.images[0]}
          alt={property.name}
          fill
          className="object-cover transition-transform duration-500 group-hover:scale-105"
          sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
          unoptimized
        />
        <div className="absolute inset-0 bg-gradient-to-t from-black/20 via-transparent to-transparent" />
        <div className="absolute bottom-3 right-3">
          <span className="glass-dark rounded-full px-3 py-1.5 text-sm font-bold text-white">
            {formatCurrency(property.pricing.baseNight)}
            <span className="font-normal text-gray-300"> / night</span>
          </span>
        </div>
      </div>

      <div className="p-5">
        <p className="text-xs font-semibold uppercase tracking-wider text-accent-dark">
          {property.location.area}
        </p>
        <h3 className="mt-1.5 text-lg font-semibold text-foreground transition-colors duration-200 group-hover:text-primary">
          {property.name}
        </h3>
        <p className="mt-1 text-sm text-muted line-clamp-2">{property.tagline}</p>

        <div className="mt-4 flex items-center gap-3 text-sm text-muted">
          <span className="flex items-center gap-1.5 rounded-full bg-muted-light/80 px-3 py-1">
            <BedDouble className="h-3.5 w-3.5 text-primary" />
            {property.details.bedrooms}
          </span>
          <span className="flex items-center gap-1.5 rounded-full bg-muted-light/80 px-3 py-1">
            <Bath className="h-3.5 w-3.5 text-primary" />
            {property.details.bathrooms}
          </span>
          <span className="flex items-center gap-1.5 rounded-full bg-muted-light/80 px-3 py-1">
            <Users className="h-3.5 w-3.5 text-primary" />
            {property.details.maxGuests}
          </span>
        </div>
      </div>
    </Link>
  );
}
