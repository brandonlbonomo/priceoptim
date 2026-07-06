import {
  Wifi, AirVent, Flame, WashingMachine, Wind,
  CookingPot, Coffee, Droplets,
  Tv, Play, Dice5,
  TreePalm, Car, Waves, Flower2,
  ShieldCheck, Cross,
  Bath, Bed,
} from "lucide-react";
import type { Amenity, AmenityCategory } from "@/types/property";

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  Wifi, AirVent, Flame, WashingMachine, Wind,
  CookingPot, Coffee, Droplets,
  Tv, Play, Dice5,
  TreePalm, Car, Waves, Flower2,
  ShieldCheck, Cross,
  Bath, Bed,
};

const categoryLabels: Record<AmenityCategory, string> = {
  essentials: "Essentials",
  kitchen: "Kitchen",
  entertainment: "Entertainment",
  outdoor: "Outdoor",
  parking: "Parking",
  safety: "Safety",
  bathroom: "Bathroom",
  bedroom: "Bedroom",
};

interface AmenityListProps {
  amenities: Amenity[];
}

export function AmenityList({ amenities }: AmenityListProps) {
  const grouped = amenities.reduce(
    (acc, amenity) => {
      if (!acc[amenity.category]) acc[amenity.category] = [];
      acc[amenity.category].push(amenity);
      return acc;
    },
    {} as Record<string, Amenity[]>,
  );

  return (
    <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
      {Object.entries(grouped).map(([category, items]) => (
        <div key={category}>
          <h4 className="eyebrow mb-3">
            {categoryLabels[category as AmenityCategory] || category}
          </h4>
          <ul className="space-y-2">
            {items.map((amenity) => {
              const Icon = amenity.icon ? iconMap[amenity.icon] : null;
              return (
                <li key={amenity.name} className="flex items-center gap-2 text-sm text-foreground">
                  {Icon && <Icon className="h-4 w-4 text-primary" />}
                  {amenity.name}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  );
}
