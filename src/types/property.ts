export interface Property {
  id: string;
  name: string;
  slug: string;
  tagline: string;
  description: string;
  location: {
    city: string;
    state: string;
    area: string;
  };
  images: string[];
  pricing: {
    baseNight: number;
    cleaningFee: number;
    currency: string;
  };
  details: {
    bedrooms: number;
    bathrooms: number;
    maxGuests: number;
    beds: number;
  };
  amenities: Amenity[];
  houseRules: string[];
  checkIn: string;
  checkOut: string;
  hospitable: {
    widgetId: string;
    propertyId: string;
  };
  featured: boolean;
  active: boolean;
}

export interface Amenity {
  name: string;
  category: AmenityCategory;
  icon?: string;
}

export type AmenityCategory =
  | "essentials"
  | "kitchen"
  | "entertainment"
  | "outdoor"
  | "safety"
  | "bathroom"
  | "bedroom"
  | "parking";

export interface Subscriber {
  id?: number;
  email: string;
  firstName?: string;
  source: string;
  createdAt?: string;
}
