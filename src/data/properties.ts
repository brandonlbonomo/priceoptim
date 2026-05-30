import { Property } from "@/types/property";

const WIDGET_ID = "a1e23bdb-9260-4616-a9ed-890372317719";

function buildImageArray(
  unit: string,
  airbnbCount: number,
  localCount: number,
  airbnbPngIndices: number[] = [],
  localPngIndices: number[] = [],
): string[] {
  const airbnb = Array.from({ length: airbnbCount }, (_, i) => {
    const ext = airbnbPngIndices.includes(i + 1) ? "png" : "jpg";
    return `/images/properties/${unit}/airbnb-${i + 1}.${ext}`;
  });
  const local = Array.from({ length: localCount }, (_, i) => {
    const ext = localPngIndices.includes(i + 1) ? "png" : "jpg";
    return `/images/properties/${unit}/${i + 1}.${ext}`;
  });
  return [...airbnb, ...local];
}

export const properties: Property[] = [
  {
    id: "unit-1",
    name: "Riverstone Retreat",
    slug: "niagara-riverstone-retreat",
    tagline: "Cozy 2-bedroom vacation rental near Niagara Falls State Park",
    description:
      "Stay in this cozy 2-bedroom Niagara Falls vacation rental, just minutes from Niagara Falls State Park. The Riverstone Retreat offers hotel-level comfort with the privacy of a full townhouse — ideal for families, couples, or small groups visiting Niagara Falls, New York. Walk to the Niagara Gorge Trail, explore Clifton Hill attractions, or visit Seneca Niagara Casino. Inside you'll find a fully equipped kitchen, fast Wi-Fi, in-unit washer and dryer, free parking, and fresh linens. Book direct with Experiences by BLB and skip the Airbnb fees.",
    location: {
      city: "Niagara Falls",
      state: "NY",
      area: "Niagara Falls State Park",
    },
    images: buildImageArray("unit-1", 0, 32),
    details: {
      bedrooms: 2,
      bathrooms: 2,
      maxGuests: 4,
      beds: 2,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Dryer", category: "essentials", icon: "Wind" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Free Parking", category: "parking", icon: "Car" },
      { name: "Pet Friendly", category: "essentials", icon: "Bed" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "First Aid Kit", category: "safety", icon: "Cross" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "Pets allowed",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292720",
    },
    featured: true,
    active: true,
  },
  {
    id: "unit-2",
    name: "Niagara Falls Retreat",
    slug: "niagara-falls-retreat",
    tagline: "Newly updated Niagara Falls home — walk to attractions",
    description:
      "This newly renovated 2-bedroom Niagara Falls vacation rental is perfect for families or couples looking for a comfortable home base. Located in a quiet residential neighborhood, you're just minutes from the Maid of the Mist, Cave of the Winds, Rainbow Bridge, and Niagara Falls State Park. The home features modern furnishings, a fully equipped kitchen, high-speed Wi-Fi, free parking, and a pet-friendly policy. Save on your next Niagara Falls trip by booking directly with Experiences by BLB — no platform fees, no middleman.",
    location: {
      city: "Niagara Falls",
      state: "NY",
      area: "Niagara Falls",
    },
    images: buildImageArray("unit-2", 8, 44, [], [1]),
    details: {
      bedrooms: 2,
      bathrooms: 1,
      maxGuests: 4,
      beds: 2,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Dryer", category: "essentials", icon: "Wind" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Free Parking", category: "parking", icon: "Car" },
      { name: "Pet Friendly", category: "essentials", icon: "Bed" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "Pets allowed",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292719",
    },
    featured: false,
    active: true,
  },
  {
    id: "unit-3",
    name: "The Gorge Getaway",
    slug: "niagara-gorge-getaway-26b",
    tagline: "2-bed, 2-bath Niagara Falls rental near State Park & casinos",
    description:
      "The Gorge Getaway is a freshly updated 2-bedroom, 2-bathroom vacation home in Niagara Falls, New York. Perfect for families visiting Niagara Falls State Park, Whirlpool State Park, and the Niagara Gorge Discovery Center. This clean, modern space offers a full kitchen, laundry, fast Wi-Fi, free parking, and a quiet neighborhood setting — all within a short drive of Clifton Hill, Seneca Niagara Casino, and the Outlet Collection at Niagara. Book your Niagara Falls vacation rental directly with Experiences by BLB for the best rate guaranteed.",
    location: {
      city: "Niagara Falls",
      state: "NY",
      area: "Niagara Falls",
    },
    images: buildImageArray("unit-3", 8, 27),
    details: {
      bedrooms: 2,
      bathrooms: 2,
      maxGuests: 4,
      beds: 2,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Dryer", category: "essentials", icon: "Wind" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Free Parking", category: "parking", icon: "Car" },
      { name: "Pet Friendly", category: "essentials", icon: "Bed" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "Pets allowed",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292715",
    },
    featured: true,
    active: true,
  },
  {
    id: "unit-4",
    name: "Luxury 3BR Home | Private Yard | Near Stadiums",
    slug: "houston-everton-luxury-3br",
    tagline: "Spacious Houston vacation rental in EaDo with private backyard",
    description:
      "This luxury 3-bedroom Houston vacation rental sits in the heart of EaDo (East Downtown), Houston's most vibrant neighborhood for dining, sports, and nightlife. You're minutes from Minute Maid Park (home of the Houston Astros), Toyota Center (Houston Rockets), and 713 Music Hall. The home features a private fenced backyard, modern renovated interiors, a fully equipped kitchen with dishwasher, in-unit laundry, dedicated parking, and keyless self check-in. Ideal for families, groups attending Houston Astros games, or anyone seeking a full-house experience near downtown Houston. Book direct with Experiences by BLB and pay less than Airbnb or Vrbo.",
    location: {
      city: "Houston",
      state: "TX",
      area: "EaDo (East Downtown)",
    },
    images: buildImageArray("unit-4", 8, 55, [4], [1, 2]),
    details: {
      bedrooms: 3,
      bathrooms: 2,
      maxGuests: 7,
      beds: 4,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Dryer", category: "essentials", icon: "Wind" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "Dishwasher", category: "kitchen", icon: "Droplets" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Private Backyard", category: "outdoor", icon: "TreePalm" },
      { name: "Self Check-in", category: "essentials", icon: "ShieldCheck" },
      { name: "Dedicated Parking", category: "parking", icon: "Car" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "First Aid Kit", category: "safety", icon: "Cross" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
      "Self check-in with lockbox",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292721",
    },
    featured: true,
    active: true,
  },
  {
    id: "unit-5",
    name: "Premium EaDo Apartment | Stadiums & Downtown",
    slug: "houston-lockwood-unit-1",
    tagline: "Upscale Houston short-term rental for business or leisure",
    description:
      "A premium 1-bedroom apartment in Houston's EaDo district — perfect for corporate travelers, remote workers, or couples visiting downtown Houston. Located on Lockwood Drive, this urban retreat is a short drive from Minute Maid Park (Houston Astros), Toyota Center (Houston Rockets), and the Theater District. Features include a dedicated workspace with ergonomic setup, full kitchen, high-speed WiFi, secure parking, in-unit laundry, and contactless self check-in. Pet-friendly and ideal for extended stays in Houston's East Downtown. Book direct with Experiences by BLB for rates lower than Airbnb.",
    location: {
      city: "Houston",
      state: "TX",
      area: "EaDo (East Downtown)",
    },
    images: buildImageArray("unit-5", 8, 37, [], [1, 2, 3, 4]),
    details: {
      bedrooms: 1,
      bathrooms: 1,
      maxGuests: 2,
      beds: 1,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Dryer", category: "essentials", icon: "Wind" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "Dedicated Workspace", category: "essentials", icon: "Tv" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Self Check-in", category: "essentials", icon: "ShieldCheck" },
      { name: "Dedicated Parking", category: "parking", icon: "Car" },
      { name: "Pet Friendly", category: "essentials", icon: "Bed" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "Pets allowed",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292716",
    },
    featured: true,
    active: true,
  },
  {
    id: "unit-6",
    name: "Modern EaDo Apartment | Downtown Houston",
    slug: "houston-lockwood-unit-2",
    tagline: "Bright, contemporary short-term rental near downtown Houston",
    description:
      "This bright, modern 1-bedroom Houston vacation rental is perfect for solo travelers or couples visiting East Downtown. Situated in the heart of EaDo on Lockwood Drive, you're a short walk or ride from Minute Maid Park, Discovery Green, the George R. Brown Convention Center, and Houston's thriving brewery district including 8th Wonder Brewery and True Anomaly Brewing. The apartment features contemporary design, a full kitchen, dedicated workspace, self check-in, and one parking spot. Skip the hotel and experience Houston like a local — book direct with Experiences by BLB.",
    location: {
      city: "Houston",
      state: "TX",
      area: "EaDo (East Downtown)",
    },
    images: buildImageArray("unit-6", 8, 34, [3], [1, 2]),
    details: {
      bedrooms: 1,
      bathrooms: 1,
      maxGuests: 2,
      beds: 1,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "Dedicated Workspace", category: "essentials", icon: "Tv" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Self Check-in", category: "essentials", icon: "ShieldCheck" },
      { name: "Dedicated Parking", category: "parking", icon: "Car" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "No pets",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292713",
    },
    featured: false,
    active: true,
  },
  {
    id: "unit-7",
    name: "Stylish EaDo Apt | Restaurants, Stadiums, Venues",
    slug: "houston-lockwood-unit-3",
    tagline: "Walkable East Downtown Houston vacation rental",
    description:
      "This stylish 1-bedroom vacation rental is in the heart of walkable East Downtown Houston. Perfectly positioned near Navigation Esplanade, you're steps from some of Houston's best restaurants, including Original Ninfa's on Navigation, El Tiempo Cantina, and local favorites along the Navigation Boulevard corridor. Minute Maid Park, Toyota Center, and 713 Music Hall are all a short ride away. The apartment features bright interiors, a fully stocked kitchen, workspace, fast WiFi, and free parking. Ideal for weekend getaways, Houston Astros game days, or business trips. Book direct with Experiences by BLB — always cheaper than Airbnb.",
    location: {
      city: "Houston",
      state: "TX",
      area: "EaDo (East Downtown)",
    },
    images: buildImageArray("unit-7", 8, 33, [], [1, 2]),
    details: {
      bedrooms: 1,
      bathrooms: 1,
      maxGuests: 2,
      beds: 1,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "Dedicated Workspace", category: "essentials", icon: "Tv" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Self Check-in", category: "essentials", icon: "ShieldCheck" },
      { name: "Secure Parking", category: "parking", icon: "Car" },
      { name: "Pet Friendly", category: "essentials", icon: "Bed" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "Pets allowed",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292717",
    },
    featured: false,
    active: true,
  },
  {
    id: "unit-8",
    name: "EaDo Apt | Near Minute Maid Park & Toyota Center",
    slug: "houston-lockwood-unit-4",
    tagline: "Modern Houston apartment in walkable East Downtown",
    description:
      "A modern 1-bedroom apartment in Houston's EaDo district, steps from Minute Maid Park, Toyota Center, and BBVA Stadium. This vacation rental is ideal for business travelers needing a dedicated workspace, couples exploring Houston's East Downtown restaurant scene, or fans attending Astros, Rockets, or Dynamo games. Features include a fully equipped kitchen, in-unit washer/dryer, high-speed Wi-Fi, dedicated parking, and pet-friendly accommodations. Located on Lockwood Drive near Navigation Boulevard — the epicenter of Houston's best taquerias, breweries, and live music. Book direct with Experiences by BLB.",
    location: {
      city: "Houston",
      state: "TX",
      area: "EaDo (East Downtown)",
    },
    images: buildImageArray("unit-8", 8, 34, [3], [1, 2]),
    details: {
      bedrooms: 1,
      bathrooms: 1,
      maxGuests: 2,
      beds: 1,
    },
    amenities: [
      { name: "WiFi", category: "essentials", icon: "Wifi" },
      { name: "Air Conditioning", category: "essentials", icon: "AirVent" },
      { name: "Heating", category: "essentials", icon: "Flame" },
      { name: "Washer", category: "essentials", icon: "WashingMachine" },
      { name: "Full Kitchen", category: "kitchen", icon: "CookingPot" },
      { name: "Coffee Maker", category: "kitchen", icon: "Coffee" },
      { name: "Dedicated Workspace", category: "essentials", icon: "Tv" },
      { name: "TV", category: "entertainment", icon: "Tv" },
      { name: "Streaming Services", category: "entertainment", icon: "Play" },
      { name: "Self Check-in", category: "essentials", icon: "ShieldCheck" },
      { name: "Free Parking", category: "parking", icon: "Car" },
      { name: "Smoke Detector", category: "safety", icon: "ShieldCheck" },
      { name: "Fresh Towels", category: "bathroom", icon: "Bath" },
      { name: "Linens Provided", category: "bedroom", icon: "Bed" },
    ],
    houseRules: [
      "No smoking",
      "No pets",
      "No parties or events",
      "Quiet hours: 10 PM – 8 AM",
    ],
    checkIn: "4:00 PM",
    checkOut: "10:00 AM",
    hospitable: {
      widgetId: WIDGET_ID,
      propertyId: "2292714",
    },
    featured: false,
    active: true,
  },
];

export function getPropertyBySlug(slug: string): Property | undefined {
  return properties.find((p) => p.slug === slug);
}

export function getFeaturedProperties(): Property[] {
  return properties.filter((p) => p.featured && p.active);
}

export function getActiveProperties(): Property[] {
  return properties.filter((p) => p.active);
}

export function getPropertiesByCity(city: string): Property[] {
  return properties.filter(
    (p) => p.active && p.location.city.toLowerCase() === city.toLowerCase()
  );
}
