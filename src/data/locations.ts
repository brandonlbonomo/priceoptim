export interface Location {
  slug: string;
  city: string;
  state: string;
  stateFullName: string;
  title: string;
  description: string;
  metaDescription: string;
  attractions: string[];
}

export const locations: Location[] = [
  {
    slug: "houston",
    city: "Houston",
    state: "TX",
    stateFullName: "Texas",
    title: "Vacation Rentals in Houston, TX",
    description:
      "Browse our curated collection of vacation rentals in Houston's East Downtown (EaDo) neighborhood. Stay minutes from Minute Maid Park, Toyota Center, 713 Music Hall, and Houston's best restaurants and breweries. Every property includes free parking, fast WiFi, a full kitchen, and keyless self check-in. Book direct and skip the platform fees.",
    metaDescription:
      "Book vacation rentals in Houston's EaDo neighborhood near Minute Maid Park, Toyota Center & 713 Music Hall. Free parking, full kitchen, WiFi. No Airbnb fees — book direct.",
    attractions: [
      "Minute Maid Park",
      "Toyota Center",
      "713 Music Hall",
      "POST Houston",
      "8th Wonder Brewery",
      "Discovery Green",
    ],
  },
  {
    slug: "niagara-falls",
    city: "Niagara Falls",
    state: "NY",
    stateFullName: "New York",
    title: "Vacation Rentals in Niagara Falls, NY",
    description:
      "Discover our cozy vacation rentals near Niagara Falls State Park. Each home offers the comfort and space of a full house — perfect for families, couples, and small groups visiting the Falls. Enjoy fully equipped kitchens, free parking, pet-friendly accommodations, and a quiet residential setting just minutes from Maid of the Mist, Cave of the Winds, and Seneca Niagara Casino. Book direct for the best rates.",
    metaDescription:
      "Book vacation rentals near Niagara Falls State Park in Niagara Falls, NY. Pet-friendly homes with full kitchens, free parking & WiFi. No platform fees — book direct.",
    attractions: [
      "Niagara Falls State Park",
      "Maid of the Mist",
      "Cave of the Winds",
      "Whirlpool State Park",
      "Seneca Niagara Casino",
      "Rainbow Bridge",
    ],
  },
];

export function getLocationBySlug(slug: string): Location | undefined {
  return locations.find((l) => l.slug === slug);
}
