import type { Property } from "@/types/property";

export interface FAQItem {
  question: string;
  answer: string;
}

export function generatePropertyFAQs(property: Property): FAQItem[] {
  const faqs: FAQItem[] = [];

  // Check-in / Check-out
  faqs.push({
    question: `What are the check-in and check-out times at ${property.name}?`,
    answer: `Check-in is at ${property.checkIn} and check-out is at ${property.checkOut}. Self check-in with keyless entry is available for a smooth arrival.`,
  });

  // Guest count
  faqs.push({
    question: `How many guests can stay at ${property.name}?`,
    answer: `This property accommodates up to ${property.details.maxGuests} guests with ${property.details.bedrooms} ${property.details.bedrooms === 1 ? "bedroom" : "bedrooms"} and ${property.details.beds} ${property.details.beds === 1 ? "bed" : "beds"}.`,
  });

  // Parking
  const parkingAmenity = property.amenities.find(
    (a) => a.category === "parking"
  );
  if (parkingAmenity) {
    faqs.push({
      question: `Is parking available at ${property.name}?`,
      answer: `Yes, ${parkingAmenity.name.toLowerCase()} is included with your stay at no extra cost.`,
    });
  }

  // Pets
  const petFriendly = property.amenities.some(
    (a) => a.name.toLowerCase().includes("pet")
  );
  const petRule = property.houseRules.some(
    (r) => r.toLowerCase().includes("pets allowed")
  );
  faqs.push({
    question: `Are pets allowed at ${property.name}?`,
    answer: petFriendly || petRule
      ? "Yes, this property is pet-friendly. Please let us know in advance if you plan to bring a pet."
      : "Unfortunately, pets are not allowed at this property.",
  });

  // Kitchen
  const hasKitchen = property.amenities.some(
    (a) => a.name.toLowerCase().includes("kitchen")
  );
  if (hasKitchen) {
    const kitchenAmenities = property.amenities
      .filter((a) => a.category === "kitchen")
      .map((a) => a.name.toLowerCase());
    faqs.push({
      question: `Does ${property.name} have a kitchen?`,
      answer: `Yes, the property features a fully equipped kitchen with ${kitchenAmenities.join(", ")}. Everything you need to prepare meals during your stay.`,
    });
  }

  // WiFi
  const hasWifi = property.amenities.some(
    (a) => a.name.toLowerCase().includes("wifi")
  );
  if (hasWifi) {
    faqs.push({
      question: `Is WiFi available at ${property.name}?`,
      answer: "Yes, high-speed WiFi is included free of charge for all guests.",
    });
  }

  // Location / Attractions
  const { city, state, area } = property.location;
  if (city === "Niagara Falls") {
    faqs.push({
      question: `How far is ${property.name} from Niagara Falls State Park?`,
      answer: `${property.name} is located in ${area}, ${city}, ${state} — just a short drive from Niagara Falls State Park, Maid of the Mist, Cave of the Winds, and other popular attractions.`,
    });
  } else if (city === "Houston") {
    faqs.push({
      question: `How far is ${property.name} from Minute Maid Park?`,
      answer: `${property.name} is located in ${area}, ${city}, ${state} — just minutes from Minute Maid Park (Houston Astros), Toyota Center (Houston Rockets), and 713 Music Hall.`,
    });
  }

  // Booking
  faqs.push({
    question: `How do I book ${property.name}?`,
    answer: "You can book directly through our website for the best rates — no Airbnb or Vrbo service fees. Select your dates using the booking calendar on this page, and you'll receive instant confirmation.",
  });

  return faqs;
}
