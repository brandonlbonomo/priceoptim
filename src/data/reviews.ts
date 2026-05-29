export interface Review {
  id: string;
  propertyId: string;
  guestName: string;
  rating: number;
  date: string;
  text: string;
}

// Replace these with your real Airbnb reviews.
// Copy the guest's first name, their review text, approximate date, and rating.
export const reviews: Review[] = [
  // ── Riverstone Retreat (unit-1 / 22B) ──
  {
    id: "r1-1",
    propertyId: "unit-1",
    guestName: "Sarah",
    rating: 5,
    date: "2025-03",
    text: "This place was perfect for our Niagara Falls trip! Super clean, well-stocked kitchen, and the location was great — just a few minutes from the State Park. Would definitely book again.",
  },
  {
    id: "r1-2",
    propertyId: "unit-1",
    guestName: "Marcus",
    rating: 5,
    date: "2025-04",
    text: "The Riverstone Retreat exceeded our expectations. Cozy, modern, and felt like home. The host was incredibly responsive and check-in was seamless. Highly recommend for families.",
  },
  {
    id: "r1-3",
    propertyId: "unit-1",
    guestName: "Jennifer",
    rating: 5,
    date: "2025-02",
    text: "Stayed here with my husband for a weekend getaway. Everything was spotless, the beds were comfortable, and we loved having a full kitchen. Will be back!",
  },

  // ── Niagara Falls Retreat 24B (unit-2) ──
  {
    id: "r2-1",
    propertyId: "unit-2",
    guestName: "David",
    rating: 5,
    date: "2025-04",
    text: "Great spot! Close to everything in Niagara Falls. The house was clean, modern, and had everything we needed. Host was super helpful with restaurant recommendations.",
  },
  {
    id: "r2-2",
    propertyId: "unit-2",
    guestName: "Emily",
    rating: 5,
    date: "2025-03",
    text: "We loved our stay here. The place was recently updated and it shows — everything felt new and fresh. Perfect for our family of four visiting the Falls.",
  },
  {
    id: "r2-3",
    propertyId: "unit-2",
    guestName: "Chris",
    rating: 5,
    date: "2025-01",
    text: "Excellent value for the location. Clean, comfortable, and the free parking was a huge plus. Would recommend to anyone visiting Niagara Falls.",
  },

  // ── The Gorge Getaway (unit-3 / 26B) ──
  {
    id: "r3-1",
    propertyId: "unit-3",
    guestName: "Amanda",
    rating: 5,
    date: "2025-05",
    text: "The Gorge Getaway was the perfect home base for exploring Niagara Falls. Two full bathrooms was a game-changer with kids. Very clean and well-maintained.",
  },
  {
    id: "r3-2",
    propertyId: "unit-3",
    guestName: "Robert",
    rating: 5,
    date: "2025-04",
    text: "Everything about this property was top-notch. The host was responsive, check-in was easy, and the place was exactly as described. We'll be back next summer.",
  },
  {
    id: "r3-3",
    propertyId: "unit-3",
    guestName: "Lisa",
    rating: 5,
    date: "2025-03",
    text: "Beautiful, updated home in a quiet neighborhood. We loved being so close to the falls without the tourist chaos. Kitchen had everything we needed to cook meals.",
  },

  // ── Luxury 3BR Houston (unit-4 / Everton) ──
  {
    id: "r4-1",
    propertyId: "unit-4",
    guestName: "Michael",
    rating: 5,
    date: "2025-05",
    text: "This house was incredible. The backyard alone was worth it — we grilled out every night. Walking distance to great restaurants in EaDo and a quick Uber to the Astros game.",
  },
  {
    id: "r4-2",
    propertyId: "unit-4",
    guestName: "Ashley",
    rating: 5,
    date: "2025-04",
    text: "Stayed here for a work trip with colleagues and it was perfect. Three bedrooms, two bathrooms, plenty of space. The neighborhood is vibrant and there's so much to do nearby.",
  },
  {
    id: "r4-3",
    propertyId: "unit-4",
    guestName: "James",
    rating: 5,
    date: "2025-03",
    text: "Best rental I've stayed in Houston. Modern, clean, and the host thought of everything. The private yard felt like a luxury. Minutes from Minute Maid Park.",
  },

  // ── EaDo Apt Unit 1 (unit-5) ──
  {
    id: "r5-1",
    propertyId: "unit-5",
    guestName: "Nicole",
    rating: 5,
    date: "2025-04",
    text: "Perfect little apartment for my solo trip to Houston. Clean, quiet, and the workspace was great for getting some remote work done. Loved the EaDo neighborhood.",
  },
  {
    id: "r5-2",
    propertyId: "unit-5",
    guestName: "Kevin",
    rating: 5,
    date: "2025-03",
    text: "Great location near the stadiums. We walked to the Toyota Center for a Rockets game. The apartment had everything we needed and the parking spot was a bonus.",
  },

  // ── Modern EaDo Apt Unit 2 (unit-6) ──
  {
    id: "r6-1",
    propertyId: "unit-6",
    guestName: "Sophia",
    rating: 5,
    date: "2025-05",
    text: "Such a cute, modern apartment. The design was beautiful and everything was spotless. Loved being near all the breweries in EaDo. Would stay again in a heartbeat.",
  },
  {
    id: "r6-2",
    propertyId: "unit-6",
    guestName: "Daniel",
    rating: 5,
    date: "2025-02",
    text: "Stayed here for a conference at the George R. Brown Convention Center. Super convenient location, comfortable bed, and the self check-in made late arrival easy.",
  },

  // ── Premium EaDo Apt Unit 3 (unit-7) ──
  {
    id: "r7-1",
    propertyId: "unit-7",
    guestName: "Rachel",
    rating: 5,
    date: "2025-04",
    text: "This apartment is a gem. Clean, stylish, and perfectly located in EaDo. The host was incredibly communicative and helpful. Already planning my next stay.",
  },
  {
    id: "r7-2",
    propertyId: "unit-7",
    guestName: "Brian",
    rating: 5,
    date: "2025-03",
    text: "Used this as a home base for an Astros series. Couldn't ask for a better location. The workspace was great for mornings and the neighborhood has amazing food options.",
  },

  // ── Stylish EaDo Apt Unit 4 (unit-8) ──
  {
    id: "r8-1",
    propertyId: "unit-8",
    guestName: "Taylor",
    rating: 5,
    date: "2025-05",
    text: "Fantastic stay! The apartment was exactly as pictured — bright, stylish, and comfortable. We ate at so many amazing restaurants within walking distance. Highly recommend.",
  },
  {
    id: "r8-2",
    propertyId: "unit-8",
    guestName: "Jordan",
    rating: 5,
    date: "2025-02",
    text: "Great value for the EaDo area. The apartment was clean, the parking was easy, and the host was responsive. Perfect for a weekend in Houston.",
  },
];

export function getAllReviews(): Review[] {
  return reviews;
}

export function getReviewsByProperty(propertyId: string): Review[] {
  return reviews.filter((r) => r.propertyId === propertyId);
}

export function getAverageRating(propertyId: string): number {
  const propertyReviews = getReviewsByProperty(propertyId);
  if (propertyReviews.length === 0) return 0;
  const sum = propertyReviews.reduce((acc, r) => acc + r.rating, 0);
  return Math.round((sum / propertyReviews.length) * 100) / 100;
}

export function getFeaturedReviews(count: number = 6): Review[] {
  return reviews.slice(0, count);
}
