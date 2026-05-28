"use client";

import { useState } from "react";
import Image from "next/image";
import Lightbox from "yet-another-react-lightbox";
import "yet-another-react-lightbox/styles.css";

interface PhotoGalleryProps {
  images: string[];
  alt: string;
}

export function PhotoGallery({ images, alt }: PhotoGalleryProps) {
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const [lightboxIndex, setLightboxIndex] = useState(0);

  const openLightbox = (index: number) => {
    setLightboxIndex(index);
    setLightboxOpen(true);
  };

  return (
    <>
      <div className="grid gap-2 sm:grid-cols-4 sm:grid-rows-2">
        {/* Main image */}
        <button
          className="relative aspect-[4/3] overflow-hidden rounded-lg bg-gray-100 sm:col-span-2 sm:row-span-2"
          onClick={() => openLightbox(0)}
        >
          <Image
            src={images[0]}
            alt={alt}
            fill
            className="object-cover transition-opacity hover:opacity-90"
            priority
            sizes="(max-width: 768px) 100vw, 50vw"
            unoptimized
          />
        </button>

        {/* Thumbnails */}
        {images.slice(1, 5).map((image, index) => (
          <button
            key={image}
            className="relative hidden aspect-[4/3] overflow-hidden rounded-lg bg-gray-100 sm:block"
            onClick={() => openLightbox(index + 1)}
          >
            <Image
              src={image}
              alt={`${alt} - Photo ${index + 2}`}
              fill
              className="object-cover transition-opacity hover:opacity-90"
              sizes="25vw"
              unoptimized
            />
            {index === 3 && images.length > 5 && (
              <div className="absolute inset-0 flex items-center justify-center bg-black/40 text-white">
                <span className="text-lg font-semibold">+{images.length - 5} more</span>
              </div>
            )}
          </button>
        ))}
      </div>

      <Lightbox
        open={lightboxOpen}
        close={() => setLightboxOpen(false)}
        index={lightboxIndex}
        slides={images.map((src) => ({ src }))}
      />
    </>
  );
}
