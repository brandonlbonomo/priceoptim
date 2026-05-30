"use client";

import { useEffect, useState } from "react";
import { List } from "lucide-react";

interface TOCItem {
  id: string;
  text: string;
  level: number;
}

interface TableOfContentsProps {
  html: string;
}

function extractHeadings(html: string): TOCItem[] {
  const headingRegex = /<h([23])[^>]*>(.*?)<\/h[23]>/gi;
  const items: TOCItem[] = [];
  let match;

  while ((match = headingRegex.exec(html)) !== null) {
    const level = parseInt(match[1]);
    const text = match[2].replace(/<[^>]+>/g, "").trim();
    const id = text
      .toLowerCase()
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-");
    items.push({ id, text, level });
  }

  return items;
}

export function TableOfContents({ html }: TableOfContentsProps) {
  const [activeId, setActiveId] = useState("");
  const headings = extractHeadings(html);

  useEffect(() => {
    // Add IDs to headings in the DOM
    const article = document.querySelector("article");
    if (!article) return;

    const domHeadings = article.querySelectorAll("h2, h3");
    domHeadings.forEach((heading) => {
      const text = heading.textContent?.trim() ?? "";
      const id = text
        .toLowerCase()
        .replace(/[^\w\s-]/g, "")
        .replace(/\s+/g, "-")
        .replace(/-+/g, "-");
      heading.id = id;
    });

    // Observe which heading is in view
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id);
          }
        });
      },
      { rootMargin: "-80px 0px -70% 0px" }
    );

    domHeadings.forEach((heading) => observer.observe(heading));
    return () => observer.disconnect();
  }, []);

  if (headings.length < 3) return null;

  return (
    <nav className="glass-card rounded-[20px] p-6" aria-label="Table of contents">
      <div className="flex items-center gap-2 text-[13px] font-semibold text-foreground">
        <List className="h-4 w-4 text-muted" />
        In This Article
      </div>
      <ol className="mt-4 space-y-2">
        {headings.map((heading) => (
          <li key={heading.id}>
            <a
              href={`#${heading.id}`}
              onClick={(e) => {
                e.preventDefault();
                document.getElementById(heading.id)?.scrollIntoView({ behavior: "smooth" });
              }}
              className={`block text-[13px] leading-relaxed transition-colors duration-200 ${
                heading.level === 3 ? "pl-4" : ""
              } ${
                activeId === heading.id
                  ? "font-medium text-accent-dark"
                  : "text-muted hover:text-foreground"
              }`}
            >
              {heading.text}
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}
