interface FirecrawlLogoProps {
  className?: string;
  mode?: "light" | "dark";
  variant?: "icon" | "wordmark";
}

/**
 * Firecrawl placeholder logo, the official logo isn't in the elements
 * registry yet. This is a simple flame mark using the brand orange.
 * TODO: replace with official mark when @elements/firecrawl-logo lands.
 */
export function FirecrawlLogo({ className, mode = "light" }: FirecrawlLogoProps) {
  const color = mode === "dark" ? "#FF6A3D" : "#E5512B";
  return (
    <svg
      role="img"
      viewBox="0 0 32 32"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="Firecrawl"
    >
      <title>Firecrawl</title>
      <path
        fill={color}
        d="M16 2c-1 4-4 6-4 10 0 3 2 5 4 5s4-2 4-5c0-4-3-6-4-10zm-6 14c-2 2-3 4-3 7 0 5 4 7 9 7s9-2 9-7c0-3-1-5-3-7-1 3-3 4-6 4s-5-1-6-4z"
      />
    </svg>
  );
}
