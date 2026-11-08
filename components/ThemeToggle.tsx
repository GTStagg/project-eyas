"use client";

import { useEffect, useState } from "react";
import { Sun, Moon } from "lucide-react";

type Theme = "dark" | "light";
const STORAGE_KEY = "eyas-theme";

export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const current = (document.documentElement.getAttribute("data-theme") as Theme | null) ?? "dark";
    setTheme(current);
    setMounted(true);
  }, []);

  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // localStorage unavailable (private mode) — toggle still works in-session.
    }
  };

  // Render an inert placeholder pre-hydration so the topbar layout doesn't
  // shift; the pre-hydration script in layout.tsx has already set the icon
  // direction on <html>, so server render of either icon would be wrong
  // half the time.
  if (!mounted) {
    return <div className="hidden h-9 w-9 sm:block" aria-hidden="true" />;
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      className="hidden h-9 w-9 items-center justify-center rounded-md border border-neutral-800 bg-neutral-950/40 text-neutral-300 transition-[border-color,background-color,color] duration-150 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200 sm:flex"
    >
      {theme === "dark" ? <Sun className="h-4 w-4" strokeWidth={2} /> : <Moon className="h-4 w-4" strokeWidth={2} />}
    </button>
  );
}
