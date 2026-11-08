import "./globals.css";
import type { Metadata } from "next";
import localFont from "next/font/local";

// Self-hosted to keep the build hermetic: next/font/google fetches from
// Google's CDN at build time, which the corporate TLS-intercepting proxy
// breaks (UNABLE_TO_GET_ISSUER_CERT_LOCALLY). These are the variable woff2
// files (full weight axis), latin subset — matching the prior Google pins.
const interTight = localFont({
  src: "./fonts/inter-tight-latin-wght-normal.woff2",
  variable: "--font-inter-tight",
  display: "swap",
  weight: "400 800",
});

const jetbrainsMono = localFont({
  src: "./fonts/jetbrains-mono-latin-wght-normal.woff2",
  variable: "--font-jetbrains-mono",
  display: "swap",
  weight: "400 700",
});

export const metadata: Metadata = {
  title: "Eyas · Agentic Console for CrowdStrike Falcon",
  description:
    "Eyas. An unofficial agentic console for the CrowdStrike falcon-mcp server. Not an official CrowdStrike product.",
};

// Pre-hydration script — reads the persisted theme and stamps data-theme on
// <html> before paint. Without this, every load flashes dark before React
// hydrates and applies the user's choice. Inlined as a string so it runs
// synchronously in document <head>.
const themeBootstrap = `(function(){try{var t=localStorage.getItem("eyas-theme");if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t);}else{document.documentElement.setAttribute("data-theme","dark");}}catch(e){document.documentElement.setAttribute("data-theme","dark");}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${interTight.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className="min-h-screen bg-neutral-950 text-neutral-100 antialiased">
        <div className="atmosphere" aria-hidden="true" />
        <div className="dot-grid" aria-hidden="true" />
        <div className="grain" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}
