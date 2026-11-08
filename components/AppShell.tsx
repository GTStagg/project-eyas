"use client";

import { useState } from "react";
import Sidebar from "./Sidebar";
import IconRail from "./IconRail";
import TopBar from "./TopBar";
import Footer from "./Footer";
import ToastProvider from "./ToastProvider";
import ChatDockProvider from "./ChatDock";

export default function AppShell({
  title,
  right,
  children,
  fullBleed,
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  /** When true, children fill the viewport below the top bar (used by chat). */
  fullBleed?: boolean;
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <ToastProvider>
      <ChatDockProvider>
        <div
          className={`flex bg-neutral-950 text-neutral-100 ${
            fullBleed ? "h-screen" : "min-h-screen"
          }`}
        >
          {/* Persistent desktop rail (md+); mobile falls back to the drawer. */}
          <IconRail />
          {/* Mobile drawer — opened from the TopBar toggle below md. */}
          <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

          <div className="flex min-w-0 flex-1 flex-col">
            <TopBar
              sidebarOpen={sidebarOpen}
              onMenuClick={() => setSidebarOpen((o) => !o)}
              title={title}
              right={right}
            />
            {children}
            {!fullBleed && <Footer />}
          </div>
        </div>
      </ChatDockProvider>
    </ToastProvider>
  );
}
