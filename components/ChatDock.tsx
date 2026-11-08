"use client";

// Global chat dock — a compact agent chat reachable from every page (the TopBar
// "Ask the agent" button opens it). One instance lives in AppShell, so any page
// can prompt the agent without navigating to the full chat at `/`.
//
// keepMounted keeps the ControlChatPanel alive while the dock is closed, so the
// transcript resumes on reopen (the persistent control-chat session).

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import SnackPanel from "./SnackPanel";
import { ControlChatPanel } from "./panels/ControlChatPanel";
import { fullChatFooter } from "./home/widgets";

type ChatDockApi = { open: () => void; close: () => void };

const Ctx = createContext<ChatDockApi | null>(null);

/** Open/close the global chat dock from anywhere under AppShell. No-ops if the
 *  provider isn't mounted (e.g. an isolated test render). */
export function useChatDock(): ChatDockApi {
  return useContext(Ctx) ?? { open() {}, close() {} };
}

export default function ChatDockProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);

  const api = useMemo<ChatDockApi>(
    () => ({ open: () => setOpen(true), close: () => setOpen(false) }),
    [],
  );
  const close = useCallback(() => setOpen(false), []);

  return (
    <Ctx.Provider value={api}>
      {children}
      <SnackPanel
        open={open}
        onClose={close}
        title="Ask the agent"
        subtitle="Full tool access · writes need approval"
        footer={fullChatFooter()}
        width="lg"
        keepMounted
      >
        <ControlChatPanel />
      </SnackPanel>
    </Ctx.Provider>
  );
}
