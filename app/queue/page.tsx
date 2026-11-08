import AppShell from "@/components/AppShell";
import QueueClient from "@/components/QueueClient";
import TriagePanel from "@/components/TriagePanel";
import IrReadinessBanner from "@/components/IrReadinessBanner";
import { getRuntimeConfig } from "@/lib/config/runtime";

export const dynamic = "force-dynamic";

export default function QueuePage() {
  const irEnabled = Boolean(getRuntimeConfig().irQuarantineGroupId);

  return (
    <AppShell title="Queue">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <div className="eyebrow">Triage // Queue</div>
              <h1 className="mt-2 text-4xl font-bold tracking-tight text-white">
                Triage queue
              </h1>
              <p className="mt-2 max-w-2xl text-sm text-neutral-400">
                Open detections from the last 14 days, ranked by severity and
                host impact. <span className="font-mono text-oxblood-300">Triage</span>{" "}
                hands a detection to the agent;{" "}
                <span className="font-mono text-amber-300">IR</span> launches the
                response workflow on the host.
              </p>
            </div>
          </div>

          <div className="mt-6">
            {irEnabled && <IrReadinessBanner />}
            <TriagePanel
              eyebrow="Agent // Triage brief"
              title="Morning standup brief on the open queue."
              subtitle="Top priorities, safe-to-defer, tuning candidates, and cross-host campaigns."
              endpoint="/api/queue/brief"
              webhookSource="queue-brief"
              webhookTitlePrefix="Triage brief"
              emptyHintText="Top priorities, safe-to-defer, and tuning candidates."
            />
            <QueueClient irEnabled={irEnabled} />
          </div>
        </div>
      </main>
    </AppShell>
  );
}
