import AppShell from "@/components/AppShell";
import HostIRPanel from "@/components/HostIRPanel";
import IrReadinessBanner from "@/components/IrReadinessBanner";
import AtRiskHostsPanel from "@/components/AtRiskHostsPanel";
import ContainedHostsPanel from "@/components/ContainedHostsPanel";
import HostSearchPanel from "@/components/HostSearchPanel";
import HostsTablePanel from "@/components/HostsTablePanel";
import HostGroupsPosturePanel from "@/components/HostGroupsPosturePanel";
import { getRuntimeConfig } from "@/lib/config/runtime";

export const dynamic = "force-dynamic";

export default function HostsPage() {
  const irEnabled = Boolean(getRuntimeConfig().irQuarantineGroupId);

  return (
    <AppShell title="Hosts">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <div className="eyebrow">Discover // Hosts</div>
              <h1 className="mt-2 text-4xl font-bold tracking-tight text-white">
                Hosts
              </h1>
            </div>
            <span className="font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400">
              search · act · browse
            </span>
          </div>

          <div className="mt-6">
            <IrReadinessBanner />
            <HostSearchPanel irEnabled={irEnabled} />
            <HostIRPanel quarantineConfigured={irEnabled} />
            <AtRiskHostsPanel irEnabled={irEnabled} />
            <ContainedHostsPanel irEnabled={irEnabled} />
            <HostGroupsPosturePanel />
            <HostsTablePanel />
          </div>
        </div>
      </main>
    </AppShell>
  );
}
