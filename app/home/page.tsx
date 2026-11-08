import AppShell from "@/components/AppShell";
import ControlCenterHeader from "@/components/home/ControlCenterHeader";
import HomeDashboard from "@/components/HomeDashboard";
import { getActiveEnvironment } from "@/lib/config/environments";
import { getRuntimeConfig } from "@/lib/config/runtime";

export const dynamic = "force-dynamic";

// Operator dashboard — the post-login landing. Composes the existing
// deterministic fetchers (at-risk hosts, contained, scorecard, prevention
// posture, cost) into bite-sized insight cards. Each actionable card hands off
// to the agent through the standard primer mechanism (buildPrimerHref), so the
// dashboard surfaces the finding and the agent refines / corrects it.
export default function HomePage() {
  const irEnabled = Boolean(getRuntimeConfig().irQuarantineGroupId);
  const envName = getActiveEnvironment().name;

  return (
    <AppShell title="Home">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <ControlCenterHeader envName={envName} />
          <HomeDashboard irEnabled={irEnabled} />
        </div>
      </main>
    </AppShell>
  );
}
