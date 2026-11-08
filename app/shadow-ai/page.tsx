import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import { Sparkles } from "lucide-react";
import ShadowAiPanel from "@/components/ShadowAiPanel";
import GuardianActivityCard from "@/components/GuardianActivityCard";

export const dynamic = "force-dynamic";

export default function ShadowAiPage() {
  return (
    <AppShell title="AI">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up space-y-8">
          <PageHero
            icon={Sparkles}
            eyebrow="AI"
            title="Find unsanctioned generative-AI tooling across the fleet."
            subtitle="AI desktop apps, agent runtimes, and inference egress — per-host drill-in classifies each finding and hands off to chat for remediation."
          />
          <GuardianActivityCard />
          <ShadowAiPanel />
        </div>
      </main>
    </AppShell>
  );
}
