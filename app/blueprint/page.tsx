import { DraftingCompass } from "lucide-react";
import AppShell from "@/components/AppShell";
import PageHero from "@/components/PageHero";
import BlueprintAdvisor from "@/components/BlueprintAdvisor";

export const dynamic = "force-dynamic";

export default function BlueprintPage() {
  return (
    <AppShell title="Blueprint">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-8">
          <PageHero
            icon={DraftingCompass}
            eyebrow="Reference · developer surface"
            title="Build your own agentic SOC."
            subtitle="How this console composes eyas-mcp, FalconPy, and Claude — so you can build the same shape in your own organization."
          />
          <BlueprintAdvisor />
        </div>
      </main>
    </AppShell>
  );
}
