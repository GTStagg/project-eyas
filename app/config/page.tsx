import { Settings2 } from "lucide-react";
import AppShell from "@/components/AppShell";
import AnthropicConfigCard from "@/components/AnthropicConfigCard";
import AidrConfigCard from "@/components/AidrConfigCard";
import KnowledgeBaseCard from "@/components/KnowledgeBaseCard";
import EnvironmentsManager from "@/components/EnvironmentsManager";
import IrQuarantineSetupCard from "@/components/IrQuarantineSetupCard";
import ShadowAiBannedSetupCard from "@/components/ShadowAiBannedSetupCard";
import ShadowAiSetupCard from "@/components/ShadowAiSetupCard";
import AuditLogViewer from "@/components/AuditLogViewer";
import { getActiveEnvironmentId, listEnvironments } from "@/lib/config/environments";
import { readAuditLog } from "@/lib/config/store";

export const dynamic = "force-dynamic";

export default async function ConfigPage() {
  const [environments, audit] = await Promise.all([
    Promise.resolve(listEnvironments()),
    readAuditLog(200),
  ]);
  const activeId = getActiveEnvironmentId();
  const gatewayOnly = process.env.ANTHROPIC_GATEWAY_ONLY === "true";

  return (
    <AppShell title="Config">
      <main className="flex-1 px-6 py-12">
        <div className="mx-auto max-w-4xl animate-fade-in-up space-y-6">
          {/* Header */}
          <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
            <div className="flex items-start gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
                <Settings2 className="h-5 w-5" strokeWidth={1.75} />
              </div>
              <div className="flex-1">
                <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
                  Config
                </div>
                <h1 className="mt-1.5 text-3xl font-semibold tracking-tight text-white">
                  Tenant configuration
                </h1>
                <p className="mt-1.5 text-base text-neutral-400">
                  Credentials, tenant environments, and one-time provisioning
                  for the agentic surfaces (IR quarantine, Shadow-AI). All
                  changes are stored on this device and recorded in the
                  activity log below. Connection health and probe results
                  live on /status.
                </p>
              </div>
            </div>
          </div>

          {/* Anthropic */}
          <AnthropicConfigCard gatewayOnly={gatewayOnly} />

          {/* Environments */}
          <EnvironmentsManager initial={environments} initialActiveId={activeId} />

          {/* AI Guard (AIDR) — per-environment guardrails for chat */}
          <AidrConfigCard />

          {/* Knowledge base — per-environment reference documents for the agent */}
          <KnowledgeBaseCard />

          {/* IR quarantine setup */}
          <IrQuarantineSetupCard />

          {/* Shadow-AI Banned setup (host group + per-platform policies + precedence) */}
          <ShadowAiBannedSetupCard />

          {/* Shadow-AI rule-group binding (Custom IOA corpus authoring + policy attach) */}
          <ShadowAiSetupCard />

          {/* Audit log */}
          <AuditLogViewer initial={audit} />
        </div>
      </main>
    </AppShell>
  );
}
