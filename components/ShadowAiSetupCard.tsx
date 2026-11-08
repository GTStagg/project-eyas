"use client";

import { useEffect, useState } from "react";
import { Shield, AlertTriangle, CheckCircle2, RefreshCw } from "lucide-react";
import { buildPrimerHref } from "@/components/primerHandoff";

type BoundPolicy = {
  id: string;
  name: string;
  platform: string;
  enabled: boolean;
};

type RuleGroupState = {
  exists: boolean;
  id: string | null;
  name: string | null;
  enabled: boolean | null;
  installed: string[];
  installedCount: number;
  missing: string[];
  corpusCount: number;
};

type SetupResp = {
  ok: boolean;
  configured: boolean;
  bannedGroupId: string | null;
  ruleGroup: RuleGroupState | null;
  boundPolicies: BoundPolicy[];
  note?: string;
  error?: string;
};

function buildAdoptPrimer(
  bannedGroupId: string,
  policy: BoundPolicy,
  ruleGroupExists: boolean,
  missingCount: number,
): string {
  const action = ruleGroupExists
    ? `append the ${missingCount} missing rule${missingCount === 1 ? "" : "s"}`
    : "create the rule group and install all 11 rules";
  const comment = ruleGroupExists
    ? `Eyas: append missing Shadow-AI rules to existing rule group`
    : `Eyas: initial Shadow-AI rule group adoption`;
  return `Adopt the Shadow-AI Custom IOA rule bundle on prevention policy \`${policy.name}\` (id \`${policy.id}\`, platform ${policy.platform}, bound to host group \`${bannedGroupId}\`). Call extras_shadow_ai_adopt_prevention with prevention_policy_id="${policy.id}", comment="${comment}", mode="detect" — this will ${action}. Then verify with extras_shadow_ai_prevention_status.`;
}

export default function ShadowAiSetupCard() {
  const [data, setData] = useState<SetupResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/shadow-ai/setup", { cache: "no-store" });
      const j = (await r.json()) as SetupResp;
      if (!j.ok) throw new Error(j.error ?? "request failed");
      setData(j);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  if (loading && !data) {
    return (
      <section className="rounded-lg border border-neutral-800 bg-neutral-950/60 p-5">
        <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-500">
          Loading prevention adoption status…
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="rounded-lg border border-red-900/60 bg-red-950/30 p-5">
        <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-red-300">
          <AlertTriangle className="h-3.5 w-3.5" strokeWidth={1.75} />
          Setup probe failed
        </div>
        <div className="mt-2 text-sm text-red-200">{error}</div>
      </section>
    );
  }

  if (!data) return null;

  // Banned host group not configured — point operator at /config.
  if (!data.configured) {
    return (
      <section className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-5">
        <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-amber-300">
          <AlertTriangle className="h-3.5 w-3.5" strokeWidth={1.75} />
          Banned host group not configured
        </div>
        <p className="mt-2 max-w-3xl text-sm text-neutral-300">
          {data.note ??
            'Set the "Shadow-AI banned host group" field on the active environment in /config before adopting Shadow-AI prevention.'}
        </p>
      </section>
    );
  }

  const rg = data.ruleGroup;
  const boundPolicies = data.boundPolicies;
  const allInstalled =
    rg?.exists &&
    rg.missing.length === 0 &&
    rg.installedCount === rg.corpusCount;

  // No prevention policy bound to the host group yet — adoption can't
  // run because there's no policy to bind the rule group to.
  if (boundPolicies.length === 0) {
    return (
      <section className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-5">
        <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-amber-300">
          <AlertTriangle className="h-3.5 w-3.5" strokeWidth={1.75} />
          No prevention policy bound to banned host group
        </div>
        <p className="mt-2 max-w-3xl text-sm text-neutral-300">
          Host group <code className="rounded bg-neutral-900 px-1 py-0.5 font-mono text-xs text-neutral-200">{data.bannedGroupId}</code> is not currently bound to any prevention policy. Bind the host group to a Shadow-AI prevention policy in Falcon Console first — adoption needs a policy to attach the rule group to.
        </p>
      </section>
    );
  }

  // Multiple bound policies — operator picks. Cross-platform deployments
  // (Win + Mac + Linux) typically have one Shadow-AI policy per platform.
  // Today the rule corpus is Windows-only; offer the Windows policy and
  // disable the others with a "future" note.
  const windowsPolicies = boundPolicies.filter(
    (p) => p.platform.toLowerCase() === "windows",
  );
  const otherPolicies = boundPolicies.filter(
    (p) => p.platform.toLowerCase() !== "windows",
  );

  return (
    <section className="rounded-lg border border-orange-900/60 bg-gradient-to-br from-orange-950/30 via-neutral-950 to-neutral-950 p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-orange-900/60 bg-orange-950/40 text-orange-300">
            <Shield className="h-4 w-4" strokeWidth={1.75} />
          </div>
          <div>
            <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-orange-300">
              Prevention adoption
            </div>
            <div className="mt-0.5 text-base font-semibold text-white">
              {allInstalled
                ? "All Shadow-AI rules installed."
                : rg?.exists
                  ? `${rg.installedCount}/${rg.corpusCount} Shadow-AI rules installed.`
                  : `Shadow-AI rule group not yet authored — ${rg?.corpusCount ?? 11} rules to install.`}
            </div>
            <div className="mt-1 text-xs text-neutral-400">
              Banned host group: <code className="rounded bg-neutral-900 px-1 py-0.5 font-mono text-[10px] text-neutral-200">{data.bannedGroupId}</code>
              {" → "}
              bound to{" "}
              <span className="text-neutral-200">
                {boundPolicies.map((p) => p.name).join(", ")}
              </span>
              .
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          className="flex h-7 items-center gap-1 rounded border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] uppercase tracking-[0.12em] text-neutral-400 transition hover:bg-neutral-900 hover:text-neutral-200"
        >
          <RefreshCw className="h-3 w-3" strokeWidth={1.75} />
          Refresh
        </button>
      </div>

      {allInstalled ? (
        <div className="mt-4 flex items-center gap-2 rounded-md border border-emerald-900/60 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200">
          <CheckCircle2 className="h-3.5 w-3.5" strokeWidth={1.75} />
          All {rg!.corpusCount} rules installed and bound. No setup action needed.
        </div>
      ) : (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {windowsPolicies.map((p) => (
            <a
              key={p.id}
              href={buildPrimerHref(
                buildAdoptPrimer(
                  data.bannedGroupId!,
                  p,
                  rg?.exists ?? false,
                  rg?.missing.length ?? 0,
                ),
              )}
              title={`Adopt rule group on ${p.name}. Each rule create is approval-gated by the agent loop.`}
              className="flex h-8 items-center gap-1.5 rounded-md border border-orange-900/60 bg-orange-950/40 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-orange-200 transition hover:bg-orange-900/40 hover:text-white"
            >
              <Shield className="h-3 w-3" strokeWidth={1.75} />
              {rg?.exists ? "Append missing rules" : "Adopt rules"} → {p.name}
            </a>
          ))}
          {otherPolicies.map((p) => (
            <span
              key={p.id}
              title="The Shadow-AI rule corpus is currently Windows-only. Mac/Linux policies will be supported when the catalog adds non-Windows rules."
              className="flex h-8 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950/60 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-600"
            >
              <Shield className="h-3 w-3" strokeWidth={1.75} />
              {p.name} ({p.platform}) — corpus Windows-only
            </span>
          ))}
        </div>
      )}

      {rg?.exists && rg.missing.length > 0 && (
        <div className="mt-3 text-xs text-neutral-500">
          Missing: <span className="text-neutral-300">{rg.missing.join(", ")}</span>
        </div>
      )}
    </section>
  );
}
