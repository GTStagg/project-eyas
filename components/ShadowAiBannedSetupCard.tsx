"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Sparkles,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { buildPrimerHref } from "@/components/primerHandoff";

// Sister card to IrQuarantineSetupCard. Same per-state CTA pattern, same
// chat-primer hand-off, same "managed by Eyas" / "shared with
// other groups" badges. Reads from /api/shadow-ai-banned/diagnose.

type Diagnostic = {
  ok: boolean;
  case?:
    | "no_group_id"
    | "group_missing"
    | "A_no_policy"
    | "B_dedicated_single_group"
    | "C_shared_policy"
    | "rules_incomplete"
    | "ready";
  host_group_id?: string | null;
  host_group?: { id: string; name: string; group_type: string } | null;
  policies?: Array<{
    id: string;
    name: string;
    platform: string;
    enabled: boolean;
    is_dedicated: boolean;
    managed_by_eyas: boolean;
    rule_group_bound: boolean;
    rules_in_group?: number;
    rules_expected?: number;
    rules_missing?: string[];
  }>;
  rule_group_attached?: boolean;
  recommended_action?: {
    tool: string;
    args: Record<string, unknown>;
    label: string;
    description: string;
    follow_up_tool_calls?: Array<{
      tool: string;
      args: Record<string, unknown>;
      platform: string;
      missing_rules?: string[];
    }>;
  } | null;
  error?: string;
};

const CASE_PILL: Record<NonNullable<Diagnostic["case"]>, { label: string; cls: string }> = {
  no_group_id: { label: "Not configured", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
  group_missing: { label: "Group missing", cls: "border-red-800/60 bg-red-950/30 text-oxblood-200" },
  A_no_policy: { label: "Group only — no policy", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
  B_dedicated_single_group: { label: "Adopt + standardize", cls: "border-sky-800/60 bg-sky-950/30 text-sky-200" },
  C_shared_policy: { label: "Shared policy — needs dedicated", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
  rules_incomplete: { label: "Rule corpus incomplete", cls: "border-amber-800/60 bg-amber-950/30 text-amber-200" },
  ready: { label: "Ready", cls: "border-emerald-800/60 bg-emerald-950/30 text-emerald-200" },
};

export default function ShadowAiBannedSetupCard() {
  const [state, setState] = useState<{ status: "loading" | "ok" | "error"; data?: Diagnostic; err?: string }>({
    status: "loading",
  });
  const router = useRouter();

  async function load() {
    setState({ status: "loading" });
    try {
      const r = await fetch("/api/shadow-ai-banned/diagnose");
      const data = (await r.json()) as Diagnostic;
      if (!r.ok || data.error) {
        setState({ status: "error", err: data.error || `HTTP ${r.status}` });
        return;
      }
      setState({ status: "ok", data });
    } catch (err) {
      setState({ status: "error", err: err instanceof Error ? err.message : String(err) });
    }
  }

  useEffect(() => {
    load();
  }, []);

  function fireRecommendation() {
    if (state.status !== "ok" || !state.data?.recommended_action) return;
    const a = state.data.recommended_action;
    let primer: string;
    if (a.tool === "extras_create_shadow_ai_banned_host_group") {
      const name = (a.args.name as string) || "Project Eyas - Shadow-AI Banned";
      primer =
        `Create the Shadow-AI Banned host group on this tenant. Call ` +
        `extras_create_shadow_ai_banned_host_group with name="${name}". The new group id is saved to the active environment automatically. Then continue straight on with extras_provision_shadow_ai_banned_policy using that host_group_id (no manual /config step needed).`;
    } else if (a.tool === "extras_provision_shadow_ai_banned_policy") {
      const groupId = a.args.host_group_id as string;
      const mode = (a.args.mode as string) || "adopt";
      primer =
        `Provision the Shadow-AI Banned prevention policies on this tenant. Call ` +
        `extras_provision_shadow_ai_banned_policy with host_group_id="${groupId}" and mode="${mode}". ` +
        `Per platform (Windows, macOS, Linux), this ${mode === "create_dedicated" ? "creates dedicated policies" : "adopts the existing single-group policy or attaches a fresh canonical one"}, ` +
        `pushes AGGRESSIVE sliders + enabled toggles, and sets precedence above standard / below IR Quarantine. ` +
        `Then for each follow_up_tool_call returned, fire extras_shadow_ai_adopt_prevention with those args (separate approval) so the Shadow-AI rule group is authored and bound to the new policies.`;
    } else if (a.tool === "extras_shadow_ai_adopt_prevention" && a.follow_up_tool_calls?.length) {
      // Rule corpus refresh — multi-call. Fire one extras_shadow_ai_adopt_prevention
      // per affected platform.
      const callList = a.follow_up_tool_calls
        .map((c) =>
          `extras_shadow_ai_adopt_prevention with prevention_policy_id="${c.args.prevention_policy_id}", ` +
          `platform="${c.args.platform}", mode="${c.args.mode || "block"}", comment="${c.args.comment}"`,
        )
        .join("; ");
      primer =
        `Refresh the Shadow-AI rule corpus on this tenant — some rules from the per-platform corpus aren't in the rule groups (the previous adoption run authored a partial set). Fire each of these calls (separate approvals): ${callList}. The tool is idempotent — already-present rules dedupe by name; only the missing rules will be authored.`;
    } else {
      return;
    }
    router.push(buildPrimerHref(primer));
  }

  return (
    <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
            <Sparkles className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">Shadow-AI Banned setup</h2>
            <p className="mt-1 max-w-xl text-sm text-neutral-400">
              Default-allow tenant: AI tooling is permitted everywhere unless
              an operator drops a host into the Shadow-AI Banned group. This
              card stands up the host group, three platform-specific
              prevention policies, and the Shadow-AI Custom IOA rule group
              that fires on banned hosts. Posture stays untouched on
              non-banned hosts; precedence ensures the banned policy wins
              when applied.
            </p>
          </div>
        </div>
        {state.status === "ok" && state.data?.case && (
          <span
            className={`shrink-0 inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide ${CASE_PILL[state.data.case].cls}`}
          >
            {state.data.case === "ready" ? (
              <ShieldCheck className="h-3 w-3" strokeWidth={2} />
            ) : (
              <AlertTriangle className="h-3 w-3" strokeWidth={2} />
            )}
            {CASE_PILL[state.data.case].label}
          </span>
        )}
      </div>

      <div className="mt-5">
        {state.status === "loading" && (
          <div className="flex items-center gap-2 text-sm text-neutral-500">
            <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2} />
            Checking tenant state…
          </div>
        )}

        {state.status === "error" && (
          <div className="rounded-md border border-red-800/60 bg-red-950/30 px-3.5 py-3 text-sm text-oxblood-200">
            <div className="font-semibold">Couldn't read tenant state.</div>
            <div className="mt-0.5 font-mono text-[12px] opacity-80">{state.err}</div>
            <button
              type="button"
              onClick={load}
              className="mt-3 inline-flex items-center gap-1.5 rounded border border-red-800/60 bg-red-950/40 px-3 py-1 font-mono text-[11px] uppercase tracking-wide hover:border-red-700"
            >
              <RefreshCw className="h-3 w-3" strokeWidth={2} />
              Retry
            </button>
          </div>
        )}

        {state.status === "ok" && state.data && <Body data={state.data} onRefresh={load} onAction={fireRecommendation} />}
      </div>
    </section>
  );
}

function Body({ data, onRefresh, onAction }: { data: Diagnostic; onRefresh: () => void; onAction: () => void }) {
  const action = data.recommended_action;
  // Always render the apply/clear surface. Operators sometimes land on a
  // wrong id (e.g. carried over from another env, or auto-saved against the
  // wrong setup card) and previously had no way to fix it from /config.
  const showApply = true;
  return (
    <div className="space-y-4">
      {data.host_group ? (
        <KvBlock>
          <Kv label="Host group" value={`${data.host_group.name} (${data.host_group.group_type})`} />
          <Kv label="Group id" value={data.host_group.id} mono />
        </KvBlock>
      ) : (
        <div className="rounded border border-dashed border-neutral-800 bg-neutral-950/50 px-3.5 py-3 text-sm text-neutral-400">
          No Shadow-AI Banned host group is set on the active environment. Adopt an existing one by name below, paste its id, or click the action further down to create one with the canonical naming.
        </div>
      )}

      {showApply && (
        <>
          <AdoptGroupByName
            defaultName="Project Eyas - Shadow-AI Banned"
            endpoint="/api/shadow-ai-banned/adopt"
            onSaved={onRefresh}
          />
          <ApplyGroupId
            label="Or paste the Shadow-AI Banned group id"
            placeholder="e.g. 9f4c…"
            endpoint="/api/environments/active/shadow-ai-banned-group"
            onSaved={onRefresh}
          />
        </>
      )}

      {data.policies && data.policies.length > 0 && (
        <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3.5 py-3">
          <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-neutral-500">
            Prevention policies attached
          </div>
          <ul className="space-y-2 text-sm">
            {data.policies.map((p) => (
              <li key={p.id} className="flex flex-wrap items-baseline gap-2">
                <span className="rounded bg-neutral-900/60 px-1.5 py-0.5 font-mono text-[10px] uppercase text-neutral-400">
                  {p.platform}
                </span>
                <span className="text-neutral-200">{p.name}</span>
                {p.managed_by_eyas && (
                  <span className="rounded border border-emerald-800/60 bg-emerald-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-emerald-200">
                    managed by Eyas
                  </span>
                )}
                {p.rule_group_bound && (
                  <span className="rounded border border-emerald-800/60 bg-emerald-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-emerald-200">
                    rule group attached
                  </span>
                )}
                {p.rules_in_group !== undefined && p.rules_expected !== undefined && (
                  <span
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
                      p.rules_missing && p.rules_missing.length > 0
                        ? "border-amber-800/60 bg-amber-950/30 text-amber-200"
                        : "border-neutral-800 bg-neutral-900/40 text-neutral-300"
                    }`}
                    title={p.rules_missing?.length ? `missing: ${p.rules_missing.join(", ")}` : undefined}
                  >
                    {p.rules_in_group}/{p.rules_expected} rules
                  </span>
                )}
                {!p.is_dedicated && (
                  <span className="rounded border border-amber-800/60 bg-amber-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-amber-200">
                    shared with other groups
                  </span>
                )}
                {!p.enabled && (
                  <span className="rounded border border-red-800/60 bg-red-950/30 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-oxblood-200">
                    disabled
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3.5 py-3">
        <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-neutral-500">
          Shadow-AI Custom IOA rule group
        </div>
        <div className="text-sm text-neutral-300">
          {data.rule_group_attached
            ? "Attached — the Shadow-AI rule corpus fires for hosts in the banned group."
            : "Not attached — banned-group hosts won't actually have AI tooling blocked until the rule group is bound. The provisioning action below returns the follow-up calls to attach it (one separate approval per policy)."}
        </div>
      </div>

      {action && (
        <div className="rounded-md border border-amber-700/60 bg-amber-950/30 px-3.5 py-3">
          <div className="text-sm font-semibold text-amber-100">{action.label}</div>
          <p className="mt-1 text-sm text-amber-100/85">{action.description}</p>
          <button
            type="button"
            onClick={onAction}
            className="mt-3 inline-flex items-center gap-1.5 rounded border border-amber-700 bg-amber-950/60 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-amber-100 hover:bg-amber-950"
          >
            Run via chat
            <ArrowRight className="h-3 w-3" strokeWidth={2} />
          </button>
        </div>
      )}

      {!action && data.case === "ready" && (
        <div className="rounded-md border border-emerald-800/60 bg-emerald-950/30 px-3.5 py-3 text-sm text-emerald-100">
          Shadow-AI Banned is fully provisioned. Drop hosts into the banned group from /hosts to enforce.
        </div>
      )}

      <div className="flex items-center justify-end">
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 rounded border border-neutral-800 bg-neutral-950 px-3 py-1 font-mono text-[11px] uppercase tracking-wide text-neutral-400 hover:border-neutral-700 hover:text-neutral-200"
        >
          <RefreshCw className="h-3 w-3" strokeWidth={2} />
          Refresh
        </button>
      </div>
    </div>
  );
}

function KvBlock({ children }: { children: React.ReactNode }) {
  return <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">{children}</dl>;
}

function Kv({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[11px] font-mono uppercase tracking-wide text-neutral-500">{label}</dt>
      <dd className={`text-sm text-neutral-200 ${mono ? "font-mono break-all" : ""}`}>{value}</dd>
    </div>
  );
}

function ApplyGroupId({
  label,
  placeholder,
  endpoint,
  onSaved,
}: {
  label: string;
  placeholder: string;
  endpoint: string;
  onSaved: () => void;
}) {
  const [value, setValue] = useState("");
  const [status, setStatus] = useState<"idle" | "saving" | "clearing" | "error">("idle");
  const [err, setErr] = useState<string | null>(null);

  async function postId(id: string, busy: "saving" | "clearing"): Promise<void> {
    setStatus(busy);
    setErr(null);
    try {
      const r = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const data = (await r.json()) as { ok?: boolean; error?: string };
      if (!r.ok || !data.ok) {
        setStatus("error");
        setErr(data.error || `HTTP ${r.status}`);
        return;
      }
      setStatus("idle");
      setValue("");
      onSaved();
    } catch (e) {
      setStatus("error");
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const id = value.trim();
    if (!id) return;
    await postId(id, "saving");
  }

  async function clear() {
    if (!confirm("Clear the saved group id on the active environment?")) return;
    await postId("", "clearing");
  }

  return (
    <form
      onSubmit={submit}
      className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3.5 py-3"
    >
      <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-neutral-500">
        {label}
      </div>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={placeholder}
          disabled={status === "saving"}
          className="flex-1 rounded border border-neutral-800 bg-neutral-950 px-2.5 py-1.5 font-mono text-sm text-neutral-200 placeholder:text-neutral-600 focus:border-neutral-600 focus:outline-none"
        />
        <button
          type="submit"
          disabled={status === "saving" || status === "clearing" || !value.trim()}
          className="inline-flex items-center justify-center gap-1.5 rounded border border-neutral-700 bg-neutral-900 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-200 hover:border-neutral-600 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {status === "saving" ? (
            <>
              <Loader2 className="h-3 w-3 animate-spin" strokeWidth={2} />
              Saving
            </>
          ) : (
            "Save group id"
          )}
        </button>
        <button
          type="button"
          onClick={clear}
          disabled={status === "saving" || status === "clearing"}
          className="inline-flex items-center justify-center gap-1.5 rounded border border-neutral-800 bg-neutral-950 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-400 hover:border-oxblood-700 hover:text-oxblood-200 disabled:cursor-not-allowed disabled:opacity-50"
          title="Clear the saved group id on the active environment"
        >
          {status === "clearing" ? (
            <>
              <Loader2 className="h-3 w-3 animate-spin" strokeWidth={2} />
              Clearing
            </>
          ) : (
            "Clear"
          )}
        </button>
      </div>
      {status === "error" && err && (
        <div className="mt-2 font-mono text-[12px] text-oxblood-200">{err}</div>
      )}
    </form>
  );
}

function AdoptGroupByName({
  defaultName,
  endpoint,
  onSaved,
}: {
  defaultName: string;
  endpoint: string;
  onSaved: () => void;
}) {
  const [value, setValue] = useState(defaultName);
  const [status, setStatus] = useState<"idle" | "adopting" | "error">("idle");
  const [err, setErr] = useState<string | null>(null);
  const [candidates, setCandidates] = useState<Array<{ id?: string; group_type?: string }> | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const name = value.trim();
    if (!name) return;
    setStatus("adopting");
    setErr(null);
    setCandidates(null);
    try {
      const r = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const data = (await r.json()) as {
        ok?: boolean;
        error?: string;
        candidates?: Array<{ id?: string; group_type?: string }>;
      };
      if (!r.ok || !data.ok) {
        setStatus("error");
        setCandidates(data.candidates && data.candidates.length > 1 ? data.candidates : null);
        setErr(data.error || `HTTP ${r.status}`);
        return;
      }
      setStatus("idle");
      onSaved();
    } catch (e2) {
      setStatus("error");
      setErr(e2 instanceof Error ? e2.message : String(e2));
    }
  }

  return (
    <form
      onSubmit={submit}
      className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3.5 py-3"
    >
      <div className="mb-1 font-mono text-[11px] uppercase tracking-wide text-neutral-500">
        Adopt existing group by name
      </div>
      <p className="mb-2 text-[12px] text-neutral-500">
        Already have this group in your tenant? Look it up by name and point the
        active environment at it — no id to copy.
      </p>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={status === "adopting"}
          className="flex-1 rounded border border-neutral-800 bg-neutral-950 px-2.5 py-1.5 font-mono text-sm text-neutral-200 placeholder:text-neutral-600 focus:border-neutral-600 focus:outline-none"
        />
        <button
          type="submit"
          disabled={status === "adopting" || !value.trim()}
          className="inline-flex items-center justify-center gap-1.5 rounded border border-neutral-700 bg-neutral-900 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wide text-neutral-200 hover:border-neutral-600 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {status === "adopting" ? (
            <>
              <Loader2 className="h-3 w-3 animate-spin" strokeWidth={2} />
              Searching
            </>
          ) : (
            "Find & adopt"
          )}
        </button>
      </div>
      {status === "error" && (
        <div className="mt-2 text-[12px] text-oxblood-200">
          {candidates ? (
            <>
              <div>
                More than one group is named that — Eyas can&rsquo;t tell which
                to use. Copy the correct id from the Falcon Console and paste it
                below instead.
              </div>
              <ul className="mt-1.5 space-y-1">
                {candidates.map((c) => (
                  <li key={c.id} className="font-mono text-[11px] text-neutral-300">
                    {c.id}
                    {c.group_type ? ` (${c.group_type})` : ""}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <>
              No host group named &ldquo;{value.trim()}&rdquo; was found in this
              tenant. Check the name, or create one with the action below.
            </>
          )}
        </div>
      )}
    </form>
  );
}
