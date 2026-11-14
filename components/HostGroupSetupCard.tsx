"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import {
  ShieldCheck,
  AlertTriangle,
  Loader2,
  ArrowRight,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";
import { buildPrimerHref } from "@/components/primerHandoff";

// Shared shell for the /config setup cards that stand up a host group and its
// prevention policies (IR quarantine, Shadow-AI Banned). Each card supplies a
// config: its copy, its endpoints, the per-case pills, the chat primer for the
// recommended action, and the few panels that differ. The shell owns the
// loading / error states, the adopt-by-name and paste-an-id forms, the policy
// list, the recommended-action box and the refresh button.
//
// The card reads state from its diagnose endpoint. Each recommended action
// hands off to chat with a primer that fires the gated Eyas tool. After the
// tool runs, the operator returns to /config and clicks "Refresh" to see the
// next step (or "ready"). The adopt and paste forms save the group id on the
// active environment directly, so there is no copy and paste after a create.

export type SetupPolicy = {
  id: string;
  name: string;
  platform: string;
  enabled: boolean;
  is_dedicated: boolean;
  managed_by_eyas: boolean;
};

export type SetupAction = {
  tool: string;
  args: Record<string, unknown>;
  label: string;
  description: string;
};

export type SetupDiagnostic = {
  ok: boolean;
  case?: string;
  host_group_id?: string | null;
  host_group?: { id: string; name: string; group_type: string } | null;
  policies?: SetupPolicy[];
  recommended_action?: SetupAction | null;
  error?: string;
};

export type CasePill = { label: string; cls: string };

export type SetupCardConfig<D extends SetupDiagnostic> = {
  icon: LucideIcon;
  title: string;
  intro: ReactNode;
  diagnoseEndpoint: string;
  adoptEndpoint: string;
  applyEndpoint: string;
  defaultGroupName: string;
  applyLabel: string;
  noGroupText: string;
  casePill: Record<string, CasePill>;
  /** Chat primer for the recommended action, or null when there is none. */
  primerFor: (action: NonNullable<D["recommended_action"]>) => string | null;
  /** Extra badges after the shared ones on each policy row. */
  policyBadges?: (policy: NonNullable<D["policies"]>[number]) => ReactNode;
  /** The card-specific status panel under the policy list. */
  statusPanel: (data: D) => ReactNode;
  readyText: string;
};

export default function HostGroupSetupCard<D extends SetupDiagnostic>({
  config,
}: {
  config: SetupCardConfig<D>;
}) {
  const [state, setState] = useState<{ status: "loading" | "ok" | "error"; data?: D; err?: string }>({
    status: "loading",
  });
  const router = useRouter();
  const Icon = config.icon;

  async function load() {
    setState({ status: "loading" });
    try {
      const r = await fetch(config.diagnoseEndpoint);
      const data = (await r.json()) as D;
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function fireRecommendation() {
    if (state.status !== "ok" || !state.data?.recommended_action) return;
    const primer = config.primerFor(state.data.recommended_action as NonNullable<D["recommended_action"]>);
    if (primer) router.push(buildPrimerHref(primer));
  }

  const pill = state.status === "ok" && state.data?.case ? config.casePill[state.data.case] : undefined;

  return (
    <section className="rounded-lg border border-neutral-800 bg-neutral-950 p-6 shadow-lg shadow-black/40">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
            <Icon className="h-5 w-5" strokeWidth={1.75} />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">{config.title}</h2>
            <p className="mt-1 max-w-xl text-sm text-neutral-400">{config.intro}</p>
          </div>
        </div>
        {pill && (
          <span
            className={`shrink-0 inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide ${pill.cls}`}
          >
            {state.data?.case === "ready" ? (
              <ShieldCheck className="h-3 w-3" strokeWidth={2} />
            ) : (
              <AlertTriangle className="h-3 w-3" strokeWidth={2} />
            )}
            {pill.label}
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
            <div className="font-semibold">Couldn&apos;t read tenant state.</div>
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

        {state.status === "ok" && state.data && (
          <Body config={config} data={state.data} onRefresh={load} onAction={fireRecommendation} />
        )}
      </div>
    </section>
  );
}

function Body<D extends SetupDiagnostic>({
  config,
  data,
  onRefresh,
  onAction,
}: {
  config: SetupCardConfig<D>;
  data: D;
  onRefresh: () => void;
  onAction: () => void;
}) {
  const action = data.recommended_action;
  // The apply / clear forms always render. Operators sometimes land on a wrong
  // id (carried over from another env, or auto-saved against the wrong setup
  // card) and need a way to fix it from /config.
  return (
    <div className="space-y-4">
      {data.host_group ? (
        <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Kv label="Host group" value={`${data.host_group.name} (${data.host_group.group_type})`} />
          <Kv label="Group id" value={data.host_group.id} mono />
        </dl>
      ) : (
        <div className="rounded border border-dashed border-neutral-800 bg-neutral-950/50 px-3.5 py-3 text-sm text-neutral-400">
          {config.noGroupText}
        </div>
      )}

      <AdoptGroupByName
        defaultName={config.defaultGroupName}
        endpoint={config.adoptEndpoint}
        onSaved={onRefresh}
      />
      <ApplyGroupId
        label={config.applyLabel}
        placeholder="e.g. 9f4c…"
        endpoint={config.applyEndpoint}
        onSaved={onRefresh}
      />

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
                {config.policyBadges?.(p as NonNullable<D["policies"]>[number])}
              </li>
            ))}
          </ul>
        </div>
      )}

      {config.statusPanel(data)}

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
          {config.readyText}
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

/** A titled panel with one line of text, for the cards' status sections. */
export function StatusPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-3.5 py-3">
      <div className="mb-2 font-mono text-[11px] uppercase tracking-wide text-neutral-500">{title}</div>
      <div className="text-sm text-neutral-300">{children}</div>
    </div>
  );
}

/** A small bordered badge, for the extra per-policy badges. */
export function PolicyBadge({
  tone,
  title,
  children,
}: {
  tone: "emerald" | "amber" | "neutral";
  title?: string;
  children: ReactNode;
}) {
  const cls =
    tone === "emerald"
      ? "border-emerald-800/60 bg-emerald-950/30 text-emerald-200"
      : tone === "amber"
        ? "border-amber-800/60 bg-amber-950/30 text-amber-200"
        : "border-neutral-800 bg-neutral-900/40 text-neutral-300";
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ${cls}`}
      title={title}
    >
      {children}
    </span>
  );
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
          ) : err && !/^no host group named/i.test(err) ? (
            <>Couldn&rsquo;t look up that group: {err}</>
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
