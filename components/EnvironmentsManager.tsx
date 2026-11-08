"use client";

import { useCallback, useState } from "react";
import {
  Boxes,
  ChevronDown,
  ChevronUp,
  Loader2,
  Pencil,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  Star,
} from "lucide-react";

type EnvView = {
  id: string;
  name: string;
  client_id_masked: string | null;
  client_secret_set: boolean;
  base_url: string;
  member_cid: string | null;
  ir_quarantine_group_id: string | null;
  shadow_ai_banned_group_id: string | null;
};

type ProbeResult = {
  ok: boolean;
  message?: string;
  oauth_ok?: boolean;
  oauth_status?: number;
  tenant_cid?: string | null;
  tenant_probe_ok?: boolean;
  tenant_probe_detail?: string;
  hosts_read_ok?: boolean;
  hosts_read_status?: number;
  error?: string;
};

export default function EnvironmentsManager({
  initial,
  initialActiveId,
}: {
  initial: EnvView[];
  initialActiveId: string;
}) {
  const [envs, setEnvs] = useState<EnvView[]>(initial);
  const [activeId, setActiveId] = useState(initialActiveId);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "loading">>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [topError, setTopError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const refreshList = useCallback(async () => {
    try {
      const r = await fetch("/api/environments", { cache: "no-store" });
      const j = (await r.json()) as { environments?: EnvView[]; active_id?: string };
      if (j.environments) setEnvs(j.environments);
      if (j.active_id) setActiveId(j.active_id);
    } catch {
      /* silent — stale display is fine */
    }
  }, []);

  const probe = useCallback(async (id: string) => {
    setProbes((p) => ({ ...p, [id]: "loading" }));
    try {
      const r = await fetch(`/api/environments/${encodeURIComponent(id)}/probe`, {
        method: "POST",
      });
      const j = (await r.json()) as ProbeResult;
      setProbes((p) => ({ ...p, [id]: j }));
    } catch (err) {
      setProbes((p) => ({
        ...p,
        [id]: {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        },
      }));
    }
  }, []);

  const setActive = useCallback(
    async (id: string) => {
      setBusy(id);
      setTopError(null);
      try {
        const r = await fetch("/api/environments/active", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id }),
        });
        if (!r.ok) {
          const j = (await r.json().catch(() => ({}))) as { error?: string };
          setTopError(j.error || `HTTP ${r.status}`);
          return;
        }
        await refreshList();
      } finally {
        setBusy(null);
      }
    },
    [refreshList],
  );

  const remove = useCallback(
    async (id: string, name: string) => {
      if (!confirm(`Delete environment "${name}"? This cannot be undone.`)) return;
      setBusy(id);
      setTopError(null);
      try {
        const r = await fetch(`/api/environments/${encodeURIComponent(id)}`, {
          method: "DELETE",
        });
        if (!r.ok) {
          const j = (await r.json().catch(() => ({}))) as { error?: string };
          setTopError(j.error || `HTTP ${r.status}`);
          return;
        }
        setProbes((p) => {
          const { [id]: _drop, ...rest } = p;
          return rest;
        });
        await refreshList();
      } finally {
        setBusy(null);
      }
    },
    [refreshList],
  );

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <Boxes className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="flex-1">
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
            CrowdStrike Falcon
          </div>
          <h2 className="mt-1.5 text-2xl font-semibold tracking-tight text-white">
            Tenant connections
          </h2>
          <p className="mt-1.5 text-sm text-neutral-400">
            Each row is a separate Falcon tenant. Use{" "}
            <span className="font-mono uppercase tracking-wider text-oxblood-300">Verify</span> to
            confirm a connection works and shows the tenant you expect — handy
            when juggling production, lab, and SE tenants.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate((v) => !v)}
          className="flex h-9 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-3 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-200 transition-colors hover:border-brand-700/60 hover:bg-neutral-800 hover:text-oxblood-200"
        >
          {showCreate ? (
            <ChevronUp className="h-3 w-3" strokeWidth={2.5} />
          ) : (
            <ChevronDown className="h-3 w-3" strokeWidth={2.5} />
          )}
          Add environment
        </button>
      </div>

      {showCreate && (
        <CreateEnvForm
          onClose={() => setShowCreate(false)}
          onSaved={async () => {
            setShowCreate(false);
            await refreshList();
          }}
        />
      )}

      {topError && (
        <div className="mt-4 rounded-md border border-rose-900/40 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">
          {topError}
        </div>
      )}

      <div className="mt-6 divide-y divide-neutral-800 rounded-md border border-neutral-800">
        {envs.map((e) => {
          const probeState = probes[e.id];
          const isActive = e.id === activeId;
          return (
            <div key={e.id} className="px-4 py-4">
              <div className="flex flex-wrap items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <div className="text-sm font-semibold text-white truncate">
                      {e.name}
                    </div>
                    {isActive && (
                      <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-emerald-300">
                        <Star className="h-3 w-3" strokeWidth={2.5} fill="currentColor" />
                        active
                      </span>
                    )}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-neutral-500">
                    <span>{e.base_url}</span>
                    <span>
                      Client ID{" "}
                      <span className="text-neutral-300">
                        {e.client_id_masked ?? "—"}
                      </span>
                    </span>
                    {e.member_cid && <span>Member CID {e.member_cid}</span>}
                    {e.ir_quarantine_group_id && (
                      <span>Quarantine group {e.ir_quarantine_group_id}</span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => probe(e.id)}
                    disabled={busy === e.id || probeState === "loading"}
                    className="flex h-8 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-2.5 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-300 transition-colors hover:border-brand-700/60 hover:bg-neutral-800 hover:text-oxblood-200 disabled:opacity-50"
                  >
                    {probeState === "loading" ? (
                      <Loader2 className="h-3 w-3 animate-spin" strokeWidth={2.5} />
                    ) : (
                      <RefreshCw className="h-3 w-3" strokeWidth={2.5} />
                    )}
                    Verify
                  </button>
                  {!isActive && (
                    <button
                      type="button"
                      onClick={() => setActive(e.id)}
                      disabled={busy === e.id}
                      className="flex h-8 items-center rounded-md border border-neutral-800 bg-neutral-900 px-2.5 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-300 transition-colors hover:border-emerald-700/60 hover:bg-emerald-900/30 hover:text-emerald-200 disabled:opacity-50"
                    >
                      Set active
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setEditingId(editingId === e.id ? null : e.id)}
                    className="flex h-8 items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-2.5 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-300 transition-colors hover:border-brand-700/60 hover:bg-neutral-800 hover:text-oxblood-200"
                  >
                    <Pencil className="h-3 w-3" strokeWidth={2.5} />
                    Edit
                  </button>
                  {!isActive && envs.length > 1 && (
                    <button
                      type="button"
                      onClick={() => remove(e.id, e.name)}
                      disabled={busy === e.id}
                      className="flex h-8 items-center rounded-md border border-neutral-800 bg-neutral-900 px-2.5 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-400 transition-colors hover:border-rose-800 hover:bg-rose-950/40 hover:text-rose-200 disabled:opacity-50"
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>

              {probeState && probeState !== "loading" && (
                <ProbeRow result={probeState} />
              )}

              {editingId === e.id && (
                <EditEnvForm
                  env={e}
                  onClose={() => setEditingId(null)}
                  onSaved={async () => {
                    setEditingId(null);
                    setProbes((p) => {
                      const { [e.id]: _drop, ...rest } = p;
                      return rest;
                    });
                    await refreshList();
                  }}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ProbeRow({ result }: { result: ProbeResult }) {
  const ok = !!(result.ok && result.oauth_ok);
  const tenantOk = !!result.tenant_cid;
  const hostsOk = !!result.hosts_read_ok;
  const oauthDetail = `status ${result.oauth_status ?? "—"}`;
  const oauthError = !ok ? result.message ?? result.error ?? null : null;
  return (
    <div className="mt-3 grid grid-cols-1 gap-2 rounded-md border border-neutral-800 bg-neutral-900/40 p-3 sm:grid-cols-3">
      <ProbeBadge label="OAuth2" ok={ok} detail={oauthDetail} error={oauthError} />
      <ProbeBadge
        label="Tenant ID"
        ok={tenantOk}
        detail={result.tenant_cid ?? result.tenant_probe_detail ?? "tenant ID was not returned"}
        error={null}
      />
      <ProbeBadge
        label="Host read access"
        ok={hostsOk}
        detail={
          hostsOk
            ? "Granted"
            : result.hosts_read_status === 403
              ? "Not granted (403)"
              : result.hosts_read_status
                ? `Returned ${result.hosts_read_status}`
                : "Not tested"
        }
        error={null}
      />
    </div>
  );
}

function ProbeBadge({
  label,
  ok,
  detail,
  error,
}: {
  label: string;
  ok: boolean;
  detail: string;
  error: string | null;
}) {
  return (
    <div className="flex items-start gap-2 rounded border border-neutral-800/60 bg-neutral-950/40 px-3 py-2">
      {ok ? (
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" strokeWidth={2} />
      ) : (
        <ShieldX className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" strokeWidth={2} />
      )}
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[10px] uppercase tracking-wider text-neutral-400">
          {label}
        </div>
        <div className="mt-0.5 break-all font-mono text-[12px] text-neutral-200">
          {detail}
        </div>
        {error && (
          <div className="mt-1 break-words text-[11px] text-rose-300">{error}</div>
        )}
      </div>
    </div>
  );
}


// ---------------------------------------------------------------------------
// Edit / create env forms — shared field shape, different submit endpoint.
// Each saves through the existing /api/environments routes which already
// run an OAuth probe gate before persisting on credential changes.
// ---------------------------------------------------------------------------

const inputClass =
  "mt-1 block w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 outline-none focus:border-neutral-600";
const labelClass = "block text-xs font-medium uppercase tracking-wider text-neutral-400";
const hintClass = "mt-1 text-xs text-neutral-500";

function EditEnvForm({
  env,
  onClose,
  onSaved,
}: {
  env: EnvView;
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const [name, setName] = useState(env.name);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [memberCid, setMemberCid] = useState("");
  const [memberCidExplicit, setMemberCidExplicit] = useState(false);
  const [irGroup, setIrGroup] = useState("");
  const [irGroupExplicit, setIrGroupExplicit] = useState(false);
  const [shadowAiGroup, setShadowAiGroup] = useState("");
  const [shadowAiGroupExplicit, setShadowAiGroupExplicit] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function buildBody() {
    const body: Record<string, unknown> = {};
    if (name.trim() && name.trim() !== env.name) body.name = name.trim();
    if (clientId) body.client_id = clientId;
    if (clientSecret) body.client_secret = clientSecret;
    if (baseUrl) body.base_url = baseUrl;
    if (memberCidExplicit) body.member_cid = memberCid;
    if (irGroupExplicit) body.ir_quarantine_group_id = irGroup;
    if (shadowAiGroupExplicit) body.shadow_ai_banned_group_id = shadowAiGroup;
    return body;
  }

  async function handleSave() {
    setError(null);
    setPending(true);
    try {
      const r = await fetch(`/api/environments/${encodeURIComponent(env.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildBody()),
      });
      const j = (await r.json()) as { ok: boolean; error?: string };
      if (!j.ok) {
        setError(j.error ?? `HTTP ${r.status}`);
        return;
      }
      await onSaved();
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="mt-4 space-y-4 rounded-md border border-neutral-800 bg-neutral-900/40 p-4">
      <div>
        <label className={labelClass}>Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Client ID</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={env.client_id_masked ?? "(not set)"}
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          className={inputClass}
        />
        <p className={hintClass}>Leave blank to keep the current value.</p>
      </div>
      <div>
        <label className={labelClass}>Client Secret</label>
        <input
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          placeholder={env.client_secret_set ? "(unchanged)" : "(not set)"}
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          className={inputClass}
        />
        <p className={hintClass}>
          Stored only on this device — never shown in the browser.
        </p>
      </div>
      <div>
        <label className={labelClass}>Base URL</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={env.base_url}
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Member CID</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={env.member_cid ?? "(not set — single tenant)"}
          value={memberCid}
          onChange={(e) => {
            setMemberCid(e.target.value);
            setMemberCidExplicit(true);
          }}
          className={inputClass}
        />
        <p className={hintClass}>
          Optional. Used for MSSP child tenants. Clear to remove.
        </p>
      </div>
      <div>
        <label className={labelClass}>IR quarantine host group</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={env.ir_quarantine_group_id ?? "(not set)"}
          value={irGroup}
          onChange={(e) => {
            setIrGroup(e.target.value);
            setIrGroupExplicit(true);
          }}
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Shadow-AI banned host group</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder={env.shadow_ai_banned_group_id ?? "(not set)"}
          value={shadowAiGroup}
          onChange={(e) => {
            setShadowAiGroup(e.target.value);
            setShadowAiGroupExplicit(true);
          }}
          className={inputClass}
        />
      </div>

      {error && (
        <div className="rounded-md border border-rose-900/60 bg-rose-950/30 p-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 pt-2">
        <button
          type="button"
          onClick={handleSave}
          disabled={pending}
          className="inline-flex items-center gap-1.5 rounded-md border border-brand-800 bg-brand-900/40 px-4 py-2 text-xs font-medium uppercase tracking-wider text-white hover:border-brand-700 hover:bg-brand-900/60 disabled:opacity-50"
        >
          {pending ? "Saving…" : "Save"}
        </button>
        <button
          type="button"
          onClick={onClose}
          disabled={pending}
          className="inline-flex items-center gap-1.5 rounded-md border border-transparent bg-transparent px-4 py-2 text-xs font-medium uppercase tracking-wider text-neutral-400 hover:text-neutral-200 disabled:opacity-50"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function CreateEnvForm({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const [name, setName] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [baseUrl, setBaseUrl] = useState("https://api.crowdstrike.com");
  const [memberCid, setMemberCid] = useState("");
  const [irGroup, setIrGroup] = useState("");
  const [activate, setActivate] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function handleSave() {
    setError(null);
    if (!name.trim() || !clientId || !clientSecret) {
      setError("Name, Client ID, and Client Secret are required.");
      return;
    }
    setPending(true);
    try {
      const body: Record<string, unknown> = {
        name: name.trim(),
        client_id: clientId,
        client_secret: clientSecret,
        base_url: baseUrl,
        activate,
      };
      if (memberCid) body.member_cid = memberCid;
      if (irGroup) body.ir_quarantine_group_id = irGroup;
      const r = await fetch("/api/environments", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = (await r.json()) as { ok: boolean; error?: string };
      if (!j.ok) {
        setError(j.error ?? `HTTP ${r.status}`);
        return;
      }
      await onSaved();
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="mt-4 space-y-4 rounded-md border border-emerald-900/40 bg-emerald-950/20 p-4">
      <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-emerald-300">
        Add environment
      </div>
      <div>
        <label className={labelClass}>Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Lab tenant"
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Client ID</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Client Secret</label>
        <input
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Base URL</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>Member CID</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={memberCid}
          onChange={(e) => setMemberCid(e.target.value)}
          placeholder="(optional — MSSP child tenant only)"
          className={inputClass}
        />
      </div>
      <div>
        <label className={labelClass}>IR quarantine host group</label>
        <input
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={irGroup}
          onChange={(e) => setIrGroup(e.target.value)}
          placeholder="(optional)"
          className={inputClass}
        />
      </div>
      <label className="flex items-center gap-2 text-sm text-neutral-300">
        <input
          type="checkbox"
          checked={activate}
          onChange={(e) => setActivate(e.target.checked)}
          className="h-4 w-4 rounded border-neutral-700 bg-neutral-950 text-emerald-600 focus:ring-emerald-700"
        />
        Activate after save
      </label>

      {error && (
        <div className="rounded-md border border-rose-900/60 bg-rose-950/30 p-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 pt-2">
        <button
          type="button"
          onClick={handleSave}
          disabled={pending}
          className="inline-flex items-center gap-1.5 rounded-md border border-emerald-800 bg-emerald-900/40 px-4 py-2 text-xs font-medium uppercase tracking-wider text-white hover:border-emerald-700 hover:bg-emerald-900/60 disabled:opacity-50"
        >
          {pending ? "Saving…" : "Create"}
        </button>
        <button
          type="button"
          onClick={onClose}
          disabled={pending}
          className="inline-flex items-center gap-1.5 rounded-md border border-transparent bg-transparent px-4 py-2 text-xs font-medium uppercase tracking-wider text-neutral-400 hover:text-neutral-200 disabled:opacity-50"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
