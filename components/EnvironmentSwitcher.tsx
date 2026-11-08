"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronDown, Plus, Check, X, Loader2 } from "lucide-react";

type EnvironmentView = {
  id: string;
  name: string;
  client_id_masked: string | null;
  client_secret_set: boolean;
  base_url: string;
  member_cid: string | null;
  ir_quarantine_group_id: string | null;
};

type ListResponse = {
  ok: true;
  active_id: string;
  environments: EnvironmentView[];
  in_flight: number;
};

const POLL_MS_OPEN = 4000;

export default function EnvironmentSwitcher() {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<ListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null); // operation in flight
  const [showCreate, setShowCreate] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/environments", { cache: "no-store" });
      const json = (await res.json()) as ListResponse | { ok: false; error: string };
      if ("ok" in json && json.ok) {
        setData(json);
        setError(null);
      } else if ("error" in json) {
        setError(json.error);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Poll while open so the in-flight count updates if a chat run starts
  // / finishes while the operator is staring at the panel.
  useEffect(() => {
    if (!open) return;
    const id = setInterval(() => void refresh(), POLL_MS_OPEN);
    return () => clearInterval(id);
  }, [open, refresh]);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) {
        setOpen(false);
        setShowCreate(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const switchTo = async (id: string) => {
    if (!data || id === data.active_id || busy) return;
    setBusy(id);
    setError(null);
    try {
      const res = await fetch("/api/environments/active", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const json = (await res.json()) as
        | { ok: true; active_id: string; environments: EnvironmentView[] }
        | { ok: false; error: string };
      if ("ok" in json && json.ok) {
        setData((prev) => (prev ? { ...prev, ...json, in_flight: prev.in_flight } : prev));
        setOpen(false);
        // Force a soft reload so server components re-fetch with the new
        // active env. Otherwise dashboards keep their cached data.
        window.location.reload();
      } else {
        setError(json.error);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (id: string) => {
    if (busy) return;
    if (!confirm("Delete this environment? This can't be undone.")) return;
    setBusy(id);
    setError(null);
    try {
      const res = await fetch(`/api/environments/${id}`, { method: "DELETE" });
      const json = (await res.json()) as
        | { ok: true; active_id: string; environments: EnvironmentView[] }
        | { ok: false; error: string };
      if ("ok" in json && json.ok) {
        setData((prev) => (prev ? { ...prev, ...json } : prev));
      } else {
        setError(json.error);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const activeName = data?.environments.find((e) => e.id === data.active_id)?.name ?? "—";
  const inFlight = data?.in_flight ?? 0;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex h-9 items-center gap-2 rounded-md border border-neutral-800 bg-neutral-950/40 px-3 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400 transition-[border-color,background-color,color] duration-150 hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200"
        aria-label="Switch environment"
        aria-expanded={open}
      >
        <span className="hidden text-neutral-600 sm:inline">env //</span>
        <span className="max-w-[140px] truncate text-neutral-200">{activeName}</span>
        <ChevronDown className="h-3.5 w-3.5" strokeWidth={2} />
      </button>
      {open && data ? (
        <div className="absolute right-0 top-full z-40 mt-2 w-[320px] overflow-hidden rounded-md border border-neutral-800 bg-neutral-950 shadow-2xl">
          <div className="flex items-center justify-between border-b border-neutral-800 px-3 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-neutral-500">
            <span>Environments</span>
            {inFlight > 0 ? (
              <span className="text-amber-300/80">{inFlight} run(s) in flight</span>
            ) : null}
          </div>
          <ul className="max-h-[280px] overflow-y-auto">
            {data.environments.map((env) => {
              const isActive = env.id === data.active_id;
              const isBusyRow = busy === env.id;
              const blocked = inFlight > 0 && !isActive;
              return (
                <li
                  key={env.id}
                  className={`flex items-center gap-2 border-b border-neutral-900/60 px-3 py-2 text-sm last:border-b-0 ${
                    isActive ? "bg-neutral-900/40" : "hover:bg-neutral-900/40"
                  }`}
                >
                  <button
                    type="button"
                    disabled={isActive || isBusyRow || blocked}
                    onClick={() => void switchTo(env.id)}
                    className="flex flex-1 items-center gap-2 text-left disabled:cursor-not-allowed"
                    title={blocked ? "Wait for in-flight runs to finish" : undefined}
                  >
                    {isActive ? (
                      <Check className="h-3.5 w-3.5 shrink-0 text-oxblood-300" strokeWidth={2} />
                    ) : isBusyRow ? (
                      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-neutral-500" strokeWidth={2} />
                    ) : (
                      <span className="h-3.5 w-3.5 shrink-0" />
                    )}
                    <span className="flex min-w-0 flex-col">
                      <span className="truncate text-neutral-100">{env.name}</span>
                      <span className="truncate font-mono text-[11px] text-neutral-500">
                        {env.client_id_masked ?? "no creds"} · {env.base_url.replace(/^https:\/\//, "")}
                      </span>
                    </span>
                  </button>
                  {!isActive && data.environments.length > 1 ? (
                    <button
                      type="button"
                      onClick={() => void remove(env.id)}
                      disabled={isBusyRow}
                      aria-label={`Delete ${env.name}`}
                      className="rounded p-1 text-neutral-600 hover:bg-neutral-900 hover:text-oxblood-300 disabled:opacity-50"
                    >
                      <X className="h-3.5 w-3.5" strokeWidth={2} />
                    </button>
                  ) : null}
                </li>
              );
            })}
          </ul>
          <div className="border-t border-neutral-800">
            {showCreate ? (
              <CreateForm
                onCancel={() => setShowCreate(false)}
                onCreated={async () => {
                  setShowCreate(false);
                  await refresh();
                }}
              />
            ) : (
              <button
                type="button"
                onClick={() => setShowCreate(true)}
                className="flex w-full items-center gap-2 px-3 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-neutral-400 hover:bg-neutral-900 hover:text-oxblood-200"
              >
                <Plus className="h-3.5 w-3.5" strokeWidth={2} />
                Add environment
              </button>
            )}
          </div>
          {error ? (
            <div className="border-t border-neutral-800 bg-oxblood-950/40 px-3 py-2 text-[12px] text-oxblood-200">
              {error}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function CreateForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => Promise<void> }) {
  const [name, setName] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [baseUrl, setBaseUrl] = useState("https://api.crowdstrike.com");
  const [memberCid, setMemberCid] = useState("");
  const [activate, setActivate] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/environments", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          client_id: clientId,
          client_secret: clientSecret,
          base_url: baseUrl,
          member_cid: memberCid || undefined,
          activate,
        }),
      });
      const json = (await res.json()) as { ok: boolean; error?: string };
      if (json.ok) {
        if (activate) {
          // Soft reload so server components pick up the new active env.
          window.location.reload();
        } else {
          await onCreated();
        }
      } else {
        setErr(json.error ?? "save failed");
      }
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : String(e2));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-2 px-3 py-3">
      <Field label="Name" value={name} onChange={setName} placeholder="Production / Lab / …" required />
      <Field label="Client ID" value={clientId} onChange={setClientId} required mono />
      <Field label="Client Secret" value={clientSecret} onChange={setClientSecret} required mono type="password" />
      <Field label="Base URL" value={baseUrl} onChange={setBaseUrl} mono />
      <Field label="Member CID (optional)" value={memberCid} onChange={setMemberCid} mono />
      <label className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-400">
        <input
          type="checkbox"
          checked={activate}
          onChange={(e) => setActivate(e.target.checked)}
          className="h-3.5 w-3.5 rounded border-neutral-700 bg-neutral-950 text-oxblood-300"
        />
        Activate after save
      </label>
      {err ? <div className="text-[12px] text-oxblood-200">{err}</div> : null}
      <div className="flex items-center justify-end gap-2 pt-1">
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-neutral-800 px-2 py-1 font-mono text-[11px] uppercase tracking-[0.12em] text-neutral-400 hover:border-neutral-700 hover:text-neutral-200"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting}
          className="rounded border border-brand-700 bg-brand-900/50 px-2 py-1 font-mono text-[11px] uppercase tracking-[0.12em] text-white hover:bg-brand-800 disabled:opacity-50"
        >
          {submitting ? "Probing…" : "Test & save"}
        </button>
      </div>
    </form>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  required,
  mono,
  type,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  required?: boolean;
  mono?: boolean;
  type?: string;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-neutral-500">
        {label}
      </span>
      <input
        type={type ?? "text"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        className={`w-full rounded border border-neutral-800 bg-neutral-950 px-2 py-1.5 text-sm text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none ${mono ? "font-mono text-[12px]" : ""}`}
      />
    </label>
  );
}
