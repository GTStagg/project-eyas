"use client";

import { useCallback, useEffect, useState, useTransition } from "react";
import { ShieldCheck, Pencil } from "lucide-react";

// Per-environment CrowdStrike AI Detection and Response (AIDR) credential
// card. Operates on the currently-active environment —
// switching the env on the topbar reloads the card via /api/environments.
//
// AIDR scans chat input + assistant output for prompt injection, PII,
// jailbreaks, etc. When unconfigured, AIDR is simply off for that env
// (chat shows an unguarded banner). When configured, blocked turns are
// surfaced to the operator as a shield-bubble in chat — agent never sees
// the input, and any blocked output is not saved to the transcript.

const inputClass =
  "mt-1 block w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 outline-none focus:border-neutral-600";
const labelClass = "block text-xs font-medium uppercase tracking-wider text-neutral-400";
const hintClass = "mt-1 text-xs text-neutral-500";

type EnvironmentView = {
  id: string;
  name: string;
  aidr_token_set: boolean;
  aidr_base_url: string;
};

type ListResponse = {
  ok: boolean;
  active_id: string;
  environments: EnvironmentView[];
};

export default function AidrConfigCard() {
  const [active, setActive] = useState<EnvironmentView | null>(null);
  const [editing, setEditing] = useState(false);
  const [token, setToken] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [baseUrlExplicit, setBaseUrlExplicit] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const refresh = useCallback(async () => {
    const r = await fetch("/api/environments", { cache: "no-store" });
    const j = (await r.json()) as ListResponse;
    if (j.ok) {
      const a = j.environments.find((e) => e.id === j.active_id) ?? null;
      setActive(a);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function resetForm() {
    setToken("");
    setBaseUrl("");
    setBaseUrlExplicit(false);
    setError(null);
  }

  function handleSave() {
    if (!active) return;
    setError(null);
    setSuccess(null);
    const body: Record<string, string> = {};
    if (token) body.aidr_token = token;
    if (baseUrlExplicit) body.aidr_base_url = baseUrl;
    if (Object.keys(body).length === 0) {
      setError("Nothing to save — enter a token or edit the base URL.");
      return;
    }
    startTransition(async () => {
      const r = await fetch(`/api/environments/${active.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = (await r.json()) as { ok: boolean; error?: string };
      if (!j.ok) {
        setError(j.error ?? `Save failed (HTTP ${r.status}).`);
        return;
      }
      setSuccess("AI Detection and Response credentials saved.");
      resetForm();
      setEditing(false);
      await refresh();
      setTimeout(() => setSuccess(null), 4000);
    });
  }

  function handleDisable() {
    if (!active) return;
    setError(null);
    setSuccess(null);
    startTransition(async () => {
      const r = await fetch(`/api/environments/${active.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ aidr_token: "", aidr_base_url: "" }),
      });
      const j = (await r.json()) as { ok: boolean; error?: string };
      if (!j.ok) {
        setError(j.error ?? `Update failed (HTTP ${r.status}).`);
        return;
      }
      setSuccess("AI Detection and Response disabled for this environment.");
      resetForm();
      setEditing(false);
      await refresh();
      setTimeout(() => setSuccess(null), 4000);
    });
  }

  if (!active) {
    return (
      <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
        <div className="text-sm text-neutral-500">Loading AI Detection and Response config…</div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <ShieldCheck className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="flex-1">
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
            AIDR
          </div>
          <h2 className="mt-1.5 text-2xl font-semibold tracking-tight text-white">
            AI Detection and Response
          </h2>
          <p className="mt-1.5 text-sm text-neutral-400">
            Optional. When configured, every chat prompt and every assistant
            response is scanned by CrowdStrike for prompt injection, sensitive
            data, jailbreak attempts, and policy violations before reaching
            you. Credential applies to the active environment ({active.name}).
          </p>
        </div>
        {!editing && (
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs font-medium uppercase tracking-wider text-neutral-200 hover:border-neutral-700 hover:bg-neutral-800"
          >
            <Pencil className="h-3.5 w-3.5" strokeWidth={2} />
            Edit
          </button>
        )}
      </div>

      {success && !editing && (
        <div className="mt-6 rounded-md border border-emerald-900/60 bg-emerald-950/30 p-3 text-sm text-emerald-300">
          {success}
        </div>
      )}

      {!editing ? (
        <div className="mt-6 overflow-hidden rounded-md border border-neutral-800 bg-neutral-950/60">
          <Row
            label="Status"
            value={active.aidr_token_set ? "Enabled" : "Not configured"}
            tone={active.aidr_token_set ? "ok" : "muted"}
          />
          <Row
            label="API token"
            value={active.aidr_token_set ? "•••••••• (set)" : "—"}
          />
          <Row label="API base URL" value={active.aidr_base_url} mono />
        </div>
      ) : (
        <div className="mt-6 space-y-4">
          <div>
            <label className={labelClass}>API token</label>
            <input
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              placeholder={active.aidr_token_set ? "(unchanged)" : "Paste the token from your AIDR collector"}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className={inputClass}
            />
            <p className={hintClass}>
              From the AIDR application collector's install instructions.
              Stored encrypted on this device. Leave blank to keep the
              current token.
            </p>
          </div>

          <div>
            <label className={labelClass}>API base URL</label>
            <input
              type="text"
              autoComplete="off"
              spellCheck={false}
              placeholder={active.aidr_base_url}
              value={baseUrl}
              onChange={(e) => {
                setBaseUrl(e.target.value);
                setBaseUrlExplicit(true);
              }}
              className={inputClass}
            />
            <p className={hintClass}>
              Use the URL shown next to the API token in the AIDR collector's
              install section (typically{" "}
              <span className="font-mono">https://api.crowdstrike.com/aidr/aiguard</span>
              ).
            </p>
          </div>

          {error && (
            <div className="rounded-md border border-rose-900/60 bg-rose-950/30 p-3 text-sm text-rose-300">
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
            {active.aidr_token_set && (
              <button
                type="button"
                onClick={handleDisable}
                disabled={pending}
                className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-4 py-2 text-xs font-medium uppercase tracking-wider text-neutral-200 hover:border-neutral-700 hover:bg-neutral-800 disabled:opacity-50"
              >
                Disable AIDR
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setEditing(false);
                resetForm();
              }}
              disabled={pending}
              className="inline-flex items-center gap-1.5 rounded-md border border-transparent bg-transparent px-4 py-2 text-xs font-medium uppercase tracking-wider text-neutral-400 hover:text-neutral-200 disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({
  label,
  value,
  mono = false,
  tone = "default",
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: "default" | "ok" | "muted";
}) {
  const valueClass =
    tone === "ok"
      ? "text-emerald-300"
      : tone === "muted"
        ? "text-neutral-500"
        : "text-neutral-100";
  return (
    <div className="flex items-center justify-between gap-4 border-b border-neutral-800/80 px-4 py-2.5 last:border-0">
      <span className="text-sm text-neutral-300">{label}</span>
      <span className={`text-sm ${mono ? "font-mono" : ""} ${valueClass}`}>{value}</span>
    </div>
  );
}
