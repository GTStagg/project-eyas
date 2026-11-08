"use client";

import { useCallback, useEffect, useState, useTransition } from "react";
import { Brain, Pencil } from "lucide-react";

type Mode = "apiKey" | "authToken";

type View = {
  credential_kind: Mode | null;
  credential_set: boolean;
  base_url: string | null;
  model: string;
  chat_max_tokens: number;
};

type Policy = {
  gateway_only: boolean;
  forced_gateway_url: string | null;
};

const inputClass =
  "mt-1 block w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 outline-none focus:border-neutral-600";
const labelClass = "block text-xs font-medium uppercase tracking-wider text-neutral-400";
const hintClass = "mt-1 text-xs text-neutral-500";

export default function AnthropicConfigCard({ gatewayOnly }: { gatewayOnly: boolean }) {
  const [view, setView] = useState<View | null>(null);
  const [policy, setPolicy] = useState<Policy>({
    gateway_only: gatewayOnly,
    forced_gateway_url: null,
  });
  const [editing, setEditing] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(
    null,
  );
  const [pending, startTransition] = useTransition();

  // Form fields. Empty `credential` means "leave alone"; non-empty rotates.
  const [mode, setMode] = useState<Mode>("apiKey");
  const [credential, setCredential] = useState("");
  const [baseURL, setBaseURL] = useState("");
  const [baseURLExplicit, setBaseURLExplicit] = useState(false);
  const [model, setModel] = useState("");
  const [modelExplicit, setModelExplicit] = useState(false);
  const [chatMaxTokens, setChatMaxTokens] = useState("");
  const [chatMaxTokensExplicit, setChatMaxTokensExplicit] = useState(false);

  const refresh = useCallback(async () => {
    const r = await fetch("/api/config/anthropic", { cache: "no-store" });
    const j = (await r.json()) as {
      ok: boolean;
      anthropic?: View;
      policy?: Policy;
    };
    if (j.ok && j.anthropic) {
      setView(j.anthropic);
      const effectiveGatewayOnly = j.policy?.gateway_only ?? gatewayOnly;
      if (effectiveGatewayOnly) setMode("authToken");
      else if (j.anthropic.credential_kind) setMode(j.anthropic.credential_kind);
      if (j.policy) setPolicy(j.policy);
    }
  }, [gatewayOnly]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function resetForm() {
    setCredential("");
    setBaseURL("");
    setBaseURLExplicit(false);
    setModel("");
    setModelExplicit(false);
    setChatMaxTokens("");
    setChatMaxTokensExplicit(false);
    setError(null);
    setTestResult(null);
  }

  function buildBody() {
    const body: Record<string, unknown> = { mode };
    if (credential) body.credential = credential;
    if (baseURLExplicit) body.baseURL = baseURL;
    if (modelExplicit) body.model = model;
    if (chatMaxTokensExplicit) {
      body.chatMaxTokens = chatMaxTokens.trim() === "" ? "" : Number(chatMaxTokens);
    }
    return body;
  }

  function handleTest() {
    setTestResult(null);
    setError(null);
    startTransition(async () => {
      const r = await fetch("/api/config/anthropic?test=1", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildBody()),
      });
      const j = (await r.json()) as { ok: boolean; message?: string; error?: string };
      setTestResult({
        ok: j.ok,
        message: j.message ?? j.error ?? `HTTP ${r.status}`,
      });
    });
  }

  function handleSave() {
    setError(null);
    setSuccess(null);
    startTransition(async () => {
      const r = await fetch("/api/config/anthropic", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildBody()),
      });
      const j = (await r.json()) as { ok: boolean; message?: string; error?: string };
      if (!j.ok) {
        setError(j.error ?? `Save failed (HTTP ${r.status}).`);
        return;
      }
      setSuccess(j.message ?? "Saved.");
      resetForm();
      setEditing(false);
      await refresh();
      setTimeout(() => setSuccess(null), 4000);
    });
  }

  if (!view) {
    return (
      <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
        <div className="text-sm text-neutral-500">Loading Anthropic config…</div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <Brain className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="flex-1">
          <div className="text-xs font-semibold uppercase tracking-[0.14em] text-oxblood-400">
            Anthropic
          </div>
          <h2 className="mt-1.5 text-2xl font-semibold tracking-tight text-white">
            LLM credentials
          </h2>
          <p className="mt-1.5 text-sm text-neutral-400">
            {gatewayOnly
              ? "This build connects to Anthropic through the organization gateway. Edit the auth token or model below."
              : "Edit the API key or gateway auth token. Saving runs a quick connection test and only writes if it succeeds."}
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
          <ViewRow
            label="Credential"
            value={
              view.credential_set
                ? `•••••••• (${view.credential_kind === "authToken" ? "auth token" : "API key"})`
                : "—"
            }
          />
          <ViewRow
            label="Base URL"
            value={view.base_url ?? "(default)"}
            mono
          />
          <ViewRow label="Model" value={view.model} mono />
          <ViewRow
            label="Chat output limit"
            value={`${view.chat_max_tokens.toLocaleString()} tokens / reply`}
            mono
          />
        </div>
      ) : (
        <div className="mt-6 space-y-4">
          {!gatewayOnly && (
            <div>
              <label className={labelClass}>Credential type</label>
              <div className="mt-1 inline-flex rounded-md border border-neutral-800 bg-neutral-950 p-0.5">
                {(["apiKey", "authToken"] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMode(m)}
                    className={`rounded px-3 py-1.5 text-xs font-mono uppercase tracking-wider transition-colors ${
                      mode === m
                        ? "bg-neutral-800 text-neutral-100"
                        : "text-neutral-400 hover:text-neutral-200"
                    }`}
                  >
                    {m === "apiKey" ? "API key" : "Auth token"}
                  </button>
                ))}
              </div>
              <p className={hintClass}>
                Use an API key for direct access to Anthropic. Use an auth
                token when going through an organization gateway or proxy.
              </p>
            </div>
          )}

          <div>
            <label className={labelClass}>
              {mode === "authToken" ? "Auth token" : "API key"}
            </label>
            <input
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              placeholder={view.credential_set ? "(unchanged)" : "(unset)"}
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
              className={inputClass}
            />
            <p className={hintClass}>
              Stored only on this device — never displayed in the browser.
              Leave blank to keep the current credential.
            </p>
          </div>

          <div>
            <label className={labelClass}>Base URL</label>
            {policy.forced_gateway_url ? (
              <>
                <input
                  type="text"
                  readOnly
                  value={policy.forced_gateway_url}
                  className={`${inputClass} cursor-not-allowed bg-neutral-900 text-neutral-400`}
                />
                <p className={hintClass}>
                  This build is locked to the organization gateway and can't
                  be changed here.
                </p>
              </>
            ) : (
              <>
                <input
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={view.base_url ?? "(default — api.anthropic.com)"}
                  value={baseURL}
                  onChange={(e) => {
                    setBaseURL(e.target.value);
                    setBaseURLExplicit(true);
                  }}
                  className={inputClass}
                />
                <p className={hintClass}>
                  Required when using an auth token. Empty value clears.
                </p>
              </>
            )}
          </div>

          <div>
            <label className={labelClass}>Model</label>
            <input
              type="text"
              autoComplete="off"
              spellCheck={false}
              placeholder={view.model}
              value={model}
              onChange={(e) => {
                setModel(e.target.value);
                setModelExplicit(true);
              }}
              className={inputClass}
            />
            <p className={hintClass}>
              The Claude model name (e.g. claude-sonnet-4-6 for the
              everyday default, claude-opus-4-7 for the highest-quality
              option).
            </p>
          </div>

          <div>
            <label className={labelClass}>Chat output limit</label>
            <input
              type="number"
              inputMode="numeric"
              min={1024}
              max={64000}
              step={1024}
              autoComplete="off"
              placeholder={`${view.chat_max_tokens}`}
              value={chatMaxTokens}
              onChange={(e) => {
                setChatMaxTokens(e.target.value);
                setChatMaxTokensExplicit(true);
              }}
              className={inputClass}
            />
            <p className={hintClass}>
              How long a single chat reply can get before it&apos;s cut off.
              Raise it if scripts or long answers are being truncated; lower it
              to cap the cost of a single reply. Allowed range 1,024–64,000;
              leave blank to use the default (16,384).
            </p>
          </div>

          {testResult && (
            <div
              className={`rounded-md border p-3 text-sm ${
                testResult.ok
                  ? "border-emerald-900/60 bg-emerald-950/30 text-emerald-300"
                  : "border-rose-900/60 bg-rose-950/30 text-rose-300"
              }`}
            >
              {testResult.ok ? "✓ " : "✗ "}
              {testResult.message}
            </div>
          )}

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
            <button
              type="button"
              onClick={handleTest}
              disabled={pending}
              className="inline-flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-900 px-4 py-2 text-xs font-medium uppercase tracking-wider text-neutral-200 hover:border-neutral-700 hover:bg-neutral-800 disabled:opacity-50"
            >
              {pending ? "Testing…" : "Test connection"}
            </button>
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

function ViewRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-neutral-800/80 px-4 py-2.5 last:border-0">
      <span className="text-sm text-neutral-300">{label}</span>
      <span className={`text-sm ${mono ? "font-mono" : ""} text-neutral-100`}>{value}</span>
    </div>
  );
}
