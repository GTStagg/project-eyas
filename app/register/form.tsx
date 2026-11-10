"use client";
import { useActionState, useState, useTransition } from "react";
import {
  registerAction,
  testConnectionAction,
  type RegisterState,
  type TestState,
} from "./actions";
import type { ConfigStatus } from "@/lib/config/runtime";
import ScopeChecklist from "@/components/ScopeChecklist";

const initialRegisterState: RegisterState = {};
const initialTestState: TestState = {};

type Mode = "apiKey" | "authToken";

const inputClass =
  "mt-1 block w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 outline-none focus:border-neutral-600";
const labelClass = "block text-xs font-medium uppercase tracking-wider text-neutral-400";
const hintClass = "mt-1 text-xs text-neutral-500";

function SourceBadge({ source }: { source: ConfigStatus["anthropic"]["baseURL"]["source"] }) {
  if (source === "config") {
    return (
      <span className="ml-2 rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-emerald-300">
        saved
      </span>
    );
  }
  return null;
}

export function RegisterForm({
  minLength,
  status,
  gatewayOnly,
  forcedGatewayUrl,
}: {
  minLength: number;
  status: ConfigStatus;
  gatewayOnly: boolean;
  forcedGatewayUrl: string | null;
}) {
  const [step, setStep] = useState<1 | 2>(1);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [stepOneError, setStepOneError] = useState<string | null>(null);

  // Anthropic mode picker. When gatewayOnly is set (standalone deployment
  // where direct Anthropic isn't an option) the picker is hidden and locked
  // to authToken. Otherwise default to whichever the existing config points
  // at, else apiKey.
  const initialMode: Mode = gatewayOnly
    ? "authToken"
    : status.anthropic.credential.kind === "authToken"
      ? "authToken"
      : "apiKey";
  const [mode, setMode] = useState<Mode>(initialMode);

  // All credential fields are controlled. React 19 resets uncontrolled inputs
  // when a useActionState form action completes, which wiped every field after
  // a "Test connection" submission and led operators to save partial configs.
  const [anthropicApiKey, setAnthropicApiKey] = useState("");
  const [anthropicAuthToken, setAnthropicAuthToken] = useState("");
  const [anthropicBaseURL, setAnthropicBaseURL] = useState("");
  const [anthropicModel, setAnthropicModel] = useState("");
  const [falconClientId, setFalconClientId] = useState("");
  const [falconClientSecret, setFalconClientSecret] = useState("");
  const [falconBaseUrl, setFalconBaseUrl] = useState("");
  const [falconMemberCid, setFalconMemberCid] = useState("");
  // FalconPy sidecar is unconditionally on; the wizard renders no toggle.
  const [irGroupId, setIrGroupId] = useState("");

  const [registerState, registerFormAction, registerPending] = useActionState(
    registerAction,
    initialRegisterState,
  );
  const [testState, testFormAction, testPending] = useActionState(
    testConnectionAction,
    initialTestState,
  );
  const [, startTransition] = useTransition();

  function handleStepOneNext(e: React.FormEvent) {
    e.preventDefault();
    setStepOneError(null);
    if (password.length < minLength) {
      setStepOneError(`Password must be at least ${minLength} characters.`);
      return;
    }
    if (password !== confirm) {
      setStepOneError("Passwords do not match.");
      return;
    }
    setStep(2);
  }

  if (step === 1) {
    return (
      <form onSubmit={handleStepOneNext} className="space-y-4">
        <div className="text-xs text-neutral-500">Step 1 of 2 · Console password</div>
        <div>
          <label htmlFor="password" className={labelClass}>Password</label>
          <input
            id="password"
            type="password"
            required
            minLength={minLength}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={inputClass}
          />
          <p className={hintClass}>Minimum {minLength} characters.</p>
        </div>
        <div>
          <label htmlFor="confirm" className={labelClass}>Confirm password</label>
          <input
            id="confirm"
            type="password"
            required
            minLength={minLength}
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className={inputClass}
          />
        </div>
        {stepOneError ? (
          <p className="text-sm text-oxblood-400" role="alert">{stepOneError}</p>
        ) : null}
        <button
          type="submit"
          className="w-full rounded-md bg-neutral-100 px-3 py-2 text-sm font-medium text-neutral-950 hover:bg-white"
        >
          Next: integration credentials
        </button>
      </form>
    );
  }

  // Step 2 — credentials. The form posts to registerFormAction; the same form
  // can also post to testFormAction via formAction overrides on the Test button.
  return (
    <form action={registerFormAction} className="space-y-6">
      <input type="hidden" name="password" value={password} />
      <input type="hidden" name="confirm" value={confirm} />
      <div className="flex items-center justify-between">
        <div className="text-xs text-neutral-500">Step 2 of 2 · Integration credentials</div>
        <button
          type="button"
          onClick={() => setStep(1)}
          className="inline-flex h-7 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-300 transition hover:border-neutral-700 hover:text-white"
        >
          ← Back
        </button>
      </div>

      <Section title="Anthropic">
        {gatewayOnly ? null : (
          <div className="flex gap-2 text-xs">
            <ModeButton active={mode === "apiKey"} onClick={() => setMode("apiKey")}>Direct API key</ModeButton>
            <ModeButton active={mode === "authToken"} onClick={() => setMode("authToken")}>Corporate gateway (Bearer)</ModeButton>
          </div>
        )}

        {mode === "apiKey" ? (
          <Field
            label={
              <span>
                API key
                <SourceBadge source={status.anthropic.credential.kind === "apiKey" ? status.anthropic.credential.source : "missing"} />
              </span>
            }
            name="anthropic_apiKey"
            type="password"
            placeholder={status.anthropic.credential.kind === "apiKey" && status.anthropic.credential.source !== "missing" ? "•• keep saved value (leave blank) ••" : "sk-ant-..."}
            hint="Get a key at https://console.anthropic.com/. Leave blank to keep the saved value."
            value={anthropicApiKey}
            onChange={setAnthropicApiKey}
          />
        ) : (
          <>
            <Field
              label={
                <span>
                  Auth token
                  <SourceBadge source={status.anthropic.credential.kind === "authToken" ? status.anthropic.credential.source : "missing"} />
                </span>
              }
              name="anthropic_authToken"
              type="password"
              placeholder={status.anthropic.credential.kind === "authToken" && status.anthropic.credential.source !== "missing" ? "•• keep saved value (leave blank) ••" : "Bearer token"}
              hint="The token your gateway issued. Used to authenticate every request through the gateway."
              value={anthropicAuthToken}
              onChange={setAnthropicAuthToken}
            />
            {forcedGatewayUrl ? (
              <Field
                label={<span>Base URL <SourceBadge source="config" /></span>}
                name="anthropic_baseURL"
                type="text"
                value={forcedGatewayUrl}
                onChange={() => {}}
                readOnly
                hint="This build is locked to the organization gateway and can't be changed here."
              />
            ) : (
              <Field
                label={<span>Base URL <SourceBadge source={status.anthropic.baseURL.source} /></span>}
                name="anthropic_baseURL"
                type="text"
                placeholder="https://your-gateway.example.com"
                hint="Required when using a gateway auth token."
                value={anthropicBaseURL}
                onChange={setAnthropicBaseURL}
              />
            )}
          </>
        )}

        <Field
          label={<span>Model <SourceBadge source={status.anthropic.model.source} /></span>}
          name="anthropic_model"
          type="text"
          placeholder={status.anthropic.model.value}
          hint='Default "claude-sonnet-5-5". Use "claude-opus-5-5" for higher quality, "claude-haiku-5-5" for cheap/fast.'
          value={anthropicModel}
          onChange={setAnthropicModel}
        />
      </Section>

      <Section title="CrowdStrike Falcon">
        <ScopeChecklist />
        <Field
          label={<span>Client ID <SourceBadge source={status.falcon.clientId.source} /></span>}
          name="falcon_clientId"
          type="text"
          placeholder={status.falcon.clientId.source !== "missing" ? "•• keep saved value ••" : "Falcon API client ID"}
          hint="In Falcon Console: Support → API Clients and Keys. Grant the permissions for the surfaces you plan to use (the checklist above shows the full set)."
          value={falconClientId}
          onChange={setFalconClientId}
        />
        <Field
          label={<span>Client secret <SourceBadge source={status.falcon.clientSecret.source} /></span>}
          name="falcon_clientSecret"
          type="password"
          placeholder={status.falcon.clientSecret.source !== "missing" ? "•• keep saved value ••" : "Falcon API client secret"}
          value={falconClientSecret}
          onChange={setFalconClientSecret}
        />
        <Field
          label={<span>Base URL <SourceBadge source={status.falcon.baseUrl.source} /></span>}
          name="falcon_baseUrl"
          type="text"
          placeholder={status.falcon.baseUrl.value}
          hint="Pick the regional endpoint for your tenant: US-1, US-2, EU-1, or US-GOV."
          value={falconBaseUrl}
          onChange={setFalconBaseUrl}
        />
        <Field
          label={<span>Member CID <SourceBadge source={status.falcon.memberCid.source} /></span>}
          name="falcon_memberCid"
          type="text"
          placeholder="(MSSP / Flight Control only)"
          hint="Optional. Set this only when authenticating against a parent tenant and scoping to a child tenant."
          value={falconMemberCid}
          onChange={setFalconMemberCid}
        />
      </Section>

      <Section title="Optional">
        <Field
          label={<span>IR quarantine group ID <SourceBadge source={status.irQuarantineGroupId.source} /></span>}
          name="irQuarantineGroupId"
          type="text"
          placeholder="(optional — leave blank to provision in /config after registration)"
          hint="If you already have a Falcon host group set aside for incident response, paste its id. Otherwise leave blank — you'll be guided to create one from /config after registration."
          value={irGroupId}
          onChange={setIrGroupId}
        />
      </Section>

      {(testState.anthropic || testState.falcon) ? (
        <div className="space-y-2 rounded-md border border-neutral-800 bg-neutral-950 p-4 text-sm">
          {testState.anthropic ? (
            <div className={testState.anthropic.ok ? "text-emerald-400" : "text-oxblood-400"}>
              Anthropic: {testState.anthropic.message}
            </div>
          ) : null}
          {testState.falcon ? (
            <div className={testState.falcon.ok ? "text-emerald-400" : "text-oxblood-400"}>
              Falcon: {testState.falcon.message}
            </div>
          ) : null}
        </div>
      ) : null}

      {registerState.error ? (
        <p className="text-sm text-oxblood-400" role="alert">{registerState.error}</p>
      ) : null}

      <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
        <button
          type="submit"
          formAction={(fd) => {
            startTransition(() => testFormAction(fd));
          }}
          disabled={testPending || registerPending}
          className="rounded-md border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm font-medium text-neutral-200 hover:border-neutral-500 hover:text-white disabled:opacity-50"
        >
          {testPending ? "Testing…" : "Test connection"}
        </button>
        <button
          type="submit"
          disabled={registerPending || testPending}
          className="rounded-md bg-neutral-100 px-4 py-2 text-sm font-medium text-neutral-950 hover:bg-white disabled:opacity-50"
        >
          {registerPending ? "Saving…" : "Create account & save"}
        </button>
      </div>
    </form>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <fieldset className="space-y-3 rounded-md border border-neutral-800 bg-neutral-950/40 p-4">
      <legend className="px-1 text-xs font-semibold uppercase tracking-wider text-neutral-300">{title}</legend>
      {children}
    </fieldset>
  );
}

function ModeButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        active
          ? "rounded-md border border-neutral-500 bg-neutral-800 px-3 py-1 text-neutral-100"
          : "rounded-md border border-neutral-800 bg-neutral-950 px-3 py-1 text-neutral-400 hover:border-neutral-700 hover:text-neutral-200"
      }
    >
      {children}
    </button>
  );
}

function Field({
  label,
  name,
  type,
  placeholder,
  hint,
  value,
  onChange,
  readOnly,
}: {
  label: React.ReactNode;
  name: string;
  type: "text" | "password";
  placeholder?: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  readOnly?: boolean;
}) {
  return (
    <div>
      <label htmlFor={name} className={labelClass}>{label}</label>
      <input
        id={name}
        name={name}
        type={type}
        placeholder={placeholder}
        className={`${inputClass}${readOnly ? " cursor-not-allowed bg-neutral-900 text-neutral-400" : ""}`}
        autoComplete="off"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        readOnly={readOnly}
      />
      {hint ? <p className={hintClass}>{hint}</p> : null}
    </div>
  );
}
