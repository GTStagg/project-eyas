# IR quarantine prerequisites

The agentic IR workflow assumes three Falcon-side artifacts exist before a host can be IR'd cleanly. The /config "IR quarantine setup" card stands them up automatically; this document is the reference for what gets created, why, and how to verify it manually.

The workflow does **not** audit these artifacts at runtime. The contract is set up once, then trusted. If the workflow misbehaves silently, the cause is almost always one of the three artifacts being misconfigured — re-run the /config card to re-detect and re-provision.

## The three artifacts

### 1. IR quarantine host group

**Canonical name:** `Project Eyas - IR Quarantine`
**Type:** static
**Created by:** `extras_create_quarantine_host_group`

A static host group that hosts get added to during Phase 1 of an IR run and removed from during Phase 4. Static (not dynamic) so the workflow can `add-members` / `remove-members` directly via the Falcon API.

If you already have your own quarantine group from a prior workflow, paste its id into the active environment's IR quarantine group field on /config. The setup card will detect it and offer to standardize the prevention policies attached to it (see migration cases below).

### 2. Three platform-specific prevention policies

**Canonical names:**
- `Project Eyas - IR Quarantine (auto, windows)`
- `Project Eyas - IR Quarantine (auto, mac)`
- `Project Eyas - IR Quarantine (auto, linux)`

**Created by:** `extras_provision_quarantine_policy`

Falcon prevention policies are per-platform; you need three of them, all attached to the single host group above. The provisioning step pushes:

- **Every slider** on the policy — `OnSensorMLSlider`, `CloudAntiMalware`, `AdwarePUP`, plus any platform-specific detection-only sliders — to `AGGRESSIVE` on both detection and prevention.
- **Every behavioral toggle** (script monitoring, encoded-command monitoring, volume-shadow-copy audit/protection, suspicious-process protection, registry-persistence detection, etc.) to `enabled = true`.

`AGGRESSIVE` is the deliberate ceiling for sliders. `EXTRA_AGGRESSIVE` is well-known to false-positive on legitimate cleanup tooling (signed `Remove-AppxPackage` descendants, signed installer uninstallers) even with the IR-readiness exclusion in place. The `(auto, <platform>)` suffix marks these policies as app-managed; if you later want to migrate to your own policies, you know which ones to delete.

The toggle-flip happens by shape (settings whose `value` is `{enabled: bool}`) rather than by a hard-coded enumeration, so the policy schema can evolve without app changes — any new toggle Falcon adds in a future release will be enabled by the next run of the provisioning step.

### 3. IR-readiness IOA exclusion

**Canonical name:** `Project Eyas IR — RTR runscript preamble`
**Created by:** `extras_provision_quarantine_policy` (pre-warmed at provisioning time, bundled into the same approval as the policy chain)

RTR's `runscript -CloudFile=<name>` transport invokes PowerShell on the host with a fixed `-EncodedCommand` preamble that decodes to `Set-Location 'C:\'`. The aggressive prevention policy's `PShellMimikatz` (and other PowerShell-encoded-command behavioral rules) will block that preamble at the sensor — every Phase 2 cleanup primitive returns `batch_init_sessions: no successful hosts initialized on RTR` and Phase 3 reports findings as still present.

The exclusion suppresses that specific preamble's pattern on hosts in the IR quarantine group only. Production hosts retain full coverage.

**Pre-warmed at provisioning:** the exclusion is installed eagerly as part of `extras_provision_quarantine_policy` rather than JIT during the first IR engagement. Sensor-side propagation of a new IOA exclusion takes 60–90 seconds typically, sometimes minutes. Installing the exclusion at IR Phase 0 (JIT) would make the first IR engagement on a freshly-provisioned tenant pay *two* propagation hits — exclusion install → sensors, then the host's group-add → that host's sensor — and routinely blow past the 5-minute Phase 1.5 wait ceiling. Pre-warming at provisioning means the exclusion has been on every sensor in the group well before any IR engagement fires, and the only propagation cost remaining at IR time is the group-add itself.

**Idempotency:** re-running provisioning is safe — `_ensure_readiness_exclusion` checks for the exclusion's presence first and `extras_create_ioa_exclusion` runs a server-side `(pattern_id, ifn_regex)` duplicate guard. Re-run after a tenant change (active environment switch, group recreation) without worrying about duplicates.

**Fresh-tenant caveat:** the exclusion needs a concrete `pattern_id` for the PShellMimikatz behavior pattern, resolved from the tenant's most recent PShellMimikatz detection. On a brand-new tenant that has never seen one fire, the pattern_id can't be resolved; provisioning logs a `pattern_id_unresolved: true` warning and the JIT fallback path kicks in for the first IR engagement (`extras_diagnose_ir_readiness` surfaces an `extras_create_ioa_exclusion` remediation at Phase 0, which the agent fires inline behind a separate approval). After the first PShellMimikatz fires, re-run `/config` provisioning and the eager-install path takes over.

## Migration cases

The /config setup card detects which case your tenant is in and surfaces the right CTA:

- **Case A — group with no dedicated prevention policy.** The host group exists (you set its id manually) but no Falcon prevention policy is attached. The "Adopt + standardize" CTA creates the three platform policies and attaches them. Zero churn to existing infrastructure.

- **Case B — group with a single-attachment dedicated policy.** Your group has its own prevention policy attached only to that group. The "Adopt + standardize" CTA renames it to canonical naming, pushes the AGGRESSIVE sliders, and creates the IR-readiness exclusion. Your group id stays in `data/eyas.db`; nothing else moves.

- **Case C — group whose policy is also attached to other groups.** Pushing AGGRESSIVE settings to your existing policy would change posture on the other groups it's attached to. The "Create dedicated" CTA creates a brand-new dedicated policy bound only to your IR quarantine group, leaves your existing policy untouched, and creates the IR-readiness exclusion. You can manually decommission the old policy from Falcon Console *if you choose*; the workflow doesn't depend on it.

## What happens at IR time

The workflow trusts the contract above. The only timing concern it actively manages is propagation:

- **Phase 1 — Quarantine.** Host is added to the IR quarantine group. Falcon's backend writes the membership; the sensor will receive the new prevention policy + IOA exclusion within 60–90 seconds typically.

- **Phase 1.5 — Wait for sensor-side propagation.** The workflow blocks on `extras_rtr_wait_until_ready` until a probe `runscript -CloudFile=` round-trip succeeds (or a 5-minute ceiling is reached). This is the gate that ensures Phase 2 cleanup actually executes rather than silently no-op'ing.

- **Phases 2–4** proceed normally. The workflow does not audit the prevention policy mid-run.

If a Phase 2 cleanup primitive returns `batch_init_sessions: 404` *after* Phase 1.5 returned ready, that's mid-run sensor degradation, not a policy block; the workflow retries before declaring failure.

## Verifying manually in Falcon Console

If you want to inspect the artifacts without the /config card:

- **Host group:** Endpoint security → Host Setup → Host groups → search for "Project Eyas".
- **Prevention policies:** Endpoint security → Prevention policies → filter by name "Project Eyas". Three rows (Windows / macOS / Linux).
- **IOA exclusion:** Endpoint security → Exclusions → IOA exclusions → search for "Project Eyas". One entry, scoped to the IR quarantine group.

## Decommissioning

To remove app-managed artifacts:

1. Detach hosts from the IR quarantine group (Falcon Console → Host group → remove members).
2. Remove the prevention policies' host-group attachment, then disable + delete the three policies.
3. Delete the IOA exclusion.
4. Delete the host group.
5. Clear `irQuarantineGroupId` on the active environment via /config.

The workflow will then refuse to launch IR (the `extras_diagnose_ir_readiness` check returns `ready: false`) until you re-provision.
