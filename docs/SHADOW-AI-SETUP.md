# Shadow-AI Banned prerequisites

The Shadow-AI Banned enforcement assumes a host group + per-platform prevention policies + per-platform Custom IOA rule groups exist on the tenant. The /config "Shadow-AI Banned setup" card stands them up automatically; this document is the reference for what gets created, why, and how to verify it manually.

The model is **default-allow, opt-in to enforcement**: standard prevention policies do NOT have the Shadow-AI rule group attached; users CAN install AI tools by default. The operator only intervenes when a specific user/host needs to be blocked — they add the host to the `Project Eyas - Shadow-AI Banned` group, the banned policy wins by precedence, and the rule group fires for that host only.

The workflow does **not** audit these artifacts at runtime. The contract is set up once, then trusted.

## The four artifacts

### 1. Shadow-AI Banned host group

**Canonical name:** `Project Eyas - Shadow-AI Banned`
**Type:** static
**Created by:** `extras_create_shadow_ai_banned_host_group`

Empty by default. Operators add hosts to this group when they decide a specific user shouldn't have access to unsanctioned AI tooling. The /shadow-ai page's existing "Ban+Clean" workflow does this as part of the per-host action.

### 2. Three platform-specific prevention policies

**Canonical names:**
- `Project Eyas - Shadow-AI Banned (auto, windows)`
- `Project Eyas - Shadow-AI Banned (auto, mac)`
- `Project Eyas - Shadow-AI Banned (auto, linux)`

**Created by:** `extras_provision_shadow_ai_banned_policy`

Each platform's policy is set to AGGRESSIVE on every detection slider + every behavioral toggle enabled (same shape-based push as IR Quarantine). The `(auto, <platform>)` suffix marks them as app-managed.

**Precedence:** above standard policies, below IR Quarantine. So a host that's both Banned AND being IR'd gets IR posture (highest precedence), and a host that's just Banned gets Banned posture (above its standard groups). Normal hosts in standard groups are unaffected — the rule group only fires on hosts in the Banned group.

### 3. Three platform-specific Custom IOA rule groups

**Canonical names:**
- Windows: `Project Eyas - Shadow-AI Block`
- macOS: `Project Eyas - Shadow-AI Block (mac)`
- Linux: `Project Eyas - Shadow-AI Block (linux)`

**Created by:** `extras_shadow_ai_adopt_prevention(platform=...)` — separate approval per platform, fired as `follow_up_tool_calls` from the provisioning step.

Falcon Custom IOA rule groups are platform-scoped — a Windows-platform group can't bind to a macOS or Linux prevention policy. Each platform gets its own group with a per-platform corpus authored against the platform's Process Creation ruletype.

**Per-platform corpora:**
- Windows: 15 rules — Cursor, Ollama, LM Studio, Claude Desktop, ComfyUI, MCP servers (npm/uvx/python), Aider, Open Interpreter, DeepSeek model loads, plus 4 installer-shape rules (Squirrel/NSIS).
- macOS: 11 rules — same product set minus Windows-only installer rules; uses macOS app-bundle paths (`/Applications/<App>.app/Contents/MacOS/<binary>`).
- Linux: 10 rules — same minus Claude Desktop (no official Linux build); covers AppImage + `/opt/<vendor>/` + Homebrew/curl-installed daemons.

### 4. Shadow-AI Banned host group membership

Operator-managed. The /shadow-ai page's host action ("Ban+Clean") adds hosts; the same group's member view shows currently-banned hosts; lifting is a manual remove.

## Per-platform regex constraints

Falcon's Custom IOA regex engine differs by platform — corpora authoring has to account for this:

- **Windows:** Supports zero-width assertions (`\b`, `^`, `$`). Standard Python regex flavor.
- **macOS / Linux:** **Does NOT support zero-width assertions.** Engine is full-match-anchored implicitly — drop trailing `$`. Submitting a regex with `\b`, `^`, or `$` returns HTTP 400 "Zero-width assertions not yet implemented."
- **Rule names:** ≤ 64 characters across all platforms.
- **Comments:** No control characters (newlines, tabs). The provisioning code sanitizes before sending.

## Migration cases

The /config setup card detects which case your tenant is in and surfaces the right CTA:

- **Case A — group with no dedicated prevention policy.** "Adopt + standardize" creates the three platform policies and attaches them, then attaches the rule groups.
- **Case B — group with single-attachment dedicated policy.** "Adopt + standardize" renames the existing policy to canonical, pushes AGGRESSIVE, attaches the rule groups.
- **Case C — group with shared policy.** "Create dedicated" creates new policies bound only to the Banned group, leaves the existing shared policy alone.
- **`rules_incomplete`** — policies + bindings are correct, but the rule corpus has drifted (a prior adoption run failed to author some rules). The card shows per-platform `<actual>/<expected> rules` chips with missing-rule names on hover; the CTA composes a multi-call primer to refire `extras_shadow_ai_adopt_prevention` per affected platform.

## Tools the workflow can't uninstall (and why that's fine)

Two classes of AI tooling are handled by sanctioning + out-of-band controls rather than host-side uninstall:

### Microsoft Copilot family — never uninstalled

The Ban + Clean playbook Phase 2 explicitly stops on any Microsoft Copilot signal. Coverage includes:

- **Windows Copilot** (`Microsoft.Copilot` MSIX in WindowsApps)
- **M365 Copilot** (Word/Excel/Outlook AI features, in-process inside Office)
- **Copilot in Edge / Bing Chat** (in-process inside `msedge.exe`)
- **GitHub Copilot CLI / IDE extensions** (extensions live inside Code.exe)
- **Copilot+ PC NPU features** (system-level)

Why: `host-uninstall-appx-package` refuses any `^Microsoft\.` pattern by design — Microsoft system packages are OS-load-bearing and removal can break Windows Update or sign-in. M365 Copilot and Copilot-in-Edge are in-process features of signed Microsoft binaries with nothing separable to uninstall. The real disable levers live elsewhere:

- **GPO:** `TurnOffWindowsCopilot` (Computer Config → Admin Templates → Windows Copilot), `DisableAIDataAnalysis` for Recall on Copilot+ PCs, Edge `HubsSidebarEnabled=0` / `CopilotCdpPageContext=0`.
- **Intune:** equivalents of the above as configuration profiles.
- **M365 admin center:** license assignment / removal for Office Copilot.
- **Sanction in `/shadow-ai`:** if the org has licensed the product, flip the per-tool Sanction toggle and the signal drops from the verdict bag.

Detect-only egress IOC (Phase 4 of Ban + Clean) is still appropriate for Microsoft Copilot — it surfaces continued use as audit trail without trying to enforce on the host.

This generalizes: anything OS-baked by a vendor that owns the OS (future Apple Intelligence / Google AI / Win12 features) lands in the same lane — sanction or out-of-band, never uninstall.

### MSIX vs Squirrel distribution forms

The curated per-product uninstall scripts (`host-uninstall-claude-desktop`, `host-uninstall-cursor`, etc.) target the **Squirrel** installer form: DisplayName-based, install root under `%LOCALAPPDATA%`. They do not cover the **MSIX** form.

If Phase 0 surfaces an install with path shape `C:\Program Files\WindowsApps\<Family>_<Version>_<Arch>__<PublisherHash>` (the `__<hash>` double-underscore suffix is the MSIX signature), or `C:\Users\<user>\AppData\Local\Packages\<PublisherHash>\` (per-user MSIX staging), the playbook routes to `host-uninstall-appx-package` with `package_name_pattern=<Family>` instead. Direct `host-delete-folder` against WindowsApps is blocked (TrustedInstaller-ACLed) and would leave orphaned AppxPackaging registry entries that re-stage the package on next logon.

## What happens at enforcement time

- Operator adds a host to the Banned group → policy precedence kicks in → Banned policy wins → rule group fires for that host.
- Operator removes a host from the Banned group → host falls to its next-precedence policy (typically a standard production policy with no rule group attached) → rule group stops firing.
- No host membership-tracking complexity. No restoration logic. Pure precedence walk.

## Verifying manually in Falcon Console

- **Host group:** Endpoint security → Host Setup → Host groups → search "Shadow-AI Banned".
- **Prevention policies:** Endpoint security → Prevention policies → filter "Shadow-AI Banned". Three rows.
- **IOA rule groups:** Endpoint security → Custom IOA rule groups → search "Shadow-AI Block". Three rows.

## Decommissioning

1. Remove every host from the Banned group.
2. Detach the rule groups from their respective prevention policies (Falcon Console → policy → IOA rule groups tab → Remove). Or `extras_detach_prevention_policy_from_host_group` for the policy↔group binding.
3. Disable + delete the three rule groups.
4. Disable + delete the three prevention policies.
5. Delete the host group.
6. Clear `shadowAiBannedGroupId` on the active environment via /config.
