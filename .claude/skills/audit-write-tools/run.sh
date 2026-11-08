#!/usr/bin/env bash
# audit-write-tools — verify every write-shaped sidecar tool is approval-gated
# and no runAgentLoop callsite passes a `requiresApproval: () => false` bypass.
set -euo pipefail

cd "$(dirname "$0")/../../.."  # repo root

BOLD=$'\033[1m'; GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; DIM=$'\033[2m'; NC=$'\033[0m'

WRITE_TOOLS_FILE="lib/mcp/write-tools.ts"
SIDECAR="falcon-extras/server.py"

# Read newline-delimited stdin into the named array. Portable replacement for
# `mapfile -t` (Bash 4+), which the macOS system bash (3.2) lacks.
read_into() {
  local __name="$1" __line
  eval "$__name=()"
  while IFS= read -r __line; do
    eval "$__name+=(\"\$__line\")"
  done
}

# Tools matching write-shape regex but intentionally NOT gated. See SKILL.md
# for rationale per entry.
ALLOWLIST=(
  "extras_rtr_check_patch_status"  # polls in-flight cloud_request_ids only
)

# Pull every gated tool name from the registry (anything inside the
# REQUIRES_APPROVAL Set, double- or single-quoted, ignoring `// …` comments).
read_into GATED < <(
  awk '/REQUIRES_APPROVAL/,/\]\)/' "$WRITE_TOOLS_FILE" \
    | sed 's://.*$::' \
    | grep -oE '"[a-z_][a-z0-9_]+"' \
    | tr -d '"' \
    | sort -u
)

# Find sidecar tools whose name matches the write-shape regex.
read_into SIDECAR_WRITE_CANDIDATES < <(
  grep -oE '^def extras_[a-z0-9_]+' "$SIDECAR" \
    | sed 's/^def //' \
    | grep -E '^(extras_(create|delete|update|add|remove|close|save)_|extras_host_(contain|lift_containment|group_(add|remove)_members)|extras_workflows_execute|extras_rtr_run_(patch|cleanup|falcon_script)|extras_update_detection_status|extras_rtr_check_patch_status)' \
    | sort -u
)

# Hard-coded upstream falcon-mcp tools that mutate. Mirrors the registry's
# upstream block; if the project ever adopts new upstream write tools (RTR
# active-responder, etc.) add them here AND to the registry.
UPSTREAM_WRITES=(
  "falcon_add_ioc"
  "falcon_remove_iocs"
  "falcon_create_firewall_rule_group"
  "falcon_delete_firewall_rule_groups"
  "falcon_create_ioa_rule"
  "falcon_create_ioa_rule_group"
  "falcon_update_ioa_rule"
  "falcon_update_ioa_rule_group"
  "falcon_delete_ioa_rules"
  "falcon_delete_ioa_rule_groups"
  "falcon_launch_scheduled_report"
  # falcon-mcp 0.10.0: cases module (replaced removed incidents module)
  "falcon_create_case"
  "falcon_update_case"
  "falcon_add_case_alert_evidence"
  "falcon_add_case_event_evidence"
  "falcon_manage_case_tags"
  # falcon-mcp 0.10.0: cloud (CSPM) + shield (SaaS Security) modules
  "falcon_create_cspm_suppression_rule"
  "falcon_delete_cspm_suppression_rules"
  "falcon_dismiss_shield_check"
  # falcon-mcp 0.11.0: quarantine + correlationrules modules
  "falcon_update_quarantined_files"
  "falcon_delete_quarantined_files"
  "falcon_create_correlation_rule"
  "falcon_update_correlation_rule"
  "falcon_delete_correlation_rules"
)

# Native detections / host_groups / exclusions / policies writes (falcon-mcp
# 0.12.0), split into two categories by the 0.6.7 reconciliation:
#
# NATIVE_WRITES (below) = the 8 SUPPRESSED. Unlike UPSTREAM_WRITES above
# (exposed + gated), these are hidden at the bridge (NATIVE_WRITE_SUPPRESS in
# tool-bridge.ts) so they never reach the agent — each has a richer FalconPy
# twin whose pre-write / in-sidecar value-add can't be re-injected onto a native
# path (verdict-tag canonicalization, zero-width pre-flight, canonical naming +
# auto-save, disable-before-delete), or is fleet-wide with no curated path
# (set_policy_precedence). Invariant: each must be BOTH suppressed AND gated.
#
# NATIVE_ADOPTED (further below) = the 5 ADOPTED. These have no twin or only a
# thin by-id twin, so native is the agent's primary write path — exposed + gated
# like UPSTREAM_WRITES. Invariant: each must be gated AND NOT suppressed.
#
# The two lists must stay DISJOINT and together cover all 13 native 0.12.0
# writes. If a future 0.12.x adds or renames a native write, re-run the offline
# list_tools() dump and classify it into one list — the drift guard below flags
# any suppress-set entry missing from NATIVE_WRITES.
NATIVE_WRITES=(
  "falcon_update_detections"
  "falcon_create_exclusion"
  "falcon_update_exclusion"
  "falcon_create_host_group"
  "falcon_perform_host_group_action"
  "falcon_create_policy"
  "falcon_delete_policies"
  "falcon_set_policy_precedence"
  # falcon-mcp 0.17.0 Fusion SOAR — KEEP: twin extras_workflows_execute resolves
  # the on-demand trigger before executing; native takes a bare definition id.
  "falcon_execute_workflow"
  # falcon-mcp 0.20.0 Data Security (#576) — KEEP: the create twins
  # (extras_create_data_protection_*) apply monitor-first defaults pre-write.
  "falcon_create_data_security_entity"
  # eyas-mcp's sidecar port — native ports of sidecar writes, held until their
  # family migrates (contain/lift: IR ledger). Multi-host read-only RTR and
  # run_falcon_script are annotation-exempt read-only, not listed here.
  "falcon_contain_hosts"
  "falcon_lift_host_containment"
)

# The adopted natives — exposed to the agent (NOT in NATIVE_WRITE_SUPPRESS) and
# gated via REQUIRES_APPROVAL. No twin, or only a thin by-id twin, so there's no
# curated behavior to regress by letting the agent call native directly.
NATIVE_ADOPTED=(
  "falcon_delete_exclusions"
  "falcon_update_host_group"
  "falcon_delete_host_groups"
  "falcon_update_policy"
  "falcon_perform_policy_action"
  # falcon-mcp 0.16.0 #487 — host grouping-tag write. No sidecar twin (Eyas
  # quarantines via static host-group membership, not FalconGroupingTags), so
  # adopted: exposed + gated, never suppressed.
  "falcon_manage_host_grouping_tags"
  # falcon-mcp 0.17.0 AgentWorks — invoke a Charlotte AI agent. No sidecar twin;
  # user-approved adopt (exposed + gated, never suppressed) — the approval gate
  # keeps agent-invocation human-in-the-loop.
  "falcon_invoke_agentworks_agent"
  # falcon-mcp 0.20.0 Data Security — edit any DLP entity (policy, pattern,
  # classification, …). No sidecar twin; user-approved adopt (exposed + gated).
  "falcon_update_data_security_entity"
)

BRIDGE_FILE="lib/mcp/tool-bridge.ts"
# Pull the names inside the NATIVE_WRITE_SUPPRESS Set (same shape as GATED).
read_into SUPPRESSED < <(
  awk '/NATIVE_WRITE_SUPPRESS: ReadonlySet/,/\]\)/' "$BRIDGE_FILE" \
    | sed 's://.*$::' \
    | grep -oE '"[a-z_][a-z0-9_]+"' \
    | tr -d '"' \
    | sort -u
)

is_gated() {
  local name="$1"
  for g in "${GATED[@]}"; do [[ "$g" == "$name" ]] && return 0; done
  return 1
}

is_suppressed() {
  local name="$1"
  for s in "${SUPPRESSED[@]}"; do [[ "$s" == "$name" ]] && return 0; done
  return 1
}

is_allowlisted() {
  local name="$1"
  for a in "${ALLOWLIST[@]}"; do [[ "$a" == "$name" ]] && return 0; done
  return 1
}

fail=0
total_candidates=0
total_gated=0

echo "${BOLD}Sidecar write-shape tools${NC}"
for t in "${SIDECAR_WRITE_CANDIDATES[@]}"; do
  total_candidates=$((total_candidates+1))
  if is_gated "$t"; then
    echo "  ${GREEN}✓${NC} $t ${DIM}(gated)${NC}"
    total_gated=$((total_gated+1))
  elif is_allowlisted "$t"; then
    echo "  ${GREEN}✓${NC} $t ${DIM}(allowlisted — read-only)${NC}"
  else
    echo "  ${RED}✗${NC} $t ${RED}(UNGATED — add to REQUIRES_APPROVAL)${NC}"
    fail=1
  fi
done

echo
echo "${BOLD}Upstream falcon-mcp write tools${NC}"
for t in "${UPSTREAM_WRITES[@]}"; do
  total_candidates=$((total_candidates+1))
  if is_gated "$t"; then
    echo "  ${GREEN}✓${NC} $t ${DIM}(gated)${NC}"
    total_gated=$((total_gated+1))
  else
    echo "  ${RED}✗${NC} $t ${RED}(UNGATED)${NC}"
    fail=1
  fi
done

echo
echo "${BOLD}Native falcon-mcp 0.12.0 writes (suppressed + gated)${NC}"
for t in "${NATIVE_WRITES[@]}"; do
  total_candidates=$((total_candidates+1))
  sup=no; gat=no
  is_suppressed "$t" && sup=yes
  is_gated "$t" && gat=yes
  if [[ "$sup" == yes && "$gat" == yes ]]; then
    echo "  ${GREEN}✓${NC} $t ${DIM}(suppressed + gated)${NC}"
    total_gated=$((total_gated+1))
  elif [[ "$sup" == yes && "$gat" == no ]]; then
    echo "  ${RED}✗${NC} $t ${RED}(suppressed but NOT gated — add to REQUIRES_APPROVAL backstop)${NC}"
    fail=1
  elif [[ "$sup" == no && "$gat" == yes ]]; then
    echo "  ${RED}✗${NC} $t ${RED}(gated but NOT suppressed — agent can still SEE it; add to NATIVE_WRITE_SUPPRESS)${NC}"
    fail=1
  else
    echo "  ${RED}✗${NC} $t ${RED}(neither suppressed NOR gated — native write reachable ungated!)${NC}"
    fail=1
  fi
done
# Drift guard: a name in NATIVE_WRITE_SUPPRESS not in this audit's list means
# 0.12.x added/renamed a native write — re-dump list_tools() and update above.
for s in "${SUPPRESSED[@]}"; do
  known=no
  for t in "${NATIVE_WRITES[@]}"; do [[ "$t" == "$s" ]] && known=yes; done
  if [[ "$known" == no ]]; then
    echo "  ${RED}✗${NC} $s ${RED}(in NATIVE_WRITE_SUPPRESS but not in this audit — update NATIVE_WRITES)${NC}"
    fail=1
  fi
done

echo
echo "${BOLD}Native falcon-mcp 0.12.0 writes (adopted — exposed + gated)${NC}"
for t in "${NATIVE_ADOPTED[@]}"; do
  total_candidates=$((total_candidates+1))
  sup=no; gat=no
  is_suppressed "$t" && sup=yes
  is_gated "$t" && gat=yes
  if [[ "$gat" == yes && "$sup" == no ]]; then
    echo "  ${GREEN}✓${NC} $t ${DIM}(adopted — exposed + gated)${NC}"
    total_gated=$((total_gated+1))
  elif [[ "$gat" == yes && "$sup" == yes ]]; then
    echo "  ${RED}✗${NC} $t ${RED}(adopted but still SUPPRESSED — remove from NATIVE_WRITE_SUPPRESS)${NC}"
    fail=1
  elif [[ "$gat" == no && "$sup" == no ]]; then
    echo "  ${RED}✗${NC} $t ${RED}(adopted but NOT gated — add to REQUIRES_APPROVAL)${NC}"
    fail=1
  else
    echo "  ${RED}✗${NC} $t ${RED}(suppressed AND ungated — misconfigured adopted native)${NC}"
    fail=1
  fi
done

# Disjointness: a native write must be in exactly one list, never both.
for w in "${NATIVE_WRITES[@]}"; do
  for a in "${NATIVE_ADOPTED[@]}"; do
    if [[ "$w" == "$a" ]]; then
      echo "  ${RED}✗${NC} $w ${RED}(in BOTH NATIVE_WRITES and NATIVE_ADOPTED — lists must be disjoint)${NC}"
      fail=1
    fi
  done
done

# Allowlist drift — entries pointing at tools that no longer exist.
echo
echo "${BOLD}Allowlist freshness${NC}"
for a in "${ALLOWLIST[@]}"; do
  if grep -q "^def $a\b" "$SIDECAR"; then
    echo "  ${GREEN}✓${NC} $a ${DIM}(present in sidecar)${NC}"
  else
    echo "  ${RED}✗${NC} $a ${RED}(stale — remove from ALLOWLIST in run.sh)${NC}"
    fail=1
  fi
done

# Registry entries pointing at tools the sidecar / upstream list no longer
# advertises. Cheap form: grep each gated name in the sidecar OR the upstream
# list OR either native-writes list; if absent from all, flag. Suppressed
# NATIVE_WRITES are gated as a fail-closed backstop (no sidecar def); adopted
# NATIVE_ADOPTED are gated + exposed (also no sidecar def) — both resolve here
# via the native lists rather than a sidecar `def`.
echo
echo "${BOLD}Registry freshness${NC}"
known_upstream=$(printf '%s\n' "${UPSTREAM_WRITES[@]}" "${NATIVE_WRITES[@]}" "${NATIVE_ADOPTED[@]}")
for g in "${GATED[@]}"; do
  if grep -q "^def $g\b" "$SIDECAR" || echo "$known_upstream" | grep -qx "$g"; then
    : # ok
  else
    echo "  ${RED}✗${NC} $g ${RED}(in registry but no sidecar def + not in upstream/native list)${NC}"
    fail=1
  fi
done
echo "  ${GREEN}✓${NC} all ${#GATED[@]} registry entries resolve"

echo
echo "${BOLD}runAgentLoop callsites${NC}"
# Every file that imports runAgentLoop. Scan each for an explicit
# requiresApproval: <expr> property assignment (must be on a runAgentLoop
# call argument; comments tolerated).
read_into CALLERS < <(
  grep -rl "from \"@/lib/chat/agent-loop\"" --include="*.ts" --include="*.tsx" app/ lib/ 2>/dev/null \
    | grep -v "lib/chat/agent-loop.ts" \
    | sort -u
)
override_hits=0
for f in "${CALLERS[@]}"; do
  # Strip leading whitespace before the property to avoid matching JSDoc
  # references; a real argument has indent + property + colon.
  hits=$(grep -nE "^[[:space:]]+requiresApproval[[:space:]]*:" "$f" || true)
  if [[ -n "$hits" ]]; then
    while IFS= read -r line; do
      lineno=${line%%:*}
      content=${line#*:}
      content=${content#:}
      # Tolerate the `// pass requiresApproval: …` comment idiom — only
      # the actual property assignment is a fail.
      stripped=$(printf "%s" "$content" | sed -E 's|//.*$||' | sed -E 's|^[[:space:]]+||')
      if [[ "$stripped" =~ ^requiresApproval[[:space:]]*: ]]; then
        echo "  ${RED}✗${NC} $f:$lineno ${RED}(override — neutralizes registry)${NC}"
        echo "      ${DIM}${content## }${NC}"
        override_hits=$((override_hits+1))
        fail=1
      fi
    done <<< "$hits"
  fi
done
if [[ "$override_hits" -eq 0 ]]; then
  echo "  ${GREEN}✓${NC} ${#CALLERS[@]} callsites · no overrides ${DIM}(registry default fires)${NC}"
fi

# Sub-agent loop guard. runSubAgent has no operator-facing approval dialog,
# so it MUST filter write-shape tools out of the model's visible toolset
# (defense at the filter layer, not the gate layer). Verify the guard is
# still in place.
echo
echo "${BOLD}Sub-agent write-tool guard${NC}"
SUB_AGENT="lib/chat/sub-agent.ts"
if [[ -f "$SUB_AGENT" ]]; then
  if grep -q "defaultRequiresApproval" "$SUB_AGENT" \
     && grep -q "if (defaultRequiresApproval(name)) return false" "$SUB_AGENT"; then
    echo "  ${GREEN}✓${NC} $SUB_AGENT filters write tools at toolFilter layer"
  else
    echo "  ${RED}✗${NC} $SUB_AGENT missing the write-tool filter guard"
    echo "      ${DIM}Sub-agents have no approval dialog — write tools must be invisible to them.${NC}"
    fail=1
  fi
else
  echo "  ${DIM}(no sub-agent.ts present — skipping)${NC}"
fi

# Annotation approval backstop. falcon-mcp 0.13.0 sets MCP tool annotations
# (readOnlyHint:false on every write). The bridge collects VISIBLE native writes
# into annotatedNativeWrites; the agent loop gates on requiresApproval(name) OR
# that set, so a native write added in a future falcon-mcp bump — but not yet in
# REQUIRES_APPROVAL — still gates fail-closed (and logs drift) instead of firing
# ungated. This is a structural check that the wiring exists; the LIVE drift
# check (which native writes are annotated-but-ungated on the configured
# version) surfaces on /agent-toolbox via the catalog's driftWarnings.
echo
echo "${BOLD}Annotation approval backstop${NC}"
AGENT_LOOP="lib/chat/agent-loop.ts"
if grep -q "annotatedNativeWrites" "$BRIDGE_FILE" \
   && grep -q "annotatedNativeWrites" "$AGENT_LOOP"; then
  echo "  ${GREEN}✓${NC} bridge exposes annotatedNativeWrites · agent loop gates on it"
else
  echo "  ${RED}✗${NC} annotation backstop wiring missing (bridge annotatedNativeWrites / agent-loop union)"
  echo "      ${DIM}A native write dropped from REQUIRES_APPROVAL would fire ungated.${NC}"
  fail=1
fi

echo
if [[ "$fail" -eq 0 ]]; then
  echo "${GREEN}${BOLD}PASS${NC} · $total_gated gated / $total_candidates candidates · 0 bypasses · 0 stale registry entries"
  exit 0
else
  echo "${RED}${BOLD}FAIL${NC} · see findings above"
  exit 1
fi
