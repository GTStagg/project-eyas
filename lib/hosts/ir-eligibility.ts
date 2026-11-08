// Single source of truth for "can this host/user run guided incident response,
// and if not, why?" — shared by HostActionButtons (/hosts) and QueueTable
// (/queue) via the IrChip component so the IR affordance is identical
// everywhere. Pure (no React) so it unit-tests without a DOM.
//
// Three states, both non-eligible ones carrying a REASON so the chip can render
// greyed-with-tooltip rather than silently disappearing:
//   eligible    → chip is live and carries its hand-off instruction
//   ineligible  → host/user can't run IR (platform / RTR / no identity)
//   off         → IR isn't configured for this environment yet

export type IrEligibility =
  | { state: "eligible"; primer: string; caution?: string }
  | { state: "ineligible"; reason: string }
  | { state: "off"; reason: string };

export const IR_OFF_REASON = "Set up Incident Response in Config to enable this.";
export const IR_PLATFORM_REASON =
  "Guided incident response runs on Windows hosts with Real Time Response enabled.";
export const IR_UNIDENTIFIED_REASON = "This host can't be identified for response.";
export const IR_NO_IDENTITY_REASON =
  "No user account is associated with this detection.";

/** High-blast-radius role caution surfaced on an otherwise-eligible chip.
 *  A Domain Controller is fully IR-eligible — operators legitimately need to
 *  respond on one — but Phase 1 network containment severs domain
 *  authentication fleet-wide, so we make that consequence visible instead of
 *  letting it hide behind a chip identical to a workstation's. */
export const IR_DC_CAUTION =
  "This host is a Domain Controller — containing it cuts off sign-ins across your environment until it's released.";

/** Falcon `product_type_desc` for a domain controller. Matched loosely because
 *  the field is free-ish text ("Domain Controller"). Kept inline (not imported
 *  from the server-only ground-truth module) so this stays a pure shared file. */
function isDomainControllerRole(productTypeDesc: string | undefined): boolean {
  return /domain controller/i.test(productTypeDesc ?? "");
}

export type EndpointHost = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  rtr_state?: string;
  product_type_desc?: string;
};

/** Endpoint IR eligibility. Lenient on sparse data: only marks a host
 *  ineligible when platform/RTR explicitly say so — otherwise defers to the
 *  workflow's own checks (mirrors the prior /hosts behavior). */
export function endpointIrEligibility(
  host: EndpointHost,
  irEnabled: boolean,
): IrEligibility {
  if (!irEnabled) return { state: "off", reason: IR_OFF_REASON };
  if (!host.device_id || !host.hostname) {
    return { state: "ineligible", reason: IR_UNIDENTIFIED_REASON };
  }
  const knownIneligible =
    Boolean(host.platform_name && host.platform_name !== "Windows") ||
    Boolean(host.rtr_state && host.rtr_state !== "enabled");
  if (knownIneligible) return { state: "ineligible", reason: IR_PLATFORM_REASON };
  return {
    state: "eligible",
    primer: `Run the agentic IR workflow on host \`${host.hostname}\` (AID \`${host.device_id}\`). Load the playbook with extras_ir_workflow_playbook and proceed.`,
    ...(isDomainControllerRole(host.product_type_desc) ? { caution: IR_DC_CAUTION } : {}),
  };
}

/** Identity IR eligibility — keyed on the resolved samAccountName. */
export function identityIrEligibility(
  sam: string | undefined,
  irEnabled: boolean,
): IrEligibility {
  if (!irEnabled) return { state: "off", reason: IR_OFF_REASON };
  if (!sam) return { state: "ineligible", reason: IR_NO_IDENTITY_REASON };
  return {
    state: "eligible",
    primer: `Run the agentic identity IR workflow on user \`${sam}\`. Load the playbook with extras_identity_ir_workflow_playbook (sam_account_name=\`${sam}\`) and proceed. Phase 1's endpoint cascade will run the host IR playbook on each machine this user has been logged into recently.`,
  };
}
