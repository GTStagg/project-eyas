import "server-only";

// Shape of a single posture capture. Every metric is `number | null`; null means
// the category could not be captured for this tenant (missing scope, upstream
// error, or a parse miss) — the snapshot's `partial` flag is set when any metric
// is null. Add fields freely: the storage column is JSON (posture_snapshots.
// metrics_json), so new metrics need no migration. Bump POSTURE_SCHEMA_VERSION
// only when the shape changes in a way a reader must branch on.

export const POSTURE_SCHEMA_VERSION = 1;

export type Metric = number | null;

export type PostureMetrics = {
  detections: {
    open: Metric;
    critical: Metric;
    high: Metric;
    contained_hosts: Metric;
    at_risk_hosts: Metric;
    campaigns: Metric;
  };
  vulns: {
    open_critical: Metric;
    open_high: Metric;
    kev: Metric;
    actively_exploited: Metric;
    affected_hosts: Metric;
  };
  coverage: {
    managed: Metric;
    unmanaged: Metric;
    stale_hosts: Metric;
    privileged_accounts: Metric;
    local_admins: Metric;
    suspicious_apps: Metric;
  };
  identity: {
    risky_entities: Metric;
    idp_detections_7d: Metric;
    policy_rules_enabled: Metric;
  };
  prevention: {
    policies_preventing: Metric;
    policies_detect_only: Metric;
  };
  dataProtection: {
    policies_enabled: Metric;
    content_patterns: Metric;
  };
  cases: {
    total: Metric;
    open: Metric;
    unassigned: Metric;
    high_sev: Metric;
  };
};

export type PostureCategory = keyof PostureMetrics;

// A stored snapshot, decoded from the DB row.
export type PostureSnapshot = {
  id: number;
  capturedAt: string;
  envId: string;
  schemaVersion: number;
  metrics: PostureMetrics;
  captureMs: number | null;
  partial: boolean;
};

// All-null starting point. Each capture fills in the categories it can reach;
// whatever stays null marks the snapshot partial.
export function emptyPostureMetrics(): PostureMetrics {
  return {
    detections: {
      open: null,
      critical: null,
      high: null,
      contained_hosts: null,
      at_risk_hosts: null,
      campaigns: null,
    },
    vulns: {
      open_critical: null,
      open_high: null,
      kev: null,
      actively_exploited: null,
      affected_hosts: null,
    },
    coverage: {
      managed: null,
      unmanaged: null,
      stale_hosts: null,
      privileged_accounts: null,
      local_admins: null,
      suspicious_apps: null,
    },
    identity: {
      risky_entities: null,
      idp_detections_7d: null,
      policy_rules_enabled: null,
    },
    prevention: {
      policies_preventing: null,
      policies_detect_only: null,
    },
    dataProtection: {
      policies_enabled: null,
      content_patterns: null,
    },
    cases: {
      total: null,
      open: null,
      unassigned: null,
      high_sev: null,
    },
  };
}

// True if any leaf metric is still null — used to set the snapshot's partial flag.
export function metricsArePartial(m: PostureMetrics): boolean {
  return Object.values(m).some((category) =>
    Object.values(category as Record<string, Metric>).some((v) => v === null),
  );
}
