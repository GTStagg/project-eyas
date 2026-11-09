"use client";

// Shared capability gate for the primary navigation. Hides nav items whose
// underlying Falcon scope isn't granted on the active tenant. Extracted from the
// old Sidebar so the persistent IconRail and the mobile drawer resolve visibility
// from ONE source (they must never disagree).
//
// Default is "everything visible": we never hide a real surface before the probe
// answers, and never hide anything if the probe fails. Each capability is checked
// with === false so missing/undefined defaults to "show". /api/health is
// module-cached for 30s.

import { useEffect, useMemo, useState } from "react";
import { NAV_GROUPS, type NavGroup } from "@/lib/nav";

export function useNavGating(): { visibleGroups: NavGroup[]; hiddenHrefs: Set<string> } {
  const [hiddenHrefs, setHiddenHrefs] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    let cancelled = false;
    fetch("/api/health", { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => {
        if (cancelled) return;
        const hidden = new Set<string>();
        const ec = j?.falconExtras?.capabilities ?? {};
        const mc = j?.falconMcp?.capabilities ?? {};
        if (mc.idp === false) hidden.add("/identity");
        // /pivot stays visible even without Threat Graph scope — cross-source
        // lookup still works; lineage mode just shows a scope-pending message.
        if (mc.malQuery === false) hidden.add("/malquery");
        if (mc.recon === false) hidden.add("/recon");
        if (mc.workflows === false) hidden.add("/workflows");
        if (ec.discover === false) hidden.add("/discover");
        if (mc.intel === false) hidden.add("/intel");
        if (mc.cases === false) hidden.add("/cases");
        if (mc.quarantine === false) hidden.add("/quarantine");
        if (mc.correlationRules === false) hidden.add("/correlation");
        if (mc.dataProtection === false) hidden.add("/data-protection");
        setHiddenHrefs(hidden);
      })
      .catch(() => {
        // On failure, keep everything visible — the page itself short-circuits
        // cleanly via its scope-pending check.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Items are alphabetized by label within each group (display order only —
  // group order and the source NAV_GROUPS are untouched). Both the IconRail
  // flyout and the mobile drawer render from this, so they stay in sync.
  const visibleGroups = useMemo<NavGroup[]>(() => {
    const byLabel = (a: { label: string }, b: { label: string }) =>
      a.label.localeCompare(b.label);
    return NAV_GROUPS.map((g) => ({
      ...g,
      items: g.items.filter((item) => !hiddenHrefs.has(item.href)).sort(byLabel),
    })).filter((g) => g.items.length > 0);
  }, [hiddenHrefs]);

  return { visibleGroups, hiddenHrefs };
}
