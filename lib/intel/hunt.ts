// Intel-to-tenant hunt matcher. Pure function: top recent Falcon Intel
// indicators × tenant detections × tenant custom IOC list → matches with
// context. Reverse direction of /intel's actor-exposure flow: that one
// goes detections → actors; this one goes recent intel IOCs → "did they
// touch us?".

import type { Detection } from "@/components/DetectionsTable";
import { readStringList } from "./attribution";

export type IntelIndicator = {
  indicator?: string; // hash / domain / ip value
  type?: string; // sha256, sha1, md5, domain, ip_address, ipv4, ipv6, url
  malicious_confidence?: string;
  published_date?: number; // epoch seconds
  last_updated?: number;
  malware_families?: string[];
  actors?: string[];
  threat_types?: string[];
};

export type CustomIoc = {
  type?: string;
  value?: string;
  action?: string;
  severity?: string;
  description?: string;
};

export type IntelHuntMatch = {
  indicator: string;
  indicator_type: string;
  malicious_confidence?: string;
  malware_families: string[];
  actors: string[];
  // Tenant evidence:
  detection_hits: number;
  detection_hosts: string[]; // unique hostnames where this hash fired
  detection_sample_ids: string[]; // sample composite_ids
  on_custom_ioc_list: boolean;
  custom_ioc_action?: string;
  // Recommended action (decision-document shape):
  verdict: "active_in_tenant" | "watchlist_only" | "covered_by_intel";
  reasons: string[];
};

const HIGH_CONFIDENCE = new Set(["high", "medium"]);

function normalize(s?: string): string {
  return (s ?? "").trim().toLowerCase();
}

export function matchIntelToTenant(
  indicators: IntelIndicator[],
  detections: Detection[],
  customIocs: CustomIoc[],
): IntelHuntMatch[] {
  // Build lookups: detection by sha256/md5/sha1 (case-insensitive); IOC by
  // value (case-insensitive). Only hash-typed indicators get cross-checked
  // against detections — domains/IPs would need a different pass over
  // network_accesses or NGSIEM, which is out of scope here.
  const detByHash = new Map<string, Detection[]>();
  for (const d of detections) {
    for (const h of [d.sha256, d.md5]) {
      if (!h) continue;
      const key = normalize(h);
      if (!detByHash.has(key)) detByHash.set(key, []);
      detByHash.get(key)!.push(d);
    }
  }

  const customByValue = new Map<string, CustomIoc>();
  for (const ioc of customIocs) {
    const v = normalize(ioc.value);
    if (!v) continue;
    customByValue.set(v, ioc);
  }

  const matches: IntelHuntMatch[] = [];
  const seen = new Set<string>(); // dedup by indicator value

  for (const ind of indicators) {
    const value = normalize(ind.indicator);
    const type = normalize(ind.type);
    if (!value || seen.has(value)) continue;
    seen.add(value);

    const conf = normalize(ind.malicious_confidence);
    if (!HIGH_CONFIDENCE.has(conf)) continue; // skip low / informational

    // Falcon Intel returns these as string[] OR [{value, slug}] — readStringList
    // normalizes both so `.join()` can't emit "[object Object]" (mirrors /intel).
    const fams = readStringList(ind.malware_families);
    const actors = readStringList(ind.actors);

    const detHits = detByHash.get(value) ?? [];
    const hostSet = new Set<string>();
    for (const d of detHits) {
      const h = d.device?.hostname;
      if (h) hostSet.add(h);
    }
    const sampleIds: string[] = [];
    for (const d of detHits) {
      if (d.composite_id && sampleIds.length < 4) sampleIds.push(d.composite_id);
    }
    const onCustomList = customByValue.has(value);
    const customAction = customByValue.get(value)?.action;

    // Decision-document verdict:
    //   active_in_tenant — fired here in last window. Top priority.
    //   watchlist_only — not seen here and not on custom list. Awareness only.
    //   covered_by_intel — Intel itself blocks this tenant-wide; redundant
    //     to add a custom IOC. We can't verify the cloud reputation block
    //     status via this tool flow, but high/medium confidence Intel is
    //     conventionally already enforced.
    let verdict: IntelHuntMatch["verdict"];
    const reasons: string[] = [];
    if (detHits.length > 0) {
      verdict = "active_in_tenant";
      reasons.push(
        `${detHits.length} detection${detHits.length === 1 ? "" : "s"} on ${hostSet.size} host${hostSet.size === 1 ? "" : "s"}`,
      );
      if (onCustomList) reasons.push(`already on custom IOC list (${customAction ?? "?"})`);
      else reasons.push("not on custom IOC list");
    } else if (conf === "high") {
      verdict = "covered_by_intel";
      reasons.push("Intel high-confidence — cloud reputation block presumed");
      if (onCustomList) reasons.push(`also on custom IOC list (${customAction ?? "?"})`);
    } else {
      verdict = "watchlist_only";
      reasons.push("no tenant evidence yet");
      if (onCustomList) reasons.push(`on custom IOC list (${customAction ?? "?"})`);
    }
    if (fams.length > 0) reasons.push(`family: ${fams.slice(0, 3).join(", ")}`);
    if (actors.length > 0) reasons.push(`actor: ${actors.slice(0, 2).join(", ")}`);

    matches.push({
      indicator: value,
      indicator_type: type,
      malicious_confidence: ind.malicious_confidence,
      malware_families: fams,
      actors,
      detection_hits: detHits.length,
      detection_hosts: [...hostSet],
      detection_sample_ids: sampleIds,
      on_custom_ioc_list: onCustomList,
      custom_ioc_action: customAction,
      verdict,
      reasons,
    });
  }

  // Sort: active_in_tenant first (loudest signal), then covered_by_intel,
  // then watchlist_only. Within each tier, more detection hits / more
  // actors first.
  const tier = (m: IntelHuntMatch): number =>
    m.verdict === "active_in_tenant" ? 0 : m.verdict === "covered_by_intel" ? 1 : 2;
  matches.sort((a, b) => {
    if (tier(a) !== tier(b)) return tier(a) - tier(b);
    if (b.detection_hits !== a.detection_hits) return b.detection_hits - a.detection_hits;
    return b.actors.length - a.actors.length;
  });
  return matches;
}
