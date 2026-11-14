// Types and labels for the curated NGSIEM playbooks. Kept apart from the
// playbook data so client code can import them without pulling the query
// text into the browser bundle.

export type PlaybookOs = "win" | "mac" | "lin";

export const OS_LABEL: Record<PlaybookOs, string> = {
  win: "Windows",
  mac: "macOS",
  lin: "Linux",
};

export type PlaybookCategory =
  | "initial-access"
  | "credential-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "lateral-movement"
  | "defense-evasion"
  | "discovery"
  | "command-and-control"
  | "impact"
  | "shadow-ai"
  | "supply-chain";

export type NgsiemPlaybook = {
  id: string;
  title: string;
  description: string;
  mitre: string[];
  category: PlaybookCategory;
  /** Which OS platform(s) the query targets — drives the badges in the UI. */
  os: PlaybookOs[];
  repository:
    | "search-all"
    | "investigate_view"
    | "third-party"
    | "falcon_for_it_view"
    | "forensics_view";
  /** Time window in hours; the API will pass an ISO `start` derived from now. */
  windowHours: number;
  cql: string;
  source: string;
  author: string;
};

export const CATEGORY_LABEL: Record<PlaybookCategory, string> = {
  "initial-access": "Initial Access",
  "credential-access": "Credential Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "lateral-movement": "Lateral Movement",
  "defense-evasion": "Defense Evasion",
  discovery: "Discovery",
  "command-and-control": "Command & Control",
  impact: "Impact",
  "shadow-ai": "Shadow AI",
  "supply-chain": "Supply Chain",
};

/** What the page needs to list and filter playbooks: everything but the query. */
export type PlaybookSummary = Omit<NgsiemPlaybook, "cql">;
