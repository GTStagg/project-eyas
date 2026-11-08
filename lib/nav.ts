import {
  Activity,
  Briefcase,
  Bug,
  Compass,
  DollarSign,
  FileText,
  Gauge,
  MessageSquare,
  KeyRound,
  Microscope,
  ShieldCheck,
  Radar,
  Search,
  Server,
  Settings2,
  Sparkles,
  Workflow,
  ShieldAlert,
  ScrollText,
  UserSearch,
  Terminal,
  ListChecks,
  Fingerprint,
  FileLock2,
  Network,
  Lock,
  Boxes,
  Blocks,
  DraftingCompass,
  LayoutDashboard,
  LayoutGrid,
  type LucideIcon,
} from "lucide-react";

export type NavItem = {
  href: string;
  label: string;
  description: string;
  icon: LucideIcon;
};

export type NavGroup = {
  label: string;
  /** Group-level icon shown on the collapsed rail; the flyout lists the items. */
  icon: LucideIcon;
  items: NavItem[];
};

/** Pinned top-of-rail entry. Not part of a group and never capability-gated —
 *  the dashboard is always reachable. */
export const HOME_ITEM: NavItem = {
  href: "/home",
  label: "Home",
  description: "Dashboard — at-a-glance posture with one-click hand-off to the agent.",
  icon: LayoutDashboard,
};

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Triage",
    icon: ListChecks,
    items: [
      {
        href: "/queue",
        label: "Queue",
        description: "Triage queue — open detections ranked for analyst attention.",
        icon: ListChecks,
      },
      {
        href: "/",
        label: "Chat",
        description: "Free-form agentic chat with full Falcon tool access.",
        icon: MessageSquare,
      },
      {
        href: "/briefing",
        label: "Briefing",
        description: "One-page daily security report — print, webhook, or schedule.",
        icon: FileText,
      },
      {
        href: "/quarantine",
        label: "Quarantine",
        description: "Files held in quarantine — clustered review with release and purge hand-off.",
        icon: FileLock2,
      },
    ],
  },
  {
    label: "Pivot",
    icon: Microscope,
    items: [
      {
        href: "/investigate",
        label: "Investigate",
        description: "Host deep-dive — detections, vulns, RTR snapshot.",
        icon: Microscope,
      },
      {
        href: "/pivot",
        label: "Artifact pivot",
        description:
          "Hash / IP / domain / URL — cross-source lookup or hash execution lineage.",
        icon: Search,
      },
    ],
  },
  {
    label: "Hunt",
    icon: Radar,
    items: [
      {
        href: "/intel",
        label: "Intel",
        description: "Adversaries with evidence in your tenant.",
        icon: UserSearch,
      },
      {
        href: "/intel-dossier",
        label: "Dossier",
        description: "Full finished-intel dossier on an actor, campaign, or keyword.",
        icon: ScrollText,
      },
      {
        href: "/ngsiem",
        label: "NGSIEM",
        description: "Natural-language → CQL with curated playbooks.",
        icon: Terminal,
      },
      {
        href: "/recon",
        label: "Recon",
        description:
          "Domain / email exposure across breaches, dark web, paste sites, Telegram.",
        icon: Radar,
      },
      {
        href: "/correlation",
        label: "Correlation rules",
        description: "NGSIEM correlation-rule health — coverage gaps, stale and inactive rules.",
        icon: Network,
      },
      {
        href: "/malquery",
        label: "MalQuery",
        description: "Hash lineage across CrowdStrike's malware research corpus.",
        icon: Fingerprint,
      },
      {
        href: "/shadow-ai",
        label: "AI",
        description:
          "AI oversight — unsanctioned tooling and SaaS egress, plus AI-agent activity in the tenant.",
        icon: Sparkles,
      },
    ],
  },
  {
    label: "Posture",
    icon: ShieldCheck,
    items: [
      {
        href: "/identity",
        label: "Identity",
        description: "Risky identities, active IDP detections, sensor posture.",
        icon: KeyRound,
      },
      {
        href: "/prevention",
        label: "Prevention",
        description:
          "Prevention policy posture — what's blocking vs detect-only across every platform.",
        icon: ShieldCheck,
      },
      {
        href: "/workflows",
        label: "Workflows",
        description: "Fusion SOAR posture — definitions, executions, failure flags.",
        icon: Workflow,
      },
      {
        href: "/discover",
        label: "Discover",
        description: "Asset, application, and account inventory — coverage gaps and privileged-account review.",
        icon: Boxes,
      },
      {
        href: "/data-protection",
        label: "Data Protection",
        description: "Data-loss posture — what's enforcing vs monitoring, and which patterns fire.",
        icon: Lock,
      },
    ],
  },
  {
    label: "Dashboards",
    icon: LayoutGrid,
    items: [
      {
        href: "/detections",
        label: "Detections",
        description: "Recent endpoint detections (raw feed).",
        icon: ShieldAlert,
      },
      {
        href: "/hosts",
        label: "Hosts",
        description: "All managed hosts in your tenant.",
        icon: Server,
      },
      {
        href: "/vulnerabilities",
        label: "Vulnerabilities",
        description: "Open CVEs by severity and host.",
        icon: Bug,
      },
      {
        href: "/cases",
        label: "Cases",
        description: "Filed investigations with attached alert and event evidence.",
        icon: Briefcase,
      },
    ],
  },
  {
    label: "System",
    icon: Settings2,
    items: [
      {
        href: "/getting-started",
        label: "Getting started",
        description: "Post-registration activation checklist — what's set up, what still needs configuring.",
        icon: Compass,
      },
      {
        href: "/ir-runs",
        label: "IR runs",
        description: "Audit trail of incident-response engagements run from this console.",
        icon: ShieldAlert,
      },
      {
        href: "/scorecard",
        label: "Scorecard",
        description:
          "What this console has accomplished for this tenant — engagements, reviewed actions, and posture movement.",
        icon: Gauge,
      },
      {
        href: "/cost",
        label: "Cost",
        description: "Token spend and projected monthly cost.",
        icon: DollarSign,
      },
      {
        href: "/config",
        label: "Config",
        description: "Connections, credentials, and recent changes.",
        icon: Settings2,
      },
      {
        href: "/status",
        label: "Status",
        description: "Health and version info.",
        icon: Activity,
      },
    ],
  },
  {
    label: "Reference",
    icon: Blocks,
    items: [
      {
        href: "/agent-toolbox",
        label: "Agent toolbox",
        description: "Every Falcon tool the agent can compose — read-only or human-approved.",
        icon: Blocks,
      },
      {
        href: "/blueprint",
        label: "Blueprint",
        description: "How to build an agentic SOC on falcon-mcp, FalconPy & Claude.",
        icon: DraftingCompass,
      },
    ],
  },
];

export const ALL_NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);
