"use client";

import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Activity,
  AlertTriangle,
  Bug,
  CheckCircle2,
  ClipboardCheck,
  Server,
  ShieldAlert,
  Target,
  Zap,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

/** Map known section heading text → icon. Matches loosely (case-insensitive,
 *  substring) so minor variations in Claude's heading text still work. */
const HEADING_ICONS: Array<{ test: RegExp; icon: LucideIcon; tone: string }> = [
  { test: /executive\s+summary/i, icon: Zap, tone: "text-oxblood-400" },
  { test: /top\s+(incidents?|cases?)/i, icon: AlertTriangle, tone: "text-amber-400" },
  { test: /critical\s+detections?|recent\s+detections?/i, icon: ShieldAlert, tone: "text-oxblood-400" },
  { test: /vulnerabilit(y|ies)|cve/i, icon: Bug, tone: "text-orange-400" },
  { test: /host\s+hygiene|stale\s+hosts?|host\s+fingerprint/i, icon: Server, tone: "text-sky-400" },
  { test: /recommended\s+actions?|next\s+steps?|action\s+items?/i, icon: Target, tone: "text-oxblood-400" },
  { test: /risk\s+assessment|posture/i, icon: Activity, tone: "text-emerald-400" },
  { test: /live\s+process\s+snapshot|rtr|process\s+snapshot/i, icon: Activity, tone: "text-sky-400" },
  { test: /detection\s+activity|recent\s+activity/i, icon: ShieldAlert, tone: "text-oxblood-400" },
  { test: /open\s+vulnerabilit/i, icon: Bug, tone: "text-orange-400" },
  { test: /summary|overview|results?/i, icon: ClipboardCheck, tone: "text-neutral-300" },
  { test: /observation|finding/i, icon: CheckCircle2, tone: "text-emerald-400" },
];

function nodeText(children: ReactNode): string {
  if (typeof children === "string") return children;
  if (typeof children === "number") return String(children);
  if (Array.isArray(children)) return children.map(nodeText).join("");
  if (
    children &&
    typeof children === "object" &&
    "props" in children &&
    typeof (children as { props?: { children?: ReactNode } }).props?.children !== "undefined"
  ) {
    return nodeText(
      (children as { props: { children: ReactNode } }).props.children,
    );
  }
  return "";
}

function HeadingWithIcon({
  level,
  children,
}: {
  level: 1 | 2 | 3;
  children: ReactNode;
}) {
  const text = nodeText(children).trim();
  const match = HEADING_ICONS.find((h) => h.test.test(text));
  const Tag = (`h${level}` as keyof React.JSX.IntrinsicElements);
  return (
    <Tag className="flex items-center gap-2.5">
      {match ? (
        <match.icon
          className={`h-[0.95em] w-[0.95em] shrink-0 ${match.tone}`}
          strokeWidth={2.25}
        />
      ) : null}
      <span>{children}</span>
    </Tag>
  );
}

// Patterns for inline `code` spans we want to turn into navigable links.
// These run only when linkEntities is enabled. Anything that doesn't match
// passes through as a plain <code>.
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const HOSTNAME_RE = /^(?=.{3,63}$)(?=.*[-.])[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;
// Hash-shaped strings that should NOT be linked as hostnames even if they
// contain hyphens/dots (e.g. SHA-256 hashes pasted with separators).
const HASHISH_RE = /^[A-Fa-f0-9]{16,}$/;

function entityLinkFor(raw: string): { href: string; external: boolean } | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (CVE_RE.test(trimmed)) {
    return { href: `https://nvd.nist.gov/vuln/detail/${trimmed.toUpperCase()}`, external: true };
  }
  if (
    HOSTNAME_RE.test(trimmed) &&
    !HASHISH_RE.test(trimmed.replace(/[-.]/g, "")) &&
    // Reject things that look like file extensions / domain-only ("foo.exe", "bar.dll").
    !/\.(exe|dll|sys|so|dylib|bat|ps1|sh|py|js|ts|md|json|yml|yaml|txt|log)$/i.test(trimmed)
  ) {
    return { href: `/investigate?host=${encodeURIComponent(trimmed)}`, external: false };
  }
  return null;
}

function LinkedCode({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  const text = nodeText(children);
  // Pass fenced/block code through untouched: those carry a language-* class
  // or contain newlines. We only ever linkify single-line inline code.
  const isBlock = (className && /(^|\s)language-/.test(className)) || /\n/.test(text);
  if (isBlock) return <code className={className}>{children}</code>;
  const link = entityLinkFor(text);
  if (!link) return <code>{children}</code>;
  if (link.external) {
    return (
      <a
        href={link.href}
        target="_blank"
        rel="noreferrer"
        className="entity-link"
      >
        <code>{children}</code>
      </a>
    );
  }
  return (
    <Link href={link.href} className="entity-link">
      <code>{children}</code>
    </Link>
  );
}

export type SectionedMarkdownProps = {
  text: string;
  /** Optional override for paragraph/list/td renderers (e.g. for citations). */
  pComponent?: (props: { children: ReactNode }) => ReactNode;
  liComponent?: (props: { children: ReactNode }) => ReactNode;
  tdComponent?: (props: { children: ReactNode }) => ReactNode;
  /** Turn inline `code` spans matching known entity patterns (hostnames,
   *  CVE IDs) into navigable links to the relevant dashboard / external
   *  reference. Off by default — enable on chat/agent surfaces only. */
  linkEntities?: boolean;
};

export default function SectionedMarkdown({
  text,
  pComponent,
  liComponent,
  tdComponent,
  linkEntities,
}: SectionedMarkdownProps) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <HeadingWithIcon level={1}>{children}</HeadingWithIcon>,
        h2: ({ children }) => <HeadingWithIcon level={2}>{children}</HeadingWithIcon>,
        h3: ({ children }) => <HeadingWithIcon level={3}>{children}</HeadingWithIcon>,
        ...(pComponent ? { p: ({ children }) => <p>{pComponent({ children })}</p> } : {}),
        ...(liComponent ? { li: ({ children }) => <li>{liComponent({ children })}</li> } : {}),
        ...(tdComponent ? { td: ({ children }) => <td>{tdComponent({ children })}</td> } : {}),
        ...(linkEntities
          ? {
              code: ({ className, children }) => (
                <LinkedCode className={className}>{children}</LinkedCode>
              ),
            }
          : {}),
        a: ({ href, children }) => {
          // Chat-primer links rendered as CTA buttons. The agent emits these
          // from triage reports as `[Remediate →](/?primer=…)`; styling them
          // as a button (vs. a plain hyperlink) makes the action discoverable.
          if (typeof href === "string" && href.startsWith("/?primer=")) {
            return (
              <Link
                href={href}
                className="inline-flex items-center gap-1.5 rounded-md border border-brand-700/60 bg-brand-600/15 px-3 py-1 align-middle text-[13px] font-semibold text-oxblood-200 !no-underline transition-colors hover:border-brand-600 hover:bg-brand-600/30 hover:text-white"
              >
                {children}
              </Link>
            );
          }
          return (
            <a href={href} target="_blank" rel="noreferrer">
              {children}
            </a>
          );
        },
      }}
    >
      {text}
    </ReactMarkdown>
  );
}
