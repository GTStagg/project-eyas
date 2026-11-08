"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Play,
  Sparkles,
  ArrowRight,
  ArrowUpRight,
  Terminal,
  ChevronDown,
  Bookmark,
  X,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import AgentRun, { type AgentRunHandle } from "@/components/AgentRun";
import PageHero from "@/components/PageHero";
import NgsiemPipelineHealth from "@/components/NgsiemPipelineHealth";
import {
  CATEGORY_LABEL,
  OS_LABEL,
  PLAYBOOKS,
  type NgsiemPlaybook,
  type PlaybookCategory,
  type PlaybookOs,
} from "@/lib/ngsiem-playbooks";

const OS_TONE: Record<PlaybookOs, string> = {
  win: "border-blue-800 bg-blue-950/40 text-blue-300",
  mac: "border-neutral-700 bg-neutral-900 text-neutral-300",
  lin: "border-yellow-800 bg-yellow-950/40 text-yellow-300",
};

const CATEGORY_TONE: Record<PlaybookCategory, string> = {
  "initial-access": "border-yellow-800 bg-yellow-950/30 text-yellow-300",
  "credential-access": "border-amber-800 bg-amber-950/30 text-amber-300",
  execution: "border-rose-800 bg-rose-950/30 text-rose-300",
  persistence: "border-emerald-800 bg-emerald-950/30 text-emerald-300",
  "privilege-escalation": "border-teal-800 bg-teal-950/30 text-teal-300",
  "lateral-movement": "border-blue-800 bg-blue-950/30 text-blue-300",
  "defense-evasion": "border-orange-800 bg-orange-950/30 text-orange-300",
  discovery: "border-sky-800 bg-sky-950/30 text-sky-300",
  "command-and-control": "border-red-800 bg-red-950/30 text-oxblood-300",
  impact: "border-pink-800 bg-pink-950/30 text-pink-300",
  "shadow-ai": "border-cyan-800 bg-cyan-950/30 text-cyan-300",
  "supply-chain": "border-fuchsia-800 bg-fuchsia-950/30 text-fuchsia-300",
};

type Mode = "playbook" | "freeform";

type SavedQuestion = { id: string; label: string; input: string };

const SAVED_QUESTIONS_KEY = "falcon-mcp-console.ngsiem-saved-questions";

function loadSavedQuestions(): SavedQuestion[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(SAVED_QUESTIONS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (p: unknown): p is SavedQuestion =>
        typeof p === "object" &&
        p !== null &&
        typeof (p as SavedQuestion).id === "string" &&
        typeof (p as SavedQuestion).label === "string" &&
        typeof (p as SavedQuestion).input === "string",
    );
  } catch {
    return [];
  }
}

function persistSavedQuestions(items: SavedQuestion[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(SAVED_QUESTIONS_KEY, JSON.stringify(items));
  } catch {
    // localStorage unavailable
  }
}

export default function NgsiemPage() {
  const ref = useRef<AgentRunHandle>(null);
  const [input, setInput] = useState("");
  const [activePlaybookId, setActivePlaybookId] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState<{ kind: Mode; payload: unknown } | null>(null);
  const [savedQuestions, setSavedQuestions] = useState<SavedQuestion[]>([]);

  useEffect(() => {
    setSavedQuestions(loadSavedQuestions());
  }, []);

  const saveCurrent = () => {
    const trimmed = input.trim();
    if (!trimmed) return;
    const defaultLabel = trimmed.length > 60 ? trimmed.slice(0, 60) + "…" : trimmed;
    const label = window.prompt("Save this question as:", defaultLabel)?.trim();
    if (!label) return;
    const next: SavedQuestion[] = [
      { id: `q-${Date.now()}`, label, input: trimmed },
      ...savedQuestions.filter((q) => q.input !== trimmed),
    ].slice(0, 50);
    setSavedQuestions(next);
    persistSavedQuestions(next);
  };

  const removeSaved = (id: string) => {
    const next = savedQuestions.filter((q) => q.id !== id);
    setSavedQuestions(next);
    persistSavedQuestions(next);
  };

  const [search, setSearch] = useState("");
  const [osFilter, setOsFilter] = useState<Set<PlaybookOs>>(new Set());

  const filteredPlaybooks = useMemo(() => {
    const q = search.trim().toLowerCase();
    return PLAYBOOKS.filter((p) => {
      if (osFilter.size > 0 && !p.os.some((o) => osFilter.has(o))) return false;
      if (!q) return true;
      const hay = (
        p.title +
        " " +
        p.description +
        " " +
        p.id +
        " " +
        p.mitre.join(" ")
      ).toLowerCase();
      return hay.includes(q);
    });
  }, [search, osFilter]);

  const groupedPlaybooks = useMemo(() => {
    const order: PlaybookCategory[] = [
      "initial-access",
      "execution",
      "persistence",
      "privilege-escalation",
      "credential-access",
      "discovery",
      "lateral-movement",
      "defense-evasion",
      "command-and-control",
      "impact",
      "shadow-ai",
      "supply-chain",
    ];
    const groups = new Map<PlaybookCategory, NgsiemPlaybook[]>();
    for (const cat of order) groups.set(cat, []);
    for (const p of filteredPlaybooks) {
      const arr = groups.get(p.category) ?? [];
      arr.push(p);
      groups.set(p.category, arr);
    }
    for (const [cat, arr] of groups) {
      if (arr.length === 0) groups.delete(cat);
    }
    return groups;
  }, [filteredPlaybooks]);

  const toggleOsFilter = (o: PlaybookOs) => {
    setOsFilter((prev) => {
      const next = new Set(prev);
      if (next.has(o)) next.delete(o);
      else next.add(o);
      return next;
    });
  };

  const categoryList = useMemo(
    () => Array.from(groupedPlaybooks.entries()),
    [groupedPlaybooks],
  );

  const [openCategories, setOpenCategories] = useState<Set<PlaybookCategory>>(
    () => new Set(categoryList.slice(0, 2).map(([cat]) => cat)),
  );

  // When the user is searching or has narrowed by OS, auto-expand every
  // surviving group so matches are visible without an extra click. Reset to
  // the default first-two-categories view when they clear the filters.
  const filtersActive = search.trim().length > 0 || osFilter.size > 0;
  useEffect(() => {
    if (filtersActive) {
      setOpenCategories(new Set(categoryList.map(([cat]) => cat)));
    }
  }, [filtersActive, categoryList]);

  const toggleCategory = (cat: PlaybookCategory) => {
    setOpenCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const jumpToCategory = (cat: PlaybookCategory) => {
    setOpenCategories((prev) => {
      if (prev.has(cat)) return prev;
      const next = new Set(prev);
      next.add(cat);
      return next;
    });
    requestAnimationFrame(() => {
      document
        .getElementById(`pb-cat-${cat}`)
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const expandAll = () =>
    setOpenCategories(new Set(categoryList.map(([cat]) => cat)));
  const collapseAll = () => setOpenCategories(new Set());

  const endpoint =
    submitted?.kind === "playbook" ? "/api/ngsiem/playbook" : "/api/ngsiem";
  const body = submitted?.payload;

  const runFreeform = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    setActivePlaybookId(null);
    setSubmitted({ kind: "freeform", payload: { input: trimmed } });
    setTimeout(() => ref.current?.start(), 0);
  };

  const runPlaybook = (pb: NgsiemPlaybook) => {
    setActivePlaybookId(pb.id);
    setInput("");
    setSubmitted({ kind: "playbook", payload: { playbook_id: pb.id } });
    setTimeout(() => ref.current?.start(), 0);
  };

  return (
    <AppShell title="NGSIEM">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-5xl animate-fade-in-up space-y-10">
          <PageHero
            icon={Terminal}
            eyebrow="NGSIEM"
            title="Hunt your telemetry in plain English."
            subtitle={
              <span className="flex flex-wrap items-center gap-2">
                Ask a question or run a curated playbook. Both execute against the live tenant.
                <a
                  href="https://www.byteray.com/cql-hub"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex h-6 items-center gap-1 rounded-md border border-neutral-800 bg-neutral-950 px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-400 transition hover:border-neutral-700 hover:text-neutral-100"
                >
                  byteray.com/cql-hub
                  <ArrowUpRight className="h-3 w-3" strokeWidth={2} />
                </a>
              </span>
            }
          />

          <NgsiemPipelineHealth />

          {/* Free-form natural-language input — moved to top per feedback. */}
          <section>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-base font-semibold uppercase tracking-widest text-neutral-300">
                Ask a question
              </h2>
              <span className="text-xs text-neutral-500">⌘/Ctrl + Enter to run</span>
            </div>
            <div className="border border-neutral-800 bg-neutral-950 p-4">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                    e.preventDefault();
                    runFreeform(input);
                  }
                }}
                placeholder="What do you want to know?"
                rows={3}
                className="w-full resize-none border border-neutral-800 bg-neutral-950 px-3.5 py-2.5 text-base text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
              />
              <div className="mt-3 flex items-center justify-end gap-3">
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={saveCurrent}
                    disabled={!input.trim()}
                    title="Save this question for later"
                    className="flex items-center gap-1.5 rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-neutral-300 transition-colors hover:border-brand-700/60 hover:bg-neutral-900 hover:text-oxblood-200 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-neutral-800 disabled:hover:bg-neutral-950 disabled:hover:text-neutral-300"
                  >
                    <Bookmark className="h-3.5 w-3.5" strokeWidth={2} />
                    Save
                  </button>
                  <button
                    onClick={() => runFreeform(input)}
                    disabled={!input.trim()}
                    className="flex items-center gap-1.5 rounded-md bg-brand-600 px-5 py-2.5 font-mono text-[12px] font-semibold uppercase tracking-[0.16em] text-white shadow-[0_0_24px_-4px_rgba(220,38,38,0.55),inset_0_1px_0_rgba(255,255,255,0.12)] transition-[background-color,box-shadow] duration-150 hover:bg-brand-500 hover:shadow-[0_0_32px_-4px_rgba(239,68,68,0.7),inset_0_1px_0_rgba(255,255,255,0.18)] disabled:cursor-not-allowed disabled:bg-neutral-900 disabled:text-neutral-600 disabled:shadow-none"
                  >
                    Run
                    <ArrowRight className="h-3.5 w-3.5" strokeWidth={2.5} />
                  </button>
                </div>
              </div>
              {savedQuestions.length > 0 ? (
                <div className="mt-3 border-t border-neutral-900 pt-3">
                  <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-500">
                    Saved questions
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {savedQuestions.map((q) => (
                      <div
                        key={q.id}
                        className="group inline-flex items-center overflow-hidden rounded-md border border-neutral-800 bg-neutral-950 transition-colors hover:border-brand-700/60 hover:bg-neutral-900"
                      >
                        <button
                          onClick={() => {
                            setInput(q.input);
                            setTimeout(() => runFreeform(q.input), 0);
                          }}
                          title={q.input}
                          className="px-3 py-1.5 text-sm text-neutral-300 transition-colors group-hover:text-oxblood-200"
                        >
                          {q.label}
                        </button>
                        <button
                          onClick={() => removeSaved(q.id)}
                          title="Remove"
                          className="border-l border-neutral-800 px-1.5 py-1.5 text-neutral-600 hover:text-rose-300"
                        >
                          <X className="h-3 w-3" strokeWidth={2.5} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </section>

          {/* Run output — moved up so user immediately sees activity. */}
          <section>
            <AgentRun
              ref={ref}
              endpoint={endpoint}
              body={body}
              webhookTitle="Falcon NGSIEM result"
              webhookSource="ngsiem"
              emptyHint={
                <div className="border border-dashed border-neutral-800 bg-neutral-950/60 p-6 text-base text-neutral-500">
                  Results will stream in here once you run a query or playbook.
                  <div className="mt-3 border border-neutral-800 bg-neutral-950 p-4 text-base text-neutral-400">
                    <strong className="text-neutral-300">Heads up:</strong> if a query
                    returns "No content was received for this request" or an empty
                    table, that almost always means your tenant has no NGSIEM ingest
                    for that event type — not a query syntax error.
                  </div>
                </div>
              }
            />
          </section>

          {/* Curated playbooks below — ground truth queries from CQL Hub. */}
          <section>
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Sparkles className="h-5 w-5 text-oxblood-400" />
                <h2 className="font-mono text-base font-semibold uppercase tracking-[0.18em] text-neutral-100">
                  Curated playbooks
                </h2>
              </div>
              <span className="font-mono text-sm uppercase tracking-[0.12em] tabular-nums text-neutral-400">
                {filtersActive
                  ? `${filteredPlaybooks.length} / ${PLAYBOOKS.length} queries`
                  : `${PLAYBOOKS.length} queries`}
              </span>
            </div>

            {/* Search + OS filter row. */}
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[16rem]">
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search by title, description, or MITRE ID…"
                  className="w-full border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 placeholder:text-neutral-600 focus:border-brand-700 focus:outline-none"
                />
                {search && (
                  <button
                    onClick={() => setSearch("")}
                    aria-label="Clear search"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-oxblood-300"
                  >
                    <X className="h-3.5 w-3.5" strokeWidth={2.5} />
                  </button>
                )}
              </div>
              <div className="flex items-center gap-1">
                {(["win", "mac", "lin"] as PlaybookOs[]).map((o) => {
                  const on = osFilter.has(o);
                  return (
                    <button
                      key={o}
                      onClick={() => toggleOsFilter(o)}
                      className={`border px-3 py-2 font-mono text-[12px] font-semibold uppercase tracking-[0.14em] transition-colors ${
                        on
                          ? "border-brand-700/70 bg-brand-950/40 text-oxblood-200"
                          : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:border-brand-800/60 hover:text-oxblood-300"
                      }`}
                    >
                      {OS_LABEL[o]}
                    </button>
                  );
                })}
                {(search || osFilter.size > 0) && (
                  <button
                    onClick={() => {
                      setSearch("");
                      setOsFilter(new Set());
                    }}
                    className="ml-1 border border-neutral-800 bg-neutral-950 px-3 py-2 font-mono text-[12px] uppercase tracking-[0.14em] text-neutral-400 hover:border-brand-800/60 hover:text-oxblood-300"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {filteredPlaybooks.length === 0 && (
              <div className="border border-dashed border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
                No playbooks match this filter.
              </div>
            )}

            {/* Sticky category rail — chips jump to (and auto-expand) a section. */}
            <div className="sticky top-0 z-10 -mx-1 mb-4 border-b border-neutral-800 bg-neutral-950/85 px-1 py-2 backdrop-blur supports-[backdrop-filter]:bg-neutral-950/70">
              <div className="flex flex-wrap items-center gap-1.5">
                {categoryList.map(([cat, pbs]) => {
                  const isOpen = openCategories.has(cat);
                  return (
                    <button
                      key={cat}
                      onClick={() => jumpToCategory(cat)}
                      className={`group flex items-center gap-1.5 border px-3 py-1.5 font-mono text-[13px] font-semibold uppercase tracking-[0.14em] transition-colors ${
                        isOpen
                          ? "border-brand-700/70 bg-brand-950/40 text-oxblood-200"
                          : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:border-brand-800/60 hover:text-oxblood-300"
                      }`}
                    >
                      {CATEGORY_LABEL[cat]}
                      <span className="rounded-sm bg-neutral-950/60 px-1.5 text-[12px] tabular-nums text-neutral-500 group-hover:text-neutral-300">
                        {pbs.length}
                      </span>
                    </button>
                  );
                })}
                <div className="ml-auto flex items-center gap-2 font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-500">
                  <button
                    onClick={expandAll}
                    className="hover:text-oxblood-300"
                  >
                    Expand all
                  </button>
                  <span className="text-neutral-700">·</span>
                  <button
                    onClick={collapseAll}
                    className="hover:text-oxblood-300"
                  >
                    Collapse all
                  </button>
                </div>
              </div>
            </div>
            <div className="space-y-3">
              {categoryList.map(([cat, pbs]) => {
                const isOpen = openCategories.has(cat);
                return (
                <div key={cat} id={`pb-cat-${cat}`} className="scroll-mt-20 border border-neutral-800 bg-neutral-950/40">
                  <button
                    onClick={() => toggleCategory(cat)}
                    aria-expanded={isOpen}
                    className="flex w-full items-center justify-between gap-3 px-3.5 py-2.5 text-left transition-colors hover:bg-neutral-900/60"
                  >
                    <div className="flex items-center gap-2.5 font-mono text-sm font-semibold uppercase tracking-[0.16em] text-oxblood-400">
                      <span className="h-px w-3 bg-brand-700/70" />
                      {CATEGORY_LABEL[cat]}
                      <span className="font-mono text-[13px] tabular-nums text-neutral-500">
                        {pbs.length}
                      </span>
                    </div>
                    <ChevronDown
                      className={`h-5 w-5 text-neutral-500 transition-transform ${isOpen ? "rotate-180" : ""}`}
                    />
                  </button>
                  {isOpen && (
                  <div className="grid gap-2 border-t border-neutral-800/70 p-3 md:grid-cols-2">
                    {pbs.map((pb) => {
                      const active = activePlaybookId === pb.id;
                      return (
                        <button
                          key={pb.id}
                          onClick={() => runPlaybook(pb)}
                          className={`group relative flex items-start gap-3 border p-4 text-left transition-all duration-150 ${
                            active
                              ? "border-brand-600 bg-brand-950/20 shadow-[0_0_0_1px_rgba(220,38,38,0.35),0_8px_24px_-12px_rgba(220,38,38,0.45)]"
                              : "border-neutral-800 bg-neutral-950 hover:-translate-y-0.5 hover:border-brand-800/60 hover:bg-neutral-900 hover:shadow-[0_8px_20px_-12px_rgba(0,0,0,0.8)]"
                          }`}
                        >
                          <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center border transition-transform group-hover:scale-105 ${CATEGORY_TONE[pb.category]}`}>
                            <Play className="h-3.5 w-3.5" strokeWidth={2.5} />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-start justify-between gap-2">
                              <div className="text-base font-semibold text-white">
                                {pb.title}
                              </div>
                              <div className="flex shrink-0 flex-wrap gap-1">
                                {pb.os.map((o) => (
                                  <span
                                    key={o}
                                    className={`border px-1.5 py-0.5 text-[12px] font-medium uppercase tracking-wider ${OS_TONE[o]}`}
                                  >
                                    {OS_LABEL[o]}
                                  </span>
                                ))}
                              </div>
                            </div>
                            <div className="mt-1.5 line-clamp-2 text-[15px] leading-snug text-neutral-400">
                              {pb.description}
                            </div>
                            {pb.mitre.length > 0 && (
                              <div className="mt-2.5 flex flex-wrap gap-1">
                                {pb.mitre.map((m) => (
                                  <span
                                    key={m}
                                    className="bg-neutral-900 px-1.5 py-0.5 font-mono text-[12px] text-neutral-400"
                                  >
                                    {m}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                  )}
                </div>
                );
              })}
            </div>
          </section>
        </div>
      </main>
    </AppShell>
  );
}
