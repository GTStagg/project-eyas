"use client";

import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { Library, Trash2, FileText, Upload, Eye, X } from "lucide-react";

type DocMeta = {
  id: string;
  title: string;
  sourceFilename: string;
  charCount: number;
  createdAt: string;
};

type ListResponse = { ok: boolean; active_id?: string; documents?: DocMeta[]; error?: string };
type EnvListResponse = { ok: boolean; active_id?: string; environments?: { id: string; name: string }[] };
type DocResponse = { ok: boolean; document?: { content: string }; error?: string };

const ACCEPT = ".pdf,.docx,.md,.markdown,.txt,.text";

// Approximate words from extracted character count — operator-friendly, no
// "chars"/"chunks"/index jargon.
function sizeLabel(charCount: number): string {
  const words = Math.max(1, Math.round(charCount / 6));
  if (words < 1000) return `~${words} words`;
  return `~${(words / 1000).toFixed(words < 10000 ? 1 : 0)}k words`;
}

function dateLabel(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export default function KnowledgeBaseCard() {
  const [envName, setEnvName] = useState<string | null>(null);
  const [docs, setDocs] = useState<DocMeta[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [pending, startTransition] = useTransition();
  const [previewId, setPreviewId] = useState<string | null>(null);
  const [previewText, setPreviewText] = useState<string>("");
  const fileRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(async () => {
    try {
      const [listRes, envRes] = await Promise.all([
        fetch("/api/config/knowledge", { cache: "no-store" }),
        fetch("/api/environments", { cache: "no-store" }),
      ]);
      const list = (await listRes.json()) as ListResponse;
      const envs = (await envRes.json()) as EnvListResponse;
      if (list.ok) setDocs(list.documents ?? []);
      if (envs.ok) {
        setEnvName(envs.environments?.find((e) => e.id === envs.active_id)?.name ?? null);
      }
    } catch {
      setError("Couldn't load reference documents. Refresh the page to try again.");
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const flashSuccess = (msg: string) => {
    setSuccess(msg);
    setTimeout(() => setSuccess(null), 4000);
  };

  const upload = useCallback(
    (file: File) => {
      setError(null);
      setSuccess(null);
      startTransition(async () => {
        const form = new FormData();
        form.append("file", file);
        try {
          const r = await fetch("/api/config/knowledge", { method: "POST", body: form });
          const j = (await r.json()) as { ok: boolean; error?: string };
          if (!j.ok) {
            setError(j.error ?? `Upload failed (HTTP ${r.status}).`);
            return;
          }
          flashSuccess(`Added “${file.name}”.`);
          await refresh();
        } catch {
          setError("Upload failed. Please try again.");
        }
      });
    },
    [refresh],
  );

  const onFilePicked = (files: FileList | null) => {
    if (files && files.length > 0) upload(files[0]);
    if (fileRef.current) fileRef.current.value = "";
  };

  const remove = (doc: DocMeta) => {
    setError(null);
    setSuccess(null);
    startTransition(async () => {
      try {
        const r = await fetch(`/api/config/knowledge/${doc.id}`, { method: "DELETE" });
        const j = (await r.json()) as { ok: boolean; error?: string };
        if (!j.ok) {
          setError(j.error ?? `Couldn't remove the document (HTTP ${r.status}).`);
          return;
        }
        if (previewId === doc.id) setPreviewId(null);
        flashSuccess(`Removed “${doc.title}”.`);
        await refresh();
      } catch {
        setError("Couldn't remove the document. Please try again.");
      }
    });
  };

  const togglePreview = async (doc: DocMeta) => {
    if (previewId === doc.id) {
      setPreviewId(null);
      return;
    }
    setPreviewId(doc.id);
    setPreviewText("Loading…");
    try {
      const r = await fetch(`/api/config/knowledge/${doc.id}`, { cache: "no-store" });
      const j = (await r.json()) as DocResponse;
      setPreviewText(j.ok && j.document ? j.document.content : "Couldn't load this document.");
    } catch {
      setPreviewText("Couldn't load this document.");
    }
  };

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-8 shadow-lg shadow-black/40">
      <div className="flex items-start gap-4">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-brand-900/40 bg-brand-950/40 text-oxblood-400">
          <Library className="h-5 w-5" strokeWidth={1.75} />
        </div>
        <div className="flex-1">
          <h2 className="text-lg font-semibold text-white">Knowledge base</h2>
          <p className="mt-1 text-sm text-neutral-400">
            Reference documents the agent draws on when answering for{" "}
            <span className="text-neutral-200">{envName ?? "this environment"}</span>. Add your
            runbooks, escalation procedures, and internal context — the agent cites them when they
            apply. Each environment keeps its own set.
          </p>
        </div>
      </div>

      {success && (
        <div className="mt-6 rounded-md border border-emerald-900/60 bg-emerald-950/30 p-3 text-sm text-emerald-300">
          {success}
        </div>
      )}
      {error && (
        <div className="mt-6 rounded-md border border-rose-900/60 bg-rose-950/30 p-3 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* Upload zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          onFilePicked(e.dataTransfer.files);
        }}
        className={`mt-6 flex flex-col items-center justify-center gap-3 rounded-md border border-dashed px-6 py-8 text-center transition-colors ${
          dragging
            ? "border-brand-700 bg-brand-950/30"
            : "border-neutral-800 bg-neutral-950/60"
        }`}
      >
        <Upload className="h-6 w-6 text-neutral-500" strokeWidth={1.5} />
        <div className="text-sm text-neutral-400">
          Drag a document here, or
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            disabled={pending}
            className="ml-1 text-oxblood-300 underline-offset-2 hover:underline disabled:opacity-50"
          >
            choose a file
          </button>
        </div>
        <div className="text-xs text-neutral-600">PDF, Word, Markdown, or plain text</div>
        <input
          ref={fileRef}
          type="file"
          accept={ACCEPT}
          className="hidden"
          onChange={(e) => onFilePicked(e.target.files)}
        />
        {pending && <div className="text-xs text-neutral-500">Working…</div>}
      </div>

      {/* Document list */}
      <div className="mt-6">
        {!loaded ? (
          <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
            Loading…
          </div>
        ) : docs.length === 0 ? (
          <div className="rounded-md border border-neutral-800 bg-neutral-950/60 px-4 py-6 text-center text-sm text-neutral-500">
            No reference documents yet. Add one above to give the agent context about how your team
            operates.
          </div>
        ) : (
          <div className="overflow-hidden rounded-md border border-neutral-800 bg-neutral-950/60">
            {docs.map((doc) => (
              <div key={doc.id} className="border-b border-neutral-800/80 last:border-0">
                <div className="flex items-center justify-between gap-4 px-4 py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <FileText className="h-4 w-4 shrink-0 text-neutral-500" strokeWidth={1.75} />
                    <div className="min-w-0">
                      <div className="truncate text-sm text-neutral-200">{doc.title}</div>
                      <div className="truncate text-xs text-neutral-500">
                        {doc.sourceFilename} · {sizeLabel(doc.charCount)} · {dateLabel(doc.createdAt)}
                      </div>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      onClick={() => togglePreview(doc)}
                      className="inline-flex items-center gap-1 rounded-md border border-transparent px-2.5 py-1.5 text-xs text-neutral-400 hover:border-neutral-700 hover:text-neutral-200"
                    >
                      {previewId === doc.id ? (
                        <X className="h-3.5 w-3.5" />
                      ) : (
                        <Eye className="h-3.5 w-3.5" />
                      )}
                      {previewId === doc.id ? "Close" : "Preview"}
                    </button>
                    <button
                      type="button"
                      onClick={() => remove(doc)}
                      disabled={pending}
                      className="inline-flex items-center gap-1 rounded-md border border-transparent px-2.5 py-1.5 text-xs text-neutral-400 hover:border-rose-900/60 hover:text-rose-300 disabled:opacity-50"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Remove
                    </button>
                  </div>
                </div>
                {previewId === doc.id && (
                  <pre className="max-h-64 overflow-auto border-t border-neutral-800/80 bg-black/30 px-4 py-3 text-xs leading-relaxed text-neutral-400 whitespace-pre-wrap">
                    {previewText}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="mt-4 text-xs text-neutral-600">
        Documents are stored privately with your environment settings and are never shared outside
        this console.
      </p>
    </div>
  );
}
