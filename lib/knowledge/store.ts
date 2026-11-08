import "server-only";
import { randomUUID } from "node:crypto";
import { rawDb } from "@/lib/db/client";
import { chunkText } from "./chunk";

// Per-environment knowledge-base storage + ingest. Documents are uploaded on
// the /config surface, text-extracted here, and indexed into the FTS5
// knowledge_chunks table for deterministic lexical retrieval (see retrieve.ts).
// Content is plaintext — operator reference material, not a secret.

export interface KnowledgeDocMeta {
  id: string;
  envId: string;
  title: string;
  sourceFilename: string;
  mime: string;
  charCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface KnowledgeDoc extends KnowledgeDocMeta {
  content: string;
}

// Bounds keep retrieval focused and storage sane. Surfaced to the operator as
// friendly errors (see KnowledgeLimitError) — never raw numbers in jargon.
export const MAX_DOC_CHARS = 2_000_000; // ~2 MB of extracted text per document
export const MAX_ENV_DOCS = 50;
export const MAX_ENV_CHARS = 20_000_000; // ~20 MB total across the environment

// Distinguishes "operator did something we should explain" (limits, unsupported
// file, empty document) from genuine 500s. The API layer maps this to a 400
// with the message shown verbatim, so messages MUST be operator-language.
export class KnowledgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KnowledgeError";
  }
}

function extensionOf(filename: string): string {
  const dot = filename.lastIndexOf(".");
  return dot === -1 ? "" : filename.slice(dot + 1).toLowerCase();
}

function titleFromFilename(filename: string): string {
  const base = filename.replace(/\.[^.]+$/, "").trim();
  return base.length > 0 ? base : filename;
}

// Minimal pure-JS 2D `DOMMatrix`. pdf-parse bundles pdfjs, which at import time
// instantiates `new DOMMatrix()` at module top level and pulls DOMMatrix from
// `@napi-rs/canvas` when running under Node. We deliberately don't ship that
// native binding (it would break the cross-platform standalone bundle), and Node
// has no global `DOMMatrix` on any platform — so without this, the very first PDF
// ingest throws `ReferenceError: DOMMatrix is not defined` at import. Text
// extraction (`getText`) only needs the matrix to exist + do affine math; the
// canvas/ImageData/Path2D rendering path is never exercised. Installed only when
// the runtime lacks DOMMatrix (a dev tree with @napi-rs/canvas keeps the native
// one). Verified headless against a real parse.
class NodeDOMMatrix {
  a = 1;
  b = 0;
  c = 0;
  d = 1;
  e = 0;
  f = 0;
  constructor(init?: number[] | string) {
    if (Array.isArray(init)) {
      if (init.length === 6) [this.a, this.b, this.c, this.d, this.e, this.f] = init;
      else if (init.length === 16) {
        this.a = init[0];
        this.b = init[1];
        this.c = init[4];
        this.d = init[5];
        this.e = init[12];
        this.f = init[13];
      }
    }
  }
  get is2D() {
    return true;
  }
  multiplySelf(m: NodeDOMMatrix) {
    const { a, b, c, d, e, f } = this;
    this.a = a * m.a + c * m.b;
    this.b = b * m.a + d * m.b;
    this.c = a * m.c + c * m.d;
    this.d = b * m.c + d * m.d;
    this.e = a * m.e + c * m.f + e;
    this.f = b * m.e + d * m.f + f;
    return this;
  }
  preMultiplySelf(m: NodeDOMMatrix) {
    const r = new NodeDOMMatrix([m.a, m.b, m.c, m.d, m.e, m.f]).multiplySelf(this);
    Object.assign(this, { a: r.a, b: r.b, c: r.c, d: r.d, e: r.e, f: r.f });
    return this;
  }
  translateSelf(tx = 0, ty = 0) {
    this.e += this.a * tx + this.c * ty;
    this.f += this.b * tx + this.d * ty;
    return this;
  }
  scaleSelf(sx = 1, sy = sx) {
    this.a *= sx;
    this.b *= sx;
    this.c *= sy;
    this.d *= sy;
    return this;
  }
}

// Loading pdf-parse pulls pdfjs, whose Node-only init block also warns (via
// `console.warn`, before any pdfjs verbosity setting can apply) that it can't
// load `@napi-rs/canvas` / polyfill ImageData / Path2D — the rendering path we
// never use. Those lines are harmless but alarming in an operator's log, so we
// drop exactly them for the one-time import. The result is cached, so the
// polyfill + filter install once; the filter is narrow and passes everything else.
let pdfParseModule: Promise<typeof import("pdf-parse")> | null = null;
function loadPdfParse(): Promise<typeof import("pdf-parse")> {
  if (!pdfParseModule) {
    const g = globalThis as { DOMMatrix?: unknown };
    if (typeof g.DOMMatrix === "undefined") g.DOMMatrix = NodeDOMMatrix;
    const benign =
      /@napi-rs\/canvas|Cannot polyfill `(?:DOMMatrix|ImageData|Path2D)`|Cannot access the `require` function/;
    const original = console.warn;
    console.warn = (...args: unknown[]) => {
      if (typeof args[0] === "string" && benign.test(args[0])) return;
      original(...args);
    };
    pdfParseModule = import("pdf-parse").finally(() => {
      console.warn = original;
    });
  }
  return pdfParseModule;
}

// Route to the right extractor by extension (mime is advisory — browsers are
// inconsistent for .md/.docx). Pure-JS extractors only, so the standalone
// bundle stays free of native bindings.
async function extractText(filename: string, buffer: Buffer): Promise<string> {
  const ext = extensionOf(filename);
  if (ext === "md" || ext === "markdown" || ext === "txt" || ext === "text" || ext === "") {
    return buffer.toString("utf8");
  }
  if (ext === "docx") {
    const mammoth = (await import("mammoth")).default;
    const { value } = await mammoth.extractRawText({ buffer });
    return value;
  }
  if (ext === "pdf") {
    const { PDFParse } = await loadPdfParse();
    const parser = new PDFParse({ data: buffer });
    const { text } = await parser.getText();
    return text;
  }
  throw new KnowledgeError(
    `That file type isn't supported. Upload a PDF, Word document, or a plain-text/Markdown file.`,
  );
}

function envTotals(envId: string): { docs: number; chars: number } {
  const row = rawDb()
    .prepare(
      `SELECT COUNT(*) AS docs, COALESCE(SUM(char_count), 0) AS chars
         FROM knowledge_docs WHERE env_id = ?`,
    )
    .get(envId) as { docs: number; chars: number };
  return { docs: row.docs, chars: row.chars };
}

export interface IngestInput {
  envId: string;
  filename: string;
  mime: string;
  buffer: Buffer;
  /** Optional override; defaults to the filename without its extension. */
  title?: string;
}

/**
 * Extract, validate, store, and index a document. All DB writes (doc row + FTS
 * chunks) happen in a single transaction so a failed chunk insert can't leave a
 * doc with no index. Throws KnowledgeError for operator-correctable problems.
 */
export async function ingestDoc(input: IngestInput): Promise<KnowledgeDocMeta> {
  const text = (await extractText(input.filename, input.buffer)).trim();
  if (text.replace(/\s+/g, "").length === 0) {
    throw new KnowledgeError(
      `We couldn't read any text from that file. If it's a scanned PDF (images only), it has no selectable text to use.`,
    );
  }
  if (text.length > MAX_DOC_CHARS) {
    throw new KnowledgeError(
      `That document is too large. Please split it into smaller documents and upload them separately.`,
    );
  }

  const totals = envTotals(input.envId);
  if (totals.docs >= MAX_ENV_DOCS) {
    throw new KnowledgeError(
      `This environment already has the maximum number of reference documents. Remove one before adding another.`,
    );
  }
  if (totals.chars + text.length > MAX_ENV_CHARS) {
    throw new KnowledgeError(
      `This would exceed the total reference-document capacity for the environment. Remove a document to make room.`,
    );
  }

  const id = randomUUID();
  const now = new Date().toISOString();
  const title = (input.title?.trim() || titleFromFilename(input.filename)).slice(0, 200);
  const chunks = chunkText(text);

  const db = rawDb();
  const insertDoc = db.prepare(
    `INSERT INTO knowledge_docs
       (id, env_id, title, source_filename, mime, content, char_count, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const insertChunk = db.prepare(
    `INSERT INTO knowledge_chunks (doc_id, env_id, title, body) VALUES (?, ?, ?, ?)`,
  );
  const txn = db.transaction(() => {
    insertDoc.run(id, input.envId, title, input.filename, input.mime, text, text.length, now, now);
    for (const body of chunks) insertChunk.run(id, input.envId, title, body);
  });
  txn();

  return {
    id,
    envId: input.envId,
    title,
    sourceFilename: input.filename,
    mime: input.mime,
    charCount: text.length,
    createdAt: now,
    updatedAt: now,
  };
}

export function listDocs(envId: string): KnowledgeDocMeta[] {
  return rawDb()
    .prepare(
      `SELECT id, env_id AS envId, title, source_filename AS sourceFilename, mime,
              char_count AS charCount, created_at AS createdAt, updated_at AS updatedAt
         FROM knowledge_docs WHERE env_id = ? ORDER BY created_at DESC`,
    )
    .all(envId) as KnowledgeDocMeta[];
}

export function getDoc(id: string): KnowledgeDoc | null {
  const row = rawDb()
    .prepare(
      `SELECT id, env_id AS envId, title, source_filename AS sourceFilename, mime,
              content, char_count AS charCount, created_at AS createdAt, updated_at AS updatedAt
         FROM knowledge_docs WHERE id = ?`,
    )
    .get(id) as KnowledgeDoc | undefined;
  return row ?? null;
}

/** Delete a document and its FTS chunks. Returns false if the id didn't exist. */
export function deleteDoc(id: string): boolean {
  const db = rawDb();
  const txn = db.transaction(() => {
    db.prepare(`DELETE FROM knowledge_chunks WHERE doc_id = ?`).run(id);
    return db.prepare(`DELETE FROM knowledge_docs WHERE id = ?`).run(id);
  });
  return txn().changes > 0;
}
