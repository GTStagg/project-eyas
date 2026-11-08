-- Per-environment knowledge base. Operators attach reference documents
-- (runbooks, process notes, org context) to a Falcon environment; the agentic
-- surfaces retrieve relevant passages at runtime and cite them.
--
-- Storage is PLAINTEXT on purpose: these are operator reference materials, not
-- secrets, so they do not go through the AES-256-GCM column path (contrast
-- environments.falcon_*_enc). Retrieval is deterministic lexical search via the
-- SQLite FTS5 virtual table below — no embeddings, no external vendor, works in
-- the standalone/gateway-only deployment.
--
-- Adds:
--   knowledge_docs    — one row per uploaded document (full extracted text)
--   knowledge_chunks  — FTS5 index over heading/paragraph-sized chunks
--
-- knowledge_chunks is populated from application code at ingest (no SQL
-- triggers), mirroring how ir_runs / chat_sessions are written from the edge.
-- Deletes cascade in app code (deleteDoc) because FTS5 virtual tables do not
-- participate in foreign-key cascades.

CREATE TABLE IF NOT EXISTS knowledge_docs (
  id TEXT PRIMARY KEY,
  env_id TEXT NOT NULL,
  title TEXT NOT NULL,
  source_filename TEXT NOT NULL,
  mime TEXT NOT NULL,
  content TEXT NOT NULL,
  char_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-->

CREATE INDEX IF NOT EXISTS knowledge_docs_env_idx ON knowledge_docs(env_id);

-->

-- FTS5 with the porter stemmer so "quarantine" matches "quarantined". doc_id +
-- env_id are UNINDEXED (stored, not tokenized) so retrieval can filter by
-- environment and join back to knowledge_docs without a second query.
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks USING fts5(
  doc_id UNINDEXED,
  env_id UNINDEXED,
  title,
  body,
  tokenize = 'porter'
);
