-- Per-turn output-token cap for the /chat surface. The chat agent loop sets
-- max_tokens from this value (parsed + clamped in lib/config/runtime.ts); a
-- NULL column means "use the built-in default" (16384). Stored as TEXT to
-- reuse the existing string-typed Anthropic settings plumbing (model/baseUrl
-- are also plain TEXT) — runtime.ts is the single place that parses it to a
-- clamped integer. Operator-editable via /config (the Anthropic card).
--
-- Forward-only: NEVER edit this file once shipped. Add a new 000N_<name>.sql.

ALTER TABLE settings ADD COLUMN anthropic_chat_max_tokens TEXT;
