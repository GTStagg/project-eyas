-- Per-tenant patch profiles. A consumer of the standalone bundle can persist a
-- successful generic-installer param-set (win-app-install: product, vendor URL,
-- installer kind, optional SHA-256 pin) as a reusable named profile, building
-- their own runtime catalog WITHOUT a rebuild. This is data, never script bytes
-- — the baked manifest regex (library.py::_validate_params) stays the security
-- boundary; a profile is just validated params the operator chose to keep.
--
-- Stored as a JSON array on the environments row, mirroring shadow_ai_sanctioned
-- _tools (same per-tenant, settings-resident shape). Nullable: an environment
-- with no saved profiles stays NULL rather than "[]".
--
-- Forward-only: NEVER edit this file once shipped. Add a new 000N_<name>.sql.

ALTER TABLE environments ADD COLUMN patch_profiles TEXT;
