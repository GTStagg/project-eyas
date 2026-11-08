import path from "node:path";
import type { Config } from "drizzle-kit";

// drizzle-kit config — used only at dev time when you want to generate
// future migration .sql files from edits to lib/db/schema.ts:
//   npx drizzle-kit generate --config=drizzle.config.ts
//
// At runtime we use our own tiny migration runner (lib/db/migrate.ts)
// rather than drizzle-orm's migrator, so the journal/snapshot format
// from drizzle-kit isn't load-bearing — only the .sql output is.

const DATA_DIR = process.env.FALCON_DATA_DIR ?? path.join(process.cwd(), "data");

export default {
  schema: "./lib/db/schema.ts",
  out: "./lib/db/migrations",
  dialect: "sqlite",
  dbCredentials: {
    url: path.join(DATA_DIR, "eyas.db"),
  },
  strict: true,
  verbose: true,
} satisfies Config;
