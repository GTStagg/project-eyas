import "server-only";

/**
 * Build-time deployment flags. Compiled into the Next.js bundle so they
 * can't be edited at runtime (no .env knob, no settings.json field, no
 * UI form). Values here are baked at `npm run build` time and become
 * part of the compiled JavaScript.
 *
 * Dev / Docker builds use the defaults below (no lock). The standalone
 * macOS bundle's `make-dist.sh` overwrites this file before running
 * `npm run build` to bake in:
 *   - `gatewayOnly: true`              — wizard hides direct API key option
 *   - `forcedGatewayUrl: "https://…"`  — base URL is fixed; UI locks input
 *                                        + server-side validation rejects
 *                                        any other value on save
 *
 * The point: if a copy of the standalone bundle ends up on a machine
 * outside the authorized distribution channel, it has no useful base URL
 * to be repointed at — the recipient can't edit a config file or UI to
 * swap in a personal gateway. The only way around it is to recompile
 * from source, which they won't have.
 */
export const BUILD_FLAGS = {
  gatewayOnly: false as boolean,
  forcedGatewayUrl: null as string | null,
} as const;
