import { ok, fail, serverError } from "@/lib/api/respond";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { getDoc, deleteDoc } from "@/lib/knowledge/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

// GET /api/config/knowledge/[id] — full extracted text of one document, for the
// preview panel. Scoped to the active environment so an id from another env
// can't be read across the switcher.
export async function GET(_request: Request, context: Ctx) {
  try {
    const { id } = await context.params;
    const doc = getDoc(id);
    if (!doc || doc.envId !== getActiveEnvironmentId()) {
      return fail("That document no longer exists.", 404);
    }
    return ok({ document: doc });
  } catch (err) {
    return serverError(err);
  }
}

// DELETE /api/config/knowledge/[id] — remove a document and its index.
export async function DELETE(_request: Request, context: Ctx) {
  try {
    const { id } = await context.params;
    const doc = getDoc(id);
    if (!doc || doc.envId !== getActiveEnvironmentId()) {
      return fail("That document no longer exists.", 404);
    }
    deleteDoc(id);
    return ok({ id });
  } catch (err) {
    return serverError(err);
  }
}
