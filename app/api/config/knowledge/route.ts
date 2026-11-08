import { ok, fail, serverError } from "@/lib/api/respond";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { ingestDoc, listDocs, KnowledgeError } from "@/lib/knowledge/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Reference documents the agent uses for the active environment. List + upload.
// Scoped to the active environment (the multi-env switcher decides which set is
// live); per-document content lives in the DB, not on disk.

// GET /api/config/knowledge — metadata for every document in the active env.
export async function GET() {
  try {
    return ok({
      active_id: getActiveEnvironmentId(),
      documents: listDocs(getActiveEnvironmentId()),
    });
  } catch (err) {
    return serverError(err);
  }
}

// Upper bound on the raw upload before we even try to extract text — keeps a
// hostile/accidental huge file from being buffered into memory. Extracted-text
// limits (per-doc / per-env) are enforced in the store after parsing.
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024; // 25 MB

// POST /api/config/knowledge — multipart upload of one document. This is the
// app's first file-upload surface; we parse via the Web FormData API (no extra
// framework dependency). Field `file` is required; optional `title` overrides
// the filename-derived title.
export async function POST(request: Request) {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return fail("Couldn't read the uploaded file. Please try again.", 400);
  }

  const file = form.get("file");
  if (!(file instanceof File) || file.size === 0) {
    return fail("Choose a document to upload.", 400);
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return fail("That file is too large. Please upload a smaller document.", 400);
  }

  const titleRaw = form.get("title");
  const title = typeof titleRaw === "string" && titleRaw.trim().length > 0 ? titleRaw.trim() : undefined;

  try {
    const buffer = Buffer.from(await file.arrayBuffer());
    const document = await ingestDoc({
      envId: getActiveEnvironmentId(),
      filename: file.name,
      mime: file.type || "application/octet-stream",
      buffer,
      title,
    });
    return ok({ document });
  } catch (err) {
    // Operator-correctable problems (unsupported type, empty, over a limit)
    // come back as KnowledgeError with an operator-language message → 400.
    if (err instanceof KnowledgeError) return fail(err.message, 400);
    return serverError(err);
  }
}
