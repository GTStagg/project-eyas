// Deterministic, heading/paragraph-aware chunking for the knowledge base.
//
// Pure function — no I/O, no clock, no randomness — so it unit-tests cleanly
// (same precedent as the other pure-function suites under scripts/test-*.mjs). Retrieval is lexical
// (FTS5), so chunks only need to be coherent passages of a bounded size; we do
// NOT need semantic/embedding-aware splitting. We split on blank-line paragraph
// boundaries, keep markdown headings attached to the text that follows them,
// and greedily pack paragraphs into ~maxChars windows with a small character
// overlap so a query term sitting on a chunk boundary still matches.

export interface ChunkOptions {
  /** Soft upper bound on chunk size in characters (~4 chars/token ⇒ ~800 tok). */
  maxChars?: number;
  /** Characters of trailing context carried into the next chunk. */
  overlapChars?: number;
}

const DEFAULTS: Required<ChunkOptions> = {
  maxChars: 3200,
  overlapChars: 200,
};

function isHeading(line: string): boolean {
  return /^#{1,6}\s/.test(line.trimStart());
}

// Split into paragraph blocks on blank lines, but force a split BEFORE a
// markdown heading so a heading always starts a fresh block (and thus stays
// attached to the prose beneath it rather than the prose above).
function toBlocks(text: string): string[] {
  const normalized = text.replace(/\r\n?/g, "\n");
  const rawBlocks = normalized.split(/\n{2,}/);
  const blocks: string[] = [];
  for (const raw of rawBlocks) {
    const lines = raw.split("\n");
    let current: string[] = [];
    for (const line of lines) {
      if (isHeading(line) && current.length > 0) {
        blocks.push(current.join("\n").trim());
        current = [];
      }
      current.push(line);
    }
    if (current.length > 0) blocks.push(current.join("\n").trim());
  }
  return blocks.filter((b) => b.length > 0);
}

// Take the last `n` characters of `text`, snapped forward to a word boundary so
// the carried-over overlap doesn't begin mid-word.
function tailOverlap(text: string, n: number): string {
  if (text.length <= n) return text;
  const slice = text.slice(text.length - n);
  const space = slice.indexOf(" ");
  return space === -1 ? slice : slice.slice(space + 1);
}

/**
 * Split `text` into bounded, overlapping passages. Returns [] for empty input.
 * A single block larger than maxChars is hard-split on character boundaries so
 * one giant paragraph can't produce an unbounded chunk.
 */
export function chunkText(text: string, options: ChunkOptions = {}): string[] {
  const { maxChars, overlapChars } = { ...DEFAULTS, ...options };
  const blocks = toBlocks(text);
  if (blocks.length === 0) return [];

  const chunks: string[] = [];
  // `parts` holds the FRESH blocks for the current chunk; `carry` is overlap
  // text from the previous chunk that prefixes this one when rendered. Keeping
  // them separate means a chunk is emitted only when it has fresh content —
  // overlap alone never becomes a standalone chunk.
  let parts: string[] = [];
  let carry = "";

  const render = (): string => {
    const body = parts.join("\n\n");
    if (!carry) return body;
    return body ? `${carry}\n\n${body}` : carry;
  };

  const emit = () => {
    if (parts.length === 0) return; // nothing fresh — don't emit overlap alone
    const text = render().trim();
    chunks.push(text);
    carry = overlapChars > 0 ? tailOverlap(text, overlapChars) : "";
    parts = [];
  };

  for (const block of blocks) {
    // Oversized single block: emit what we have, then hard-split the block so
    // no single chunk exceeds maxChars. (Hard-split pieces don't carry overlap
    // — they're already at the size ceiling.)
    if (block.length > maxChars) {
      emit();
      carry = "";
      for (let i = 0; i < block.length; i += maxChars) {
        parts = [block.slice(i, i + maxChars)];
        emit();
        carry = "";
      }
      continue;
    }

    // Would appending this block overflow the current (carry + parts) chunk?
    const sep = render().length > 0 ? 2 : 0;
    if (render().length + sep + block.length > maxChars && parts.length > 0) {
      emit();
    }
    parts.push(block);
  }
  emit();

  return chunks;
}
