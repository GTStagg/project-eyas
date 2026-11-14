// Server-sent-event stream parsing shared by the chat and agent surfaces.
// Feed it the text received so far; it returns every complete event and the
// unfinished tail to prepend to the next chunk.
export type ParsedSSE = { event: string; data: string };

export function parseSSE(buffer: string): { events: ParsedSSE[]; rest: string } {
  const events: ParsedSSE[] = [];
  let rest = buffer;
  while (true) {
    const idx = rest.indexOf("\n\n");
    if (idx === -1) break;
    const block = rest.slice(0, idx);
    rest = rest.slice(idx + 2);
    let event = "message";
    const dataLines: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event: ")) event = line.slice(7);
      else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
    }
    events.push({ event, data: dataLines.join("\n") });
  }
  return { events, rest };
}
