// Browser-compatible built-in only; source prepared, runtime strictness unqualified.
// No Canvas, DOM image/color management, library download or custom DEFLATE.
export async function inflateZlibBounded(bytes, expectedBytes, signal, timeoutMs) {
  if (typeof DecompressionStream !== "function" || typeof Blob !== "function") {
    throw new Error("PNG_BUILTIN_INFLATE_UNAVAILABLE");
  }
  const control = new AbortController();
  const abort = () => control.abort(signal?.reason ?? new Error("PNG_ABORTED"));
  if (signal?.aborted) abort();
  signal?.addEventListener("abort", abort, {once: true});
  const timer = setTimeout(() => control.abort(new Error("PNG_INFLATE_DEADLINE")), timeoutMs);
  let reader;
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(
      new DecompressionStream("deflate"), {signal: control.signal});
    reader = stream.getReader();
    const output = new Uint8Array(expectedBytes);
    let at = 0;
    while (true) {
      if (control.signal.aborted) throw control.signal.reason;
      const {done, value} = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) || value.length > expectedBytes - at) {
        throw new Error("PNG_INFLATE_OUTPUT_CAP");
      }
      output.set(value, at); at += value.length;
    }
    if (at !== expectedBytes) throw new Error("PNG_INFLATE_SIZE_MISMATCH");
    return output;
  } finally {
    clearTimeout(timer); signal?.removeEventListener("abort", abort);
    if (reader) {
      // Native stream cancellation is requested, not treated as a hard realtime
      // cleanup guarantee. A host Worker deadline remains the outer hard gate.
      reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
}
