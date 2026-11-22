/** Browser/Node transport for the proposed same-artifact benchmark ABI.
 * Module/release authentication belongs to the caller and must precede instantiation.
 * This module never assigns a guest verdict, score or attestation.
 */
export const ABI = 1;
export const NAMESPACE = 0x424d4b31;
export const PHASE = Object.freeze({ denied: 0, collecting: 1, setup: 2, scored: 3,
  finishing: 4, done: 5, failed: 6, raw: 7, cancelled: 8 });
export const KIND = Object.freeze({ rgb: 1, ram: 2, pcm: 3, identity: 4, status: 5 });
const U32_MAX = 0xffffffff;
const MAX_TICKS = (1n << 53n) - 1n;
const MAX_INPUT = 16n * 1024n * 1024n;
const MAX_MEMORY = 512 * 1024 * 1024;
const FACTORY_TOKEN = Symbol('validated-module-transport');
const OUTPUT_CAPS = Object.freeze({ 1: 319872, 2: 65536, 3: 10227200, 4: 232, 5: 128 });
const EXPORTS = ['alloc', 'c64_buffer_release', 'c64_bench_abi', 'c64_bench_namespace',
  'c64_bench_open', 'c64_bench_provide', 'c64_bench_begin', 'c64_bench_pump',
  'c64_bench_cancel', 'c64_bench_finish', 'c64_bench_release',
  'c64_bench_output_len', 'c64_bench_copy'];

export class HarnessError extends Error {
  constructor(message, details = {}) { super(message); this.name = 'HarnessError';
    this.category = 'harness'; this.details = Object.freeze({ ...details }); }
}
export class OperationError extends HarnessError {
  constructor(operation, code) { super(`${operation} rejected (${code})`, { operation, code });
    this.name = 'OperationError'; this.code = code; }
}
function need(test, message) { if (!test) throw new HarnessError(message); }
// Capture intrinsic accessors once: caller-owned typed-array properties may be shadowed.
const U8 = Uint8Array;
const APPLY = Reflect.apply;
const TYPED = Object.getPrototypeOf(U8.prototype);
const GET_TAG = Object.getOwnPropertyDescriptor(TYPED, Symbol.toStringTag).get;
const GET_LENGTH = Object.getOwnPropertyDescriptor(TYPED, 'length').get;
const GET_BYTES = Object.getOwnPropertyDescriptor(TYPED, 'byteLength').get;
const GET_OFFSET = Object.getOwnPropertyDescriptor(TYPED, 'byteOffset').get;
const GET_BUFFER = Object.getOwnPropertyDescriptor(TYPED, 'buffer').get;
const GET_AB_BYTES = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const SET_BYTES = U8.prototype.set;
function byteInfo(value) {
    let info;
    try {
        info = {
            tag: APPLY(GET_TAG, value, []),
            length: APPLY(GET_LENGTH, value, []),
            byteLength: APPLY(GET_BYTES, value, []),
            byteOffset: APPLY(GET_OFFSET, value, []),
            buffer: APPLY(GET_BUFFER, value, [])
        };
        // The ArrayBuffer intrinsic rejects SAB, including cross-realm/spoofed buffers.
        APPLY(GET_AB_BYTES, info.buffer, []);
    } catch {
        need(false, 'ordinary unshared Uint8Array required; shared input is unsupported');
    }
    need(info.tag === 'Uint8Array' && info.length === info.byteLength,
        'Uint8Array intrinsic brand required');
    return info;
}
function copyBytes(info) {
    // Never consult the original view's iterator, getters, species or constructor.
    const copy = new U8(info.byteLength);
    const view = new U8(info.buffer, info.byteOffset, info.byteLength);
    APPLY(SET_BYTES, copy, [view]);
    return copy;
}
function bytes(value, length, cap) {
    need(Number.isSafeInteger(cap) && cap >= 0, 'explicit byte capture cap required');
    const info = byteInfo(value);
    need(info.byteLength <= cap, 'byte capture capacity exceeded');
    need(length === undefined || info.byteLength === length, 'wrong packet length');
    return copyBytes(info);
}
function words(raw, length) {
  const captured = bytes(raw, length, length), view = new DataView(captured.buffer);
  return Array.from({ length: length / 4 }, (_, i) => view.getUint32(i * 4, true));
}
const pair = (w, i) => BigInt(w[i]) | (BigInt(w[i + 1]) << 32n);
const hex = value => Array.from(value, x => x.toString(16).padStart(2, '0')).join('');

/** Parse independently serialized metadata. Parsing is not authentication. */
export function decodeStatus(raw, expectedHandle) {
  const w = words(raw, 128);
  need(w[0] === ABI && w[1] <= PHASE.cancelled, 'unsupported status ABI/phase');
  need(w[2] <= 14 && w[3] <= w[4] && w[4] <= 20, 'invalid status errors/slots');
  need(w[30] !== 0 && (expectedHandle === undefined || w[30] === expectedHandle), 'wrong status handle');
  need((w[31] & ~15) === 0, 'unknown metadata flags');
  const hasClock = !!(w[31] & 1), hasIdentity = !!(w[31] & 2);
  const rawFinished = !!(w[31] & 4), cancelIntegrity = !!(w[31] & 8);
  const limit = pair(w, 6), setup = pair(w, 8), scored = pair(w, 10);
  const finishing = pair(w, 12), stopTick = pair(w, 16), logicalBytes = pair(w, 19);
  const quarantineBytes = pair(w, 26), signedInputBytes = pair(w, 28);
  need(w[14] <= 2 && w[18] <= 2, 'invalid stop/frame metadata');
  need(finishing >= BigInt(w[18]), 'frame changes exceed finishing ticks');
  need(rawFinished === (w[1] === PHASE.raw), 'raw flag/phase conflict');
  need(!cancelIntegrity || (w[1] === PHASE.cancelled && hasClock), 'invalid cancellation flag');
  need(quarantineBytes <= MAX_INPUT + 1088n && signedInputBytes <= MAX_INPUT, 'input capacity exceeded');
  need(w[21] <= OUTPUT_CAPS[1] && (w[22] === 0 || w[22] === 65536)
    && w[23] <= OUTPUT_CAPS[3] && w[23] % 256 === 0, 'invalid output capacities');
  if (hasIdentity) {
    need(w[5] < 10000 && w[4] >= 5 && limit > 0n && limit <= MAX_TICKS, 'invalid signed metadata');
    need(signedInputBytes >= 36865n, 'signed input total is too short');
  } else need(w[5] === U32_MAX, 'index without identity');
  need(w[1] === PHASE.denied || hasIdentity, 'phase requires an authenticated identity');
  if (hasClock) need(hasIdentity && scored <= limit, 'invalid clock budget');
  else need(setup === 0n && scored === 0n && finishing === 0n && w[14] === 0
    && stopTick === 0n && w[18] === 0, 'invented clock before execution');
  if (w[14] === 0) need(w[15] === U32_MAX && stopTick === 0n && finishing === 0n && w[18] === 0, 'invalid absent stop');
  else {
    need(hasClock && stopTick > 0n && stopTick === scored, 'stop/counter conflict');
    if (w[14] === 1) need(w[15] <= 255, 'invalid debug cartridge byte');
    else need(w[15] === U32_MAX && stopTick === limit, 'invalid limit stop');
  }
  if (w[1] === PHASE.done || rawFinished) {
    need(hasClock && w[14] !== 0 && w[18] === 2 && finishing >= 2n, 'incomplete terminal clock');
  }
  if ([PHASE.setup, PHASE.scored, PHASE.finishing, PHASE.done, PHASE.raw].includes(w[1]))
    need(hasClock && hasIdentity && w[3] === w[4], 'phase requires complete authenticated execution');
  if (w[1] === PHASE.collecting) need(hasIdentity && !hasClock, 'invalid collection phase');
  if (w[1] === PHASE.collecting || (w[1] === PHASE.cancelled && !hasClock))
    need(logicalBytes === 0n, 'unstarted context has a resource estimate');
  if (w[1] === PHASE.failed || (w[1] === PHASE.cancelled && hasClock))
    need(w[3] === w[4], 'executed terminal context has incomplete inputs');
  if (w[1] === PHASE.cancelled && hasClock) need(w[18] < 2, 'completed clock cannot become cancelled');
  if (w[1] === PHASE.denied) need(!hasIdentity && !hasClock, 'invalid denied phase');
  if (w[1] === PHASE.denied)
    need(w[3] === 0 && w[4] === 0 && limit === 0n && signedInputBytes === 0n && logicalBytes === 0n,
      'denied context has signed metadata');
  if ([PHASE.setup, PHASE.scored].includes(w[1]))
    need(w[14] === 0 && finishing === 0n && w[18] === 0, 'execution phase has a terminal stop');
  if (w[1] === PHASE.setup) need(scored === 0n, 'setup has scored ticks');
  if (w[1] === PHASE.scored) need(scored < limit, 'scored phase already reached its limit');
  if (w[1] === PHASE.finishing) need(w[14] !== 0 && w[18] < 2, 'invalid finishing phase');
  if (!rawFinished) need(w.slice(21, 26).every(x => x === 0), 'non-raw output metadata');
  if (rawFinished) {
    need([[392, 272], [418, 235], [411, 234]].some(([x, y]) => x === w[24] && y === w[25]),
      'unknown raw picture geometry');
    need(w[21] === w[24] * w[25] * 3 && w[22] === 65536, 'raw output geometry differs');
  }
  return Object.freeze({ abi: w[0], phase: w[1], error: w[2], accepted: w[3], required: w[4],
    originalIndex: hasIdentity ? w[5] : null, limit, setup, scored, finishing,
    totalTicks: setup + scored + finishing,
    stop: w[14] === 0 ? null : Object.freeze({ kind: w[14], code: w[14] === 1 ? w[15] : null, tick: stopTick }),
    finishingFrameChanges: w[18], logicalBytes, rgbLength: w[21], ramLength: w[22],
    pcmLength: w[23], width: w[24], height: w[25], quarantineBytes, signedInputBytes,
    handle: w[30], hasClock, hasIdentity, rawFinished, cancelIntegrity });
}

export function decodeIdentity(raw) {
  const captured = bytes(raw, 232, 232), view = new DataView(captured.buffer);
  need(view.getUint32(0, true) === ABI, 'unsupported identity ABI');
  const originalIndex = view.getUint32(4, true);
  need(originalIndex < 10000, 'invalid original row index');
  return Object.freeze({ abi: ABI, originalIndex, testlistSha256: hex(captured.subarray(8, 40)),
    lineSha256: hex(captured.subarray(40, 72)), envelopeSha256: hex(captured.subarray(72, 104)),
    romSha256: Object.freeze(Array.from({ length: 4 }, (_, i) => hex(captured.subarray(104 + 32 * i, 136 + 32 * i)))) });
}

/** Host-side transport only. Caller owns the dedicated Worker and its wall deadline. */
class BenchmarkHost {
  #exports; #memory; #cap; #handle = 0; #dead = false;
  constructor(instance, { maxMemoryBytes = MAX_MEMORY } = {}, token) {
    need(token === FACTORY_TOKEN, 'use the guarded module factory');
    need(instance instanceof WebAssembly.Instance, 'actual WebAssembly.Instance required');
    need(Number.isSafeInteger(maxMemoryBytes) && maxMemoryBytes >= 65536 && maxMemoryBytes <= MAX_MEMORY,
      'invalid host memory budget');
    this.#exports = instance.exports; this.#memory = instance.exports.memory; this.#cap = maxMemoryBytes;
    need(this.#memory instanceof WebAssembly.Memory, 'exported memory required');
    for (const name of EXPORTS) need(typeof this.#exports[name] === 'function', `missing ${name}`);
    need(this.#invoke('c64_bench_abi') === ABI && this.#invoke('c64_bench_namespace') === NAMESPACE,
      'unsupported benchmark ABI/namespace');
  }
  #checkMemory() {
    if (this.#dead) this.#discard('discard this Worker/Instance after a trap or resource failure');
    const buffer = this.#memory.buffer;
    if ((typeof SharedArrayBuffer !== 'undefined' && buffer instanceof SharedArrayBuffer)
      || buffer.byteLength > this.#cap) {
      this.#discard('module memory resource limit/shared memory', { bytes: buffer.byteLength });
    }
  }
  #invoke(name, ...args) {
    this.#checkMemory();
    let value;
    try { value = this.#exports[name](...args); }
    catch (cause) { this.#discard(`WASM trap in ${name}`, { cause: String(cause) }); }
    this.#checkMemory();
    if (!Number.isInteger(value) || value < -2147483648 || value > U32_MAX) this.#discard('invalid ABI scalar');
    return value >>> 0;
  }
  #operation(name, ...args) {
    const code = this.#invoke(name, ...args);
    if (code === 1 || code === 2) this.#discard('busy/poisoned adapter requires a new Worker/Instance', { operation: name, code });
    if (code > 14) this.#discard('unknown operation error', { operation: name, code });
    if (code !== 0) throw new OperationError(name, code);
  }
  #discard(message, details = {}) {
    this.#dead = true;
    throw new HarnessError(message, { ...details, discardInstance: true });
  }
  #allocate(length) {
    const pointer = this.#invoke('alloc', length);
    if (pointer === 0 || pointer + length > this.#memory.buffer.byteLength) this.#discard('staging allocation failed');
    return pointer;
  }
  #free(pointer, length, mayHaveBeenConsumed = false) {
    if (this.#dead || !pointer) return;
    const released = this.#invoke('c64_buffer_release', pointer, length);
    if (released !== 0 && released !== 1) this.#discard('invalid owned-buffer release result');
    need(mayHaveBeenConsumed || released === 1, 'owned staging buffer was not returned');
  }
  #capturedInput(value, cap) {
    const info = byteInfo(value);
    need(info.buffer !== this.#memory.buffer, 'input must be an external captured byte array');
    return bytes(value, undefined, cap);
  }
  #stage(data) {
    const pointer = this.#allocate(data.byteLength);
    new Uint8Array(this.#memory.buffer, pointer, data.byteLength).set(data);
    return pointer;
  }
  #active() { need(this.#handle !== 0, 'no benchmark context'); return this.#handle; }
  open(envelope) {
    need(this.#handle === 0, 'release the existing context before opening another');
    const data = this.#capturedInput(envelope, 1088);
    need(data.byteLength >= 488 && data.byteLength <= 1088, 'envelope size outside SDK bounds');
    const reply = this.#allocate(16); let pointer = 0;
    try {
      pointer = this.#stage(data);
      const code = this.#invoke('c64_bench_open', pointer, data.byteLength, reply, 16);
      if (code === 1 || code === 2) this.#discard('open ownership restoration is uncertain; discard this instance', { code });
      if (code > 14) this.#discard('unknown open error', { code });
      const w = words(new Uint8Array(this.#memory.buffer, reply, 16), 16);
      if (w[0] !== ABI || w[1] !== NAMESPACE || w[3] !== code || (code === 0 && w[2] === 0))
        this.#discard('invalid open reply');
      this.#handle = w[2];
      if (code !== 0) throw new OperationError('c64_bench_open', code);
      return this.status();
    } finally {
      this.#free(pointer, data.byteLength, true); this.#free(reply, 16);
    }
  }
  provide(slot, value) {
    const handle = this.#active(), data = this.#capturedInput(value, 8 * 1024 * 1024);
    need(Number.isInteger(slot) && slot >= 0 && slot < 20 && data.byteLength > 0
      && data.byteLength <= 8 * 1024 * 1024, 'input slot/size outside SDK bounds');
    const pointer = this.#stage(data);
    try { this.#operation('c64_bench_provide', NAMESPACE, handle, slot, pointer, data.byteLength); }
    finally { this.#free(pointer, data.byteLength, true); }
  }
  begin() { this.#operation('c64_bench_begin', NAMESPACE, this.#active()); return this.status(); }
  pump(quota) {
    need(Number.isInteger(quota) && quota >= 1 && quota <= 4096, 'invalid pump quota');
    this.#operation('c64_bench_pump', NAMESPACE, this.#active(), quota); return this.status();
  }
  cancel() { this.#operation('c64_bench_cancel', NAMESPACE, this.#active()); return this.status(); }
  finish() { this.#operation('c64_bench_finish', NAMESPACE, this.#active()); return this.status(); }
  #length(kind) {
    const reply = this.#allocate(4);
    try {
      this.#operation('c64_bench_output_len', NAMESPACE, this.#active(), kind, reply, 4);
      const length = new DataView(this.#memory.buffer).getUint32(reply, true);
      need(length <= OUTPUT_CAPS[kind], 'output exceeds fixed capacity'); return length;
    } finally { this.#free(reply, 4); }
  }
  #copy(kind, length) {
    if (length === 0) {
      this.#operation('c64_bench_copy', NAMESPACE, this.#active(), kind, 0, 0);
      return new Uint8Array();
    }
    const pointer = this.#allocate(length);
    try {
      this.#operation('c64_bench_copy', NAMESPACE, this.#active(), kind, pointer, length);
      return new Uint8Array(this.#memory.buffer, pointer, length).slice();
    } finally { this.#free(pointer, length); }
  }
  status() {
    const raw = this.#copy(KIND.status, 128);
    try { return decodeStatus(raw, this.#active()); }
    catch (cause) { this.#discard('invalid engine status packet', { cause: String(cause) }); }
  }
  identity() { return decodeIdentity(this.#copy(KIND.identity, 232)); }
  rawOutputs() {
    const status = this.status(); need(status.phase === PHASE.raw, 'finish the completed Session first');
    const rgbLength = this.#length(KIND.rgb), ramLength = this.#length(KIND.ram), pcmLength = this.#length(KIND.pcm);
    need(rgbLength === status.rgbLength && ramLength === status.ramLength && pcmLength === status.pcmLength,
      'output lengths changed');
    const identity = this.identity(); need(identity.originalIndex === status.originalIndex, 'identity index changed');
    return { status, identity, rgb: this.#copy(KIND.rgb, rgbLength), ram: this.#copy(KIND.ram, ramLength),
      setupPcm: this.#copy(KIND.pcm, pcmLength), scope: 'untrusted-host-raw-observation-no-score' };
  }
  release() {
    if (this.#dead) { this.#handle = 0; return; } // Caller must terminate the Worker; do not mask its original error.
    if (!this.#handle) return;
    this.#operation('c64_bench_release', NAMESPACE, this.#handle); this.#handle = 0;
  }
}

/** Small static policy parser, not a substitute for WebAssembly validation or authentication. */
export function preflightWasmMemory(wasmBytes, maxMemoryBytes = MAX_MEMORY) {
  const b = bytes(wasmBytes, undefined, 16 * 1024 * 1024);
  need(Number.isSafeInteger(maxMemoryBytes) && maxMemoryBytes >= 65536 && maxMemoryBytes <= MAX_MEMORY,
    'invalid host memory budget');
  need(b.byteLength >= 8 && b.byteLength <= 16 * 1024 * 1024, 'WASM artifact size bound');
  need([0, 97, 115, 109, 1, 0, 0, 0].every((v, i) => b[i] === v), 'unsupported WASM header');
  let at = 8, memory = null;
  const u32 = end => {
    let n = 0;
    for (let i = 0; i < 5; i++) {
      need(at < end, 'truncated WASM LEB'); const v = b[at++];
      need(i !== 4 || (v & 0xf0) === 0, 'overflowing WASM LEB'); n += (v & 127) * 2 ** (7 * i);
      if (!(v & 128)) return n;
    }
    throw new HarnessError('unterminated WASM LEB');
  };
  while (at < b.length) {
    const id = b[at++]; need(id <= 13, 'unsupported WASM section');
    const length = u32(b.length), end = at + length; need(end <= b.length, 'truncated WASM section');
    if (id === 2) { need(u32(end) === 0, 'WASM imports are forbidden'); need(at === end, 'invalid empty import section'); }
    if (id === 8) throw new HarnessError('WASM start section is forbidden');
    if (id === 5) {
      need(memory === null && u32(end) === 1, 'exactly one internal memory required');
      need(u32(end) === 1, 'finite unshared wasm32 memory required');
      const minimumPages = u32(end), maximumPages = u32(end);
      need(at === end && minimumPages <= maximumPages && maximumPages <= 8192, 'invalid WASM memory bounds');
      need(minimumPages * 65536 <= maxMemoryBytes, 'initial memory exceeds host budget');
      memory = Object.freeze({ minimumPages, maximumPages });
    }
    at = end;
  }
  need(memory !== null, 'internal WASM memory missing'); return memory;
}

/** Caller MUST authenticate expectedSha256 through the signed release before calling. */
export async function instantiateBenchmark(wasmBytes, { expectedSha256, maxMemoryBytes = MAX_MEMORY } = {}) {
  const captured = bytes(wasmBytes, undefined, 16 * 1024 * 1024);
  need(captured.byteLength >= 8 && captured.byteLength <= 16 * 1024 * 1024, 'WASM artifact size bound');
  need(typeof expectedSha256 === 'string' && /^[0-9a-f]{64}$/.test(expectedSha256), 'authenticated expected WASM digest required');
  need(globalThis.crypto?.subtle, 'WebCrypto SHA-256 is required');
  const actual = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', captured)));
  need(actual === expectedSha256, 'WASM digest mismatch');
  preflightWasmMemory(captured, maxMemoryBytes); // Before instantiate, including before any start code.
  const module = await WebAssembly.compile(captured);
  need(WebAssembly.Module.imports(module).length === 0, 'benchmark artifact must have zero imports');
  const instance = await WebAssembly.instantiate(module, {});
  return new BenchmarkHost(instance, { maxMemoryBytes }, FACTORY_TOKEN);
}

export function rawMetadataJSON(value) {
  const active = new Set();
  const capture = item => {
    if (typeof item === 'bigint') return item.toString(10);
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number') { need(Number.isFinite(item) && (!Number.isInteger(item) || Number.isSafeInteger(item)), 'unsafe numeric metadata'); return item; }
    need(typeof item === 'object', 'unsupported metadata value');
    need(!ArrayBuffer.isView(item) && !(item instanceof ArrayBuffer), 'store raw byte outputs separately');
    need(!active.has(item), 'cyclic metadata');
    need(Array.isArray(item) || [Object.prototype, null].includes(Object.getPrototypeOf(item)), 'plain metadata objects required');
    active.add(item); const descriptors = Object.getOwnPropertyDescriptors(item);
    const out = Array.isArray(item) ? [] : Object.create(null);
    for (const key of Object.keys(item)) {
      const descriptor = descriptors[key]; need(Object.hasOwn(descriptor, 'value'), 'metadata accessors are unsupported');
      out[key] = capture(descriptor.value);
    }
    active.delete(item); return out;
  };
  return JSON.stringify(capture(value));
}
