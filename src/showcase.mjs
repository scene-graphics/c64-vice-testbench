// scene.graphics C64 showcase. Executes downloaded WASM, never builds an engine.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import {spawn, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {instantiateBenchmark, PHASE, rawMetadataJSON} from './benchmark-host.mjs';
import {decodePngRgb8} from './png-rgb8.mjs';
import {compareRGB, PEPTO} from './comparator.mjs';

// Independently installed scene.graphics public key. No keys come from downloads.
export const PUBLIC_KEY = 'Kc7vClsRPS+kQ0wIHtTZo+33Zt8Lq+Yw7GFSOc5sEGc=';
const key = crypto.createPublicKey({key: Buffer.concat([
  Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(PUBLIC_KEY, 'base64')
]), format: 'der', type: 'spki'});
export const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const check = (ok, message) => { if (!ok) throw Error(message); };
const hashOK = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const safePath = x => typeof x === 'string' && x.length <= 512 &&
  !/[\\:\x00-\x20\x7f?#%]/.test(x) && x.split('/').every(p => p && p !== '.' && p !== '..');
export function authenticate(raw, domain = null) {
  check(raw.length <= 2_000_000, 'Signed document exceeds size limit');
  const e = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(raw));
  check(typeof e.manifest === 'string' && typeof e.sig === 'string', 'Invalid signed envelope');
  const sig = Buffer.from(e.sig, 'base64'), msg = Buffer.from(e.manifest);
  check(msg.length <= 1_000_000 && sig.length === 64 && sig.toString('base64') === e.sig,
    'Invalid signature encoding');
  let signed = msg;
  if (Object.hasOwn(e, 'scheme')) {
    // true is retained for callers of the initial release-only helper.
    if (domain === true) domain = 'release';
    const role = domain === 'release' ? ['release', 'release.json', 'emulator-release-'] :
      domain === 'showcase' ? ['showcase', 'showcase.json', 'c64-showcase-'] : null;
    check(role && e.scheme === `xen-v2-${role[0]}-sha256`, 'Invalid release signature scheme');
    const hash = sha(msg);
    signed = Buffer.from(JSON.stringify({files: {[role[1]]: hash}, id: `${role[2]}${hash}`, v: 2}));
  }
  check(crypto.verify(null, signed, key, sig), 'Ed25519 signature rejected');
  return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(msg));
}
export function descriptor(d, cap = 16 * 1024 * 1024) {
  check(d && safePath(d.path) && hashOK(d.sha256) && Number.isSafeInteger(d.bytes) &&
    d.bytes > 0 && d.bytes <= cap, 'Invalid artifact descriptor');
  return d;
}
export function verifyBytes(b, d) {
  check(b.length === d.bytes && sha(b) === d.sha256, `SHA-256/length mismatch: ${d.path}`);
  return b;
}
// Independent structural decoding of the EXISTING Rust SDK1 signed policy.
// Rust independently verifies it again before accepting any guest input.
export function policyBytes(envelope) {
  check(envelope.length === 488, 'Showcase supports exactly four ROMs and one PRG');
  const signature = envelope.subarray(0, 64), b = envelope.subarray(64);
  const hash = sha(b);
  const xenMessage = Buffer.from(JSON.stringify({files: {'sdk1-policy.bin': hash}, id: `c64-sdk1-policy-${hash}`, v: 2}));
  check(crypto.verify(null, b, key, signature) || crypto.verify(null, xenMessage, key, signature), 'Case authorization signature rejected');
  check(b.subarray(0, 8).toString() === 'SGC64C01' && b.readUInt16LE(8) === 1 &&
    b[10] === 1 && b[11] <= 2 && b[12] <= 3 && b[13] === 1 && b.readUInt16LE(14) === 0 &&
    b[16] === 5 && b[17] === 1 && b[18] === 2 && b[19] === 0 &&
    b.subarray(52, 64).every(x => x === 0), 'Unsupported signed case recipe/profile');
  const slots = Array.from({length: 5}, (_, i) => {
    const at = 224 + i * 40;
    check(b[at] === i && b[at + 1] === (i === 4 ? 1 : 0) && b.readUInt16LE(at + 2) === 0,
      'Unsupported signed slot');
    const bytes = b.readUInt32LE(at + 4);
    check(i < 4 ? bytes === [4096, 8192, 8192, 16384][i] : bytes > 2 && bytes <= 65537,
      'Signed slot size is invalid');
    return {bytes, sha256: b.subarray(at + 8, at + 40).toString('hex')};
  });
  const limit = b.readBigUInt64LE(24);
  check(limit > 0n && limit <= BigInt(Number.MAX_SAFE_INTEGER), 'Invalid signed cycle limit');
  return {machine: b[11], flags: b[12], index: b.readUInt32LE(20), limit: String(limit),
    revision: b.subarray(32, 52).toString('hex'), testlist: b.subarray(64, 96).toString('hex'),
    line: b.subarray(192, 224).toString('hex'), slots};
}
export function catalogChecks(c, releaseDigest, release) {
  check(c.v === 1 && c.kind === 'scene.graphics/c64-showcase' && c.benchmark_abi === 1 &&
    c.release_sha256 === releaseDigest, 'Showcase and live release differ; retry after publication completes');
  check(c.repository === 'libsidplayfp/vice-testprogs' && /^[a-f0-9]{40}$/.test(c.revision),
    'Unsupported VICE upstream/revision');
  descriptor(c.testlist, 1_000_000);
  check(c.testlist.path === 'testbench/x64sc-testlist.txt', 'Wrong upstream test list');
  check(Array.isArray(c.cases) && c.cases.length > 0 && c.cases.length <= 64,
    'Showcase must explicitly list 1–64 selected cases');
  const ids = new Set();
  for (const row of c.cases) {
    check(Number.isInteger(row.index) && row.index >= 0 && row.index < 10000 && !ids.has(row.index),
      'Duplicate/invalid original case index'); ids.add(row.index);
    check(typeof row.line === 'string' && row.line.length < 4096 && hashOK(row.line_sha256) &&
      sha(Buffer.from(row.line)) === row.line_sha256, 'Original test row identity mismatch');
    check(['exitcode', 'screenshot'].includes(row.type) && ['ok', 'error', 'timeout'].includes(row.expected),
      'Unsupported original test expectation');
    descriptor(row.policy, 1088); descriptor(row.program, 65537);
    check(row.program.path.endsWith('.prg'), 'Showcase accepts PRG dispatch only');
    if (row.reference) descriptor(row.reference, 4 * 1024 * 1024);
  }
  check(release.v === 1 && release.kind === 'scene.graphics/emulator-release' &&
    release.build !== 'development', 'Invalid production release');
  for (const name of ['c64/c64.wasm', ...romPaths]) descriptor({path: name, ...release.files?.[name]});
  return c;
}
const romPaths = ['chargen', 'basic', 'kernal', '1541'].map(n => `c64/roms/${n}.rom`);
export function bindCase(catalog, row, p, release, testLines) {
  check(p.index === row.index && p.line === row.line_sha256 && p.revision === catalog.revision &&
    p.testlist === catalog.testlist.sha256 && testLines[p.index] === row.line,
    'Policy/catalog/original test list mismatch');
  const fields = row.line.split(',');
  check(fields[2] === row.type && fields[3] === p.limit &&
    (fields.includes('expect:error') ? 'error' : fields.includes('expect:timeout') ? 'timeout' : 'ok') === row.expected,
    'Catalog changed original type, cycle limit or expectation');
  const programPath = path.posix.normalize(path.posix.join('testbench', fields[0], fields[1]));
  check(programPath === row.program.path, 'Program differs from original test row');
  for (let i = 0; i < 4; i++) {
    const d = release.files[romPaths[i]];
    check(p.slots[i].bytes === d.bytes && p.slots[i].sha256 === d.sha256,
      'Case policy ROM differs from current production ROM; release needs matching policies');
  }
  check(p.slots[4].bytes === row.program.bytes && p.slots[4].sha256 === row.program.sha256,
    'Program differs from signed case authorization');
}
const crc32 = b => { let c = 0xffffffff; for (const v of b) { c ^= v;
  for (let i = 0; i < 8; i++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
} return (c ^ 0xffffffff) >>> 0; };
export function encodePng(width, height, rgb) {
  check(rgb.length === width * height * 3 && width > 0 && height > 0, 'Invalid RGB geometry');
  const chunk = (name, body) => {
    const type = Buffer.from(name), out = Buffer.alloc(body.length + 12);
    out.writeUInt32BE(body.length); type.copy(out, 4); Buffer.from(body).copy(out, 8);
    out.writeUInt32BE(crc32(out.subarray(4, -4)), out.length - 4); return out;
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 2;
  const scan = Buffer.alloc(height * (width * 3 + 1));
  for (let y = 0; y < height; y++) Buffer.from(rgb.subarray(y * width * 3, (y + 1) * width * 3)).copy(scan, y * (width * 3 + 1) + 1);
  return Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(scan)), chunk('IEND', Buffer.alloc(0))]);
}
export async function decodeImage(bytes) {
  const im = await decodePngRgb8(bytes);
  return {width: im.width, height: im.height, data: im.rgb};
}
export function viceArgs(p, roms, prg, screenshot, palette) {
  const model = ['c64', 'ntsc', 'oldntsc'][p.machine];
  return ['-default', '-console', '+sound', '-warp', '-seed', '1', '-model', model,
    '-ciamodel', String(p.flags & 1 ? 1 : 0), '-sidmodel', String(p.flags & 2 ? 1 : 0),
    '-VICIIfilter', '0', '-VICIIextpal', '-VICIIpalette', palette,
    '-VICIIsaturation', '1000', '-VICIIbrightness', '1000', '-VICIIcontrast', '1000',
    '-VICIIgamma', '1000', '-VICIItint', '1000', '-quicksaveformat', 'png',
    '-kernal', roms[2], '-basic', roms[1], '-chargen', roms[0],
    '-debugcart', '-jamaction', '1', '-limitcycles', p.limit,
    '-autostartprgmode', '1', '+autostart-delay-random',
    '-exitscreenshot', screenshot, '-autostart', prg];
}
export function viceObservation(result, text) {
  const log = text.replace(/\x1b\[[0-9;]*m/g, '');
  const marker = /DBGCART:\s*exit\((\d+)\)\s*cycles elapsed:\s*(\d+)/i.exec(log);
  const stop = marker ? {code: Number(marker[1]), elapsedCycles: marker[2]} : null;
  let outcome = 'harness';
  if (!result.timedOut && !result.logLimit && result.signal === null) {
    if (stop && stop.code === result.code && stop.code <= 255)
      outcome = stop.code === 0 ? 'ok' : 'error';
    else if (!stop && result.code === 1 && /^.*\bMain CPU:\s*(?:Error\s*-\s*)?cycle limit reached\.\s*$/mi.test(log))
      outcome = 'timeout';
  }
  return {outcome, stop, version: /\*\*\* VICE Version (.*?) \*\*\*/.exec(log)?.[1] || null};
}
function options(argv) {
  const a = {tests: [], output: `scene-c64-demo-${new Date().toISOString().replace(/[:.]/g, '-')}`,
    vice: 'x64sc', manifest: 'https://scene.graphics/player/c64/benchmark/showcase.json', timeout: 180};
  for (let i = 0; i < argv.length; i++) {
    const n = argv[i];
    if (['--help', '--list', '--all', '--verify-only'].includes(n)) a[n.slice(2)] = true;
    else if (['--test', '--output', '--vice', '--manifest-url', '--timeout'].includes(n)) {
      check(i + 1 < argv.length, `Missing value for ${n}`); const value = argv[++i];
      if (n === '--test') { check(/^\d{1,4}$/.test(value), '--test requires original zero-based row index'); a.tests.push(Number(value)); }
      else a[{'--manifest-url': 'manifest', '--timeout': 'timeout'}[n] || n.slice(2)] = value;
    } else if (n === '--verify-engine') {
      a.verifyEngine = true;
      if (argv[i + 1] && !argv[i + 1].startsWith('--')) a.localEngine = argv[++i];
    } else throw Error(`Unknown argument: ${n}`);
  }
  a.timeout = Number(a.timeout);
  check(Number.isInteger(a.timeout) && a.timeout >= 5 && a.timeout <= 1800, '--timeout range: 5..1800 seconds per engine/case');
  check(!a.all || !a.tests.length, 'Use --all or --test');
  check(!a.verifyEngine || !(a.all || a.tests.length || a.list || a['verify-only']),
    'Use --verify-engine as a separate operation');
  return a;
}
function usage() {
  console.log(`Usage: sh scene-c64-demo.sh [--test INDEX ... | --all] [--output DIRECTORY]
       sh scene-c64-demo.sh --list | --verify-only
       sh scene-c64-demo.sh --verify-engine [LOCAL_WASM] [--output DIRECTORY]

Requires Node.js 22+, curl, and VICE x64sc with PNG screenshot support.
Linux without a display: xvfb-run -a sh scene-c64-demo.sh --all
Options: --vice /path/to/x64sc, --timeout SECONDS (default 180 per engine/case)
         --manifest-url HTTPS_URL (default production showcase manifest)

Default: run the released selected showcase (maximum 64 cases), one case at a time.
Always downloads the CURRENT signed production release; never builds an engine.
Saves screenshots/{scene,vice,upstream}, exact input files, logs and report.json.
VICE is a comparison, not a hardware oracle. This selected demonstration is not
a whole-suite score. Host-produced reports are reproducible observations, not attestations.`);
}
export async function child(command, args, timeout, log, progress = () => {}) {
  const fd = fs.openSync(log, 'wx', 0o600);
  let proc;
  try {
    proc = spawn(command, args, {stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32'});
    return await new Promise((resolve, reject) => {
      let timedOut = false, interrupted = false, logLimit = false, logBytes = 0, killTimer, hostError;
      const kill = signal => { try {
        if (process.platform === 'win32') proc.kill(signal); else process.kill(-proc.pid, signal);
      } catch (e) { if (e.code !== 'ESRCH') throw e; } };
      const timer = setTimeout(() => { timedOut = true; kill('SIGTERM');
        killTimer = setTimeout(() => kill('SIGKILL'), 1000); }, timeout * 1000);
      const capture = b => {
        if (logLimit) return;
        const left = 2 * 1024 * 1024 - logBytes;
        try { fs.writeSync(fd, b.subarray(0, left)); logBytes += Math.min(left, b.length); }
        catch (e) { hostError = e; kill('SIGTERM');
          killTimer = setTimeout(() => kill('SIGKILL'), 1000); return; }
        if (b.length > left) { logLimit = true; kill('SIGTERM');
          killTimer = setTimeout(() => kill('SIGKILL'), 1000); }
      };
      proc.stdout.on('data', capture); proc.stderr.on('data', capture);
      const pulse = setInterval(progress, 15_000);
      const interrupt = () => { interrupted = true; kill('SIGTERM'); killTimer = setTimeout(() => kill('SIGKILL'), 1000); };
      process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
      const cleanup = () => { clearTimeout(timer); clearTimeout(killTimer); clearInterval(pulse);
        process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt); };
      proc.once('error', e => { cleanup(); reject(e); });
      proc.once('close', (code, signal) => { cleanup();
        if (hostError) reject(hostError);
        else if (interrupted) { const e = Error('Interrupted by user; remaining cases stay pending'); e.code = 'CANCELLED'; reject(e); }
        else resolve({code, signal, timedOut, logLimit}); });
    });
  } finally { fs.closeSync(fd); }
}
async function engineChild(jobFile) {
  const job = JSON.parse(fs.readFileSync(jobFile));
  const wasm = fs.readFileSync(job.wasm); verifyBytes(wasm, job.wasmDescriptor);
  const envelope = fs.readFileSync(job.policy); verifyBytes(envelope, job.policyDescriptor);
  const p = policyBytes(envelope);
  const host = await instantiateBenchmark(wasm, {expectedSha256: job.wasmDescriptor.sha256});
  const deadline = Date.now() + job.timeout * 1000; let s;
  try {
    s = host.open(envelope);
    for (let i = 0; i < job.inputs.length; i++) {
      const b = fs.readFileSync(job.inputs[i]);
      verifyBytes(b, {path: `slot-${i}`, ...p.slots[i]}); host.provide(i, b);
    }
    s = host.begin();
    while (s.phase !== PHASE.done) {
      check(Date.now() < deadline, 'Engine host deadline');
      check([PHASE.setup, PHASE.scored, PHASE.finishing].includes(s.phase), 'Engine session failed');
      s = host.pump(4096);
    }
    host.finish(); const out = host.rawOutputs();
    check(out.identity.originalIndex === p.index && out.identity.envelopeSha256 === sha(envelope) &&
      out.identity.testlistSha256 === p.testlist && out.identity.lineSha256 === p.line &&
      out.identity.romSha256.every((x, i) => x === p.slots[i].sha256) &&
      String(out.status.limit) === p.limit, 'Actual engine result identity changed');
    fs.writeFileSync(job.screenshot, encodePng(out.status.width, out.status.height, out.rgb), {flag: 'wx'});
    fs.writeFileSync(job.result, rawMetadataJSON({identity: out.identity, status: out.status}) + '\n', {flag: 'wx'});
  } finally { host.release(); }
}
async function main(argv) {
  const a = options(argv); if (a.help) return usage();
  check(Number(process.versions.node.split('.')[0]) >= 22, 'Node.js 22 or newer is required');
  const origin = new URL(a.manifest);
  check(origin.protocol === 'https:' && ['scene.graphics', 'files.scene.graphics'].includes(origin.hostname) &&
    !origin.username && !origin.password && !origin.hash && !origin.search,
    'Manifest must be an HTTPS scene.graphics production URL');
  const root = path.resolve(a.output); fs.mkdirSync(root, {mode: 0o700});
  for (const dir of ['assets', 'logs', 'jobs', 'screenshots/scene', 'screenshots/vice', 'screenshots/upstream'])
    fs.mkdirSync(path.join(root, dir), {recursive: true, mode: 0o700});
  const report = {v: 1, kind: 'scene.graphics/c64-showcase-observations', started: new Date().toISOString(),
    scope: 'selected-showcase-not-full-suite-score', trust: 'untrusted-local-host-observations',
    hostSources: Object.fromEntries(['showcase.mjs', 'benchmark-host.mjs', 'comparator.mjs', 'png-rgb8.mjs', 'inflate-web.mjs']
      .map(n => [n, sha(fs.readFileSync(new URL(n, import.meta.url)))])), records: []};
  const save = () => { fs.writeFileSync(path.join(root, 'report.next'), JSON.stringify(report, null, 2) + '\n');
    fs.renameSync(path.join(root, 'report.next'), path.join(root, 'report.json')); };
  let downloaded = 0; const cache = new Map();
  const fetchBytes = (url, cap) => {
    check(downloaded + cap <= 96 * 1024 * 1024, '96 MiB total download bound');
    const u = new URL(url); check(u.protocol === 'https:' && !u.username && !u.password && !u.hash, 'HTTPS required');
    const r = spawnSync('curl', ['--fail', '--silent', '--show-error', '--proto', '=https',
      '--connect-timeout', '10', '--max-time', '30', '--header', 'Cache-Control: no-cache',
      '--max-filesize', String(cap), '--url', url],
      {maxBuffer: cap + 65536, timeout: 35_000});
    check(!r.error && r.status === 0, `Download failed: ${url}\n${String(r.stderr || r.error || '').slice(-512)}`);
    check(r.stdout.length > 0 && r.stdout.length <= cap, 'Download size bound');
    downloaded += r.stdout.length; return r.stdout;
  };
  const retain = (name, b) => { const f = path.join(root, name); fs.writeFileSync(f, b, {flag: 'wx', mode: 0o600}); return f; };
  const asset = (url, d) => {
    descriptor(d); if (cache.has(d.sha256)) return cache.get(d.sha256);
    const b = verifyBytes(fetchBytes(url, d.bytes), d);
    const f = retain(`assets/${d.sha256}`, b); cache.set(d.sha256, {b, f}); return {b, f};
  };
  const upstreamURL = (revision, name) => `https://raw.githubusercontent.com/libsidplayfp/vice-testprogs/${revision}/${name.split('/').map(encodeURIComponent).join('/')}`;
  const productionURL = name => `https://scene.graphics/player/${name.split('/').map(encodeURIComponent).join('/')}`;
  try {
    const stat = fs.statfsSync(root);
    if (!a.verifyEngine)
      check(Number(stat.bavail) * Number(stat.bsize) >= 512 * 1024 * 1024, '512 MiB free disk space required (bounded run; no engine build)');
    console.log('Fetching and verifying current production release…');
    const bootstrap = fetchBytes('https://scene.graphics/player/secure-boot.js', 128 * 1024);
    const releasePin = /const RELEASE_SHA256\s*=\s*['"]([a-f0-9]{64})['"]/.exec(bootstrap.toString('utf8'));
    check(releasePin, 'Published bootstrap lacks a sealed release pin');
    retain('secure-boot.js', bootstrap); // Inspected as data; NEVER executed/imported.
    const releaseRaw = fetchBytes(`https://scene.graphics/player/boot-release.json?pin=${releasePin[1]}`, 2_000_000);
    check(sha(releaseRaw) === releasePin[1], 'Release differs from the current website bootstrap pin');
    const release = authenticate(releaseRaw, true), releaseDigest = sha(releaseRaw);
    check(release.kind === 'scene.graphics/emulator-release' && release.v === 1, 'Wrong release manifest');
    retain('boot-release.json', releaseRaw);
    const wasmDescriptor = {path: 'c64/c64.wasm', ...release.files['c64/c64.wasm']};
    if (a.verifyEngine) {
      const url = productionURL(wasmDescriptor.path);
      const wasm = asset(url, wasmDescriptor);
      const module = await WebAssembly.compile(wasm.b);
      const exports = WebAssembly.Module.exports(module).map(entry => entry.name);
      report.scope = 'website-engine-identity';
      report.release = {build: release.build, sha256: releaseDigest, publicKey: PUBLIC_KEY,
        wasm: {...wasmDescriptor, url, savedAs: path.relative(root, wasm.f)}};
      report.sdk1 = ['c64_bench_open', 'c64_bench_pump', 'c64_bench_copy'].every(name => exports.includes(name));
      if (a.localEngine) {
        const file = path.resolve(a.localEngine);
        report.localEngine = {file, matches: fs.statSync(file).size === wasmDescriptor.bytes &&
          fs.readFileSync(file).equals(wasm.b)};
        check(report.localEngine.matches, 'Local WASM differs from the signed website WASM');
      }
      report.status = 'website-engine-verified';
      save();
      console.log(`Verified website build ${release.build}\nWASM SHA-256 ${wasmDescriptor.sha256}\nSaved ${wasm.f}`);
      if (report.localEngine) console.log('Local WASM matches the website byte for byte.');
      return;
    }
    const catalogRaw = fetchBytes(a.manifest, 2_000_000), catalog = authenticate(catalogRaw, 'showcase');
    catalogChecks(catalog, releaseDigest, release); retain('showcase.json', catalogRaw);
    report.release = {build: release.build, sha256: releaseDigest, manifestURL: a.manifest,
      showcaseSha256: sha(catalogRaw), wasm: release.files['c64/c64.wasm'], publicKey: PUBLIC_KEY};
    const rows = catalog.cases.filter(c => !a.tests.length || a.tests.includes(c.index));
    check(rows.length > 0 && a.tests.every(i => rows.some(c => c.index === i)), 'Requested row is absent from released showcase; use --list');
    report.requested = rows.map(c => c.index); report.records = rows.map(c => ({index: c.index, line: c.line, status: 'pending'})); save();
    if (a.list) { for (const c of rows) console.log(`${c.index}\t${c.line}`); report.status = 'listed-no-guest-executed'; save(); return; }
    const wasm = asset(productionURL(wasmDescriptor.path), wasmDescriptor);
    const module = await WebAssembly.compile(wasm.b);
    check(WebAssembly.Module.imports(module).length === 0 && WebAssembly.Module.exports(module).some(x => x.name === 'c64_bench_open'),
      'Published engine lacks SDK1 benchmark interface; update the engine release before sharing this script');
    const roms = romPaths.map(n => asset(productionURL(n), {path: n, ...release.files[n]}));
    const testlist = asset(upstreamURL(catalog.revision, catalog.testlist.path), catalog.testlist);
    const lines = testlist.b.toString('utf8').split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith('#'));
    const prepared = [];
    for (const row of rows) {
      const policy = asset(new URL(row.policy.path, origin).href, row.policy);
      const p = policyBytes(policy.b); bindCase(catalog, row, p, release, lines);
      const program = asset(upstreamURL(catalog.revision, row.program.path), row.program);
      const reference = row.reference ? asset(upstreamURL(catalog.revision, row.reference.path), row.reference) : null;
      prepared.push({row, policy, p, program, reference});
    }
    report.downloadedBytes = downloaded; report.status = 'verified-no-guest-executed'; save();
    if (a['verify-only']) { console.log(`Verified ${prepared.length} cases; no guest executed. ${root}`); return; }
    // Some distributed VICE builds break their early -version path. Check the
    // actual required options in -help; record the version from each real run.
    const vice = spawnSync(a.vice, ['-help'], {encoding: 'utf8', maxBuffer: 256 * 1024, timeout: 10_000});
    const help = String(vice.stdout || '') + String(vice.stderr || '');
    check(!vice.error && ['-exitscreenshot', '-debugcart', '-limitcycles'].every(x => help.includes(x)),
      'VICE x64sc with testbench options is required; install VICE or use --vice /path/to/x64sc');
    report.viceHelpSha256 = sha(Buffer.from(help)); report.status = 'running'; save();
    const palette = retain('pepto.vpl', Buffer.from(PEPTO.map(rgb => rgb.map(n => n.toString(16).padStart(2, '0')).join(' ')).join('\n') + '\n'));
    for (let i = 0; i < prepared.length; i++) {
      const {row, p, policy, program, reference} = prepared[i], record = report.records[i];
      const name = String(row.index).padStart(4, '0'), relScene = `screenshots/scene/${name}.png`, relVice = `screenshots/vice/${name}.png`;
      const scenePNG = path.join(root, relScene), vicePNG = path.join(root, relVice);
      console.log(`[${i + 1}/${rows.length}] ${row.index} ${row.program.path}`);
      record.profile = {machine: ['pal', 'ntsc', 'ntscold'][p.machine], nativeFlags: p.flags, reuKiB: 0};
      record.originalCycleLimit = p.limit;
      record.methods = {scene: 'SDK1 original native setup, signed scored budget, two finishing frame changes',
        vice: 'VICE direct RAM injection autostart, debugcart, original global cycle limit, exit screenshot'};
      const free = fs.statfsSync(root);
      check(Number(free.bavail) * Number(free.bsize) >= 128 * 1024 * 1024, 'Stopping at 128 MiB remaining disk floor');
      const job = {wasm: wasm.f, wasmDescriptor, policy: policy.f, policyDescriptor: row.policy,
        inputs: [...roms.map(r => r.f), program.f], screenshot: scenePNG,
        result: path.join(root, `jobs/${name}-scene-result.json`), timeout: a.timeout};
      const jobPath = retain(`jobs/${name}.json`, Buffer.from(JSON.stringify(job)));
      record.status = 'running'; save();
      const scene = await child(process.execPath, [fileURLToPath(import.meta.url), '--engine-child', jobPath],
        a.timeout + 5, path.join(root, `logs/${name}-scene.log`), () => console.log(`  scene engine: ${row.index} still running`));
      const vicePRG = retain(`jobs/${name}.prg`, program.b);
      const args = viceArgs(p, roms.map(r => r.f), vicePRG, vicePNG, palette);
      record.viceCommand = [a.vice, ...args];
      const v = await child(a.vice, args, a.timeout, path.join(root, `logs/${name}-vice.log`),
        () => console.log(`  VICE: ${row.index} still running`));
      record.sceneProcess = scene; record.viceProcess = v;
      try {
        check(!scene.timedOut && !scene.logLimit && scene.code === 0 && !v.timedOut && !v.logLimit && v.signal === null,
          'Engine/VICE host error; inspect retained logs');
        const result = JSON.parse(fs.readFileSync(job.result)); record.scene = result;
        record.sceneOutcome = result.status.stop.kind === 2 ? 'timeout' : result.status.stop.code === 0 ? 'ok' : 'error';
        // VICE's standard testbench uses status 1 for cycle limit, ff for usual guest failure.
        // A status 1 alone is NOT a cycle-limit observation: require its actual log marker.
        const log = fs.readFileSync(path.join(root, `logs/${name}-vice.log`), 'utf8');
        const observation = viceObservation(v, log);
        record.viceVersion = observation.version;
        record.viceGuestStop = observation.stop; record.viceOutcome = observation.outcome;
        check(record.viceOutcome !== 'harness', 'VICE did not produce a recognized guest stop');
        const oursBytes = fs.readFileSync(scenePNG), viceBytes = fs.readFileSync(vicePNG);
        const ours = await decodeImage(oursBytes), other = await decodeImage(viceBytes);
        check(ours.data.some(x => x !== 0) && other.data.some(x => x !== 0), 'Empty screenshot is not evidence');
        const alignment = {ox: [32, 43, 44][p.machine], oy: p.machine ? 10 : 36, rx: 32, ry: 35};
        const cmp = compareRGB(other, ours, alignment);
        record.screenshots = {scene: {path: relScene, sha256: sha(oursBytes)}, vice: {path: relVice, sha256: sha(viceBytes)}};
        record.comparison = {policy: 'raw-palette-indices-no-glyph-exemptions', ...cmp};
        if (reference) {
          const refPath = `screenshots/upstream/${name}.png`; retain(refPath, reference.b);
          const ref = await decodeImage(reference.b);
          record.upstream = {path: refPath, sha256: sha(reference.b), scene: compareRGB(ref, ours, alignment),
            vice: compareRGB(ref, other, {ox: 32, oy: 35, rx: 32, ry: 35})};
        }
        record.expected = row.expected;
        record.sceneOriginalExpectation = row.type === 'exitcode' ? record.sceneOutcome === row.expected : null;
        record.viceOriginalExpectation = row.type === 'exitcode' ? record.viceOutcome === row.expected : null;
        record.status = 'observed';
        console.log(`  scene ${record.sceneOutcome}, VICE ${record.viceOutcome}; ${cmp.bad}/${cmp.total} aligned pixels differ`);
      } catch (e) { record.status = 'harness'; record.error = e.message; console.log(`  HARNESS: ${e.message}`); }
      save();
    }
    report.status = report.records.some(r => r.status !== 'observed') ? 'incomplete' : 'completed';
    report.summary = {requested: report.records.length,
      observed: report.records.filter(r => r.status === 'observed').length,
      harness: report.records.filter(r => r.status === 'harness').length,
      identicalPictures: report.records.filter(r => r.comparison?.bad === 0).length,
      differentPictures: report.records.filter(r => r.comparison?.bad > 0).length};
    report.finished = new Date().toISOString(); save();
    console.log(`Screenshots: ${path.join(root, 'screenshots')}\nReceipts: ${path.join(root, 'report.json')}`);
    if (report.status !== 'completed') process.exitCode = 2;
  } catch (e) {
    report.status = e.code === 'CANCELLED' ? 'cancelled' : 'failed'; report.error = e.message;
    for (const r of report.records) if (r.status === 'running') r.status = 'interrupted';
    save(); throw e;
  }
}
if (process.argv[1] && fs.existsSync(process.argv[1]) && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  try {
    if (process.argv[2] === '--engine-child') await engineChild(process.argv[3]);
    else await main(process.argv.slice(2));
  } catch (e) { console.error(`scene-c64-demo: ${e.message}`); process.exitCode = 2; }
}
