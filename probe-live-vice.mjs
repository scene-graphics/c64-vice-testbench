import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import inspector from 'node:inspector';
import path from 'node:path';
import {authenticate, sha, verifyBytes} from './src/showcase.mjs';
import {compareBalanced28Indexed, compareIndexed, OURS, PEPTO, quantizeRGB} from './src/comparator.mjs';
import {decodePngRgb8} from './src/png-rgb8.mjs';

const [directory, corpus, planFile, ...indices] = process.argv.slice(2);
const nativeScreenshots = process.env.C64_NATIVE_SCREENSHOTS === '1';
assert(!nativeScreenshots || !process.env.C64_WEBSITE_REUSE,
       'Native screenshot capture requires fresh receipts');
const queueProtocol = indices[0] === '--queue-v1';
if (queueProtocol) indices.shift();
assert.equal(Boolean(process.env.C64_WEBSITE_QUEUE), queueProtocol, 'Website worker queue protocol mismatch');
assert(directory && corpus, 'Usage: node probe-live-vice.mjs VERIFIED_RELEASE_DIR VICE_CORPUS [PLAN_JSON ORIGINAL_INDEX ...]');
const bootstrap = fs.readFileSync(path.join(directory, 'secure-boot.js'), 'utf8');
const pin = /const RELEASE_SHA256\s*=\s*['"]([a-f0-9]{64})['"]/.exec(bootstrap);
const manifest = fs.readFileSync(path.join(directory, 'boot-release.json'));
assert.equal(sha(manifest), pin?.[1]);
const release = authenticate(manifest, true);
const wasmPath = 'c64/c64.wasm';
const wasmDescriptor = {path: wasmPath, ...release.files[wasmPath]};
const wasm = verifyBytes(fs.readFileSync(path.join(directory, 'assets', wasmDescriptor.sha256)),
                         wasmDescriptor);

// Sites and locals come from V8's bytecode disassembly for this exact digest.
// All eight sites are existing SID write observation paths after the I/O and write checks.
assert.equal(wasmDescriptor.sha256, '1d769f456528d328bb8b2b6b740a1f273565a8526cad8d80f674ba26cfca5c6c',
             'Runtime observation sites need to be verified for this website release');
const sites = new Map([
  [178383, [4, 13]], [184822, [4, 13]], [191318, [7, 16]], [199496, [7, 16]],
  [219084, [13, 5]], [229170, [13, 5]], [261784, [10, 5]], [268488, [10, 5]],
]);

const models = {
  pal: {id: 0, width: 392, height: 272, stride: 504, lines: 312, x: 0, y: 0},
  ntsc: {id: 1, width: 418, height: 235, stride: 520, lines: 263, x: 77, y: 41},
};
const qualifiedRoms = {
  "c64/roms/1541.rom": "11d2cf1ef2cc2bfe406920f14eb0e35d8d8cf4800bf8cb6bd51fb4d8755f05a5",
  "c64/roms/basic.rom": "01f4b08554e4ad3117eb07ff04e4035ce70f1cfb4d49531f7675c2c323b5e737",
  "c64/roms/chargen.rom": "b163901b416541b1c7051f197b998c2893fb54ff3ab3112cf95ce08f826261f1",
  "c64/roms/kernal.rom": "e89b80272ac0a8c5504be47ea7da5829ce7e196fd2b967266cf570fc300e8d86"
};
for (const [file, digest] of Object.entries(qualifiedRoms))
  assert.equal(release.files[file]?.sha256, digest, `Unqualified website ROM: ${file}`);
const roms = await Promise.all(['chargen', 'basic', 'kernal', '1541'].map(async name => {
  const path = `c64/roms/${name}.rom`;
  const descriptor = {path, ...release.files[path]};
  const retained = `${directory}/assets/${descriptor.sha256}`;
  if (fs.existsSync(retained)) return verifyBytes(fs.readFileSync(retained), descriptor);
  const response = await fetch(`https://scene.graphics/player/${path}`, {signal: AbortSignal.timeout(30_000)});
  assert(response.ok, `Download failed for ${path}`);
  return verifyBytes(Buffer.from(await response.arrayBuffer()), descriptor);
}));
const glyphSourceSha = 'ad9a7173a17518d201216d75ffa02f3577efd58bc7826b5dae7007fc4139bcad';
function balancedFonts(assets, generatorPath) {
  const source = fs.readFileSync(generatorPath);
  assert.equal(sha(source), glyphSourceSha);
  const bytes = execFileSync('python3', ['-I', '-c', [
    'import sys',
    'scope = {}',
    'exec(compile(sys.stdin.buffer.read(), "glyph_probe_codes.py", "exec"), scope)',
    'sys.stdout.buffer.write(b"".join(scope["roms"](scope["generate"]())))',
  ].join('\n')], {input: source, timeout: 60_000});
  assert.equal(bytes.length, 28 * 4096);
  const variants = ['ones', 'zeros', ...Array.from({length: 28}, (_, i) => `id${String(i).padStart(2, '0')}`)];
  return variants.map((name, i) => {
    const font = i < 2 ? Buffer.alloc(4096, i === 0 ? 255 : 0) : bytes.subarray((i - 2) * 4096, (i - 1) * 4096);
    return verifyBytes(font, assets.get(`release-balanced28-${name}`));
  });
}
const original = (name, digest) => {
  const bytes = fs.readFileSync(path.join(corpus, 'testbench', 'selftest', `c64-${name}.prg`));
  assert.equal(sha(bytes), digest);
  return bytes;
};
const pass = original('pass', 'ca7940e06bb77fbacaa291992a8493d6616538b802e495e7cdb0c1c757f7bc74');
const fail = original('fail', '66da27452f09c9ab6fd7ebab31111f3c2b71dedd211672837361c52420df13eb');
const mirror = Buffer.from(pass);
const store = mirror.indexOf(Buffer.from([0x8e, 0xff, 0xd7]));
assert(store >= 0);
mirror.writeUInt16LE(0xd41f, store + 1);
const programEnd = pass.readUInt16LE() + pass.length - 2;
const loop = programEnd + 9;
const hidden = Buffer.concat([pass, Buffer.from([
  0xa9, 0x30, 0x85, 0x01,             // Bank out I/O and ROM.
  0xa9, 0xa5, 0x8d, 0xff, 0xd7,       // Write a marker to RAM under $D7FF.
  0x4c, loop & 255, loop >> 8,
])]);
hidden[store] = 0x4c;
hidden.writeUInt16LE(programEnd, store + 1);

const session = new inspector.Session();
session.connect();
const post = (method, params = {}) => new Promise((resolve, reject) =>
  session.post(method, params, (error, result) => error ? reject(error) : resolve(result)));
session.on('Debugger.scriptParsed', ({params}) => {
  if (params.scriptLanguage === 'WebAssembly') scriptId = params.scriptId;
});
function readProperties(objectId) {
  let values;
  let failure;
  session.post('Runtime.getProperties', {objectId, ownProperties: true}, (error, result) => {
    failure = error;
    values = result?.result;
  });
  if (failure) throw failure;
  assert(values, 'No debugger values at WASM breakpoint');
  return new Map(values.map(({name, value}) => [name, value]));
}
function wasmLocal(locals, index) {
  const local = locals.get(`$var${index}`);
  return readProperties(local.objectId).get('value');
}

let scriptId;
let engine;
let writes = [];
let error;
let capture;
let frameAtExit;
function instanceAddress(view, handle) {
  return view.getUint32(1228856, true) + (handle - 1) * 5688;
}
function readClock(handle) {
  const view = new DataView(engine.memory.buffer);
  const watch = view.getUint32(instanceAddress(view, handle) + 5512, true);
  assert(watch);
  const cycle = Number(view.getBigUint64(watch + 64, true));
  assert(Number.isSafeInteger(cycle));
  return cycle;
}
function completedFrame(handle, {width, height, stride, lines, x, y}) {
  // Same offsets read by c64_picture. Use the exact frame without calling a
  // reentrant export or advancing the machine.
  const memory = engine.memory.buffer;
  const view = new DataView(memory);
  const instance = instanceAddress(view, handle);
  const pointer = view.getUint32(instance + 4444, true);
  assert.equal(view.getUint32(instance + 4448, true), stride * lines);
  const source = new Uint8Array(memory, pointer, stride * lines);
  const data = new Uint8Array(width * height);
  for (let row = 0; row < height; row++) {
    const start = ((row + y) % lines) * stride + x;
    data.set(source.subarray(start, start + width), row * width);
  }
  return {width, height, data};
}
session.on('Debugger.paused', ({params}) => {
  try {
    const frame = params.callFrames[0];
    const site = sites.get(frame.location.columnNumber);
    assert(site && frame.location.scriptId === scriptId);
    const scope = frame.scopeChain.find(item => item.type === 'local');
    const locals = readProperties(scope.object.objectId);
    const pins = BigInt(wasmLocal(locals, site[0]).unserializableValue.slice(0, -1));
    const address = Number(pins & 0xffffn);
    if (address === 0xd7ff || address === 0xd41f) {
      const watch = wasmLocal(locals, site[1]).value;
      const cycle = Number(new DataView(engine.memory.buffer).getBigUint64(watch + 64, true));
      assert(Number.isSafeInteger(cycle) && cycle > 0);
      writes.push({address, value: Number((pins >> 16n) & 255n), cycle});
      if (address === 0xd7ff && capture && cycle > capture.boot && cycle <= capture.limit && !frameAtExit) {
        const view = new DataView(engine.memory.buffer);
        const count = view.getUint32(instanceAddress(view, capture.handle) + 5524, true);
        frameAtExit = {image: completedFrame(capture.handle, capture.model), count};
      }
    }
  } catch (cause) {
    error ??= cause;
  } finally {
    session.post('Debugger.resume');
  }
});
try {
  await post('Debugger.enable');
  const {instance} = await WebAssembly.instantiate(wasm);
  engine = instance.exports;
  assert(scriptId);
  for (const columnNumber of sites.keys()) {
    const location = {scriptId, lineNumber: 0, columnNumber};
    const [pinLocal] = sites.get(columnNumber);
    const address = `($var${pinLocal}.value & 65535n)`;
    const condition = `${address} === 55295n || ${address} === 54303n`;
    const breakpoint = await post('Debugger.setBreakpoint', {location, condition});
    assert.deepEqual(breakpoint.actualLocation, location);
  }

  const send = bytes => {
    const ptr = engine.alloc(bytes.length);
    assert(ptr);
    new Uint8Array(engine.memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  };
  const results = [];
  for (const [label, bytes, address, value] of [
    ['original-0', pass, 0xd7ff, 0], ['original-1', fail, 0xd7ff, 255],
    ['mirror-control', mirror, 0xd41f, 0], ['unmapped-control', hidden, null, 0xa5],
  ]) {
    writes = [];
    const handle = engine.c64_create(...roms.flatMap(send));
    assert(handle);
    try {
      engine.c64_watch_on(handle);
      assert(engine.c64_load_prg(handle, ...send(bytes)));
      assert(engine.c64_run(handle, 4096));
      if (error) throw error;
      assert.deepEqual(writes.map(event => [event.address, event.value]), address ? [[address, value]] : []);
      if (!address) assert.equal(engine.c64_peek(handle, 0xd7ff), value, 'RAM control marker was never written');
      results.push({label, programSha256: sha(bytes), writes,
                    debugCartExits: writes.filter(event => event.address === 0xd7ff)});
    } finally {
      engine.c64_destroy(handle);
    }
  }
  for (const model of Object.values(models)) {
    const handle = engine.c64_create_model(...roms.flatMap(send), model.id);
    assert(handle);
    try {
      assert.equal(engine.c64_width(handle), model.width);
      assert.equal(engine.c64_height(handle), model.height);
      assert(engine.c64_run(handle, 4096));
      const picture = engine.c64_picture(handle);
      assert(picture);
      const raw = completedFrame(handle, model);
      const rgba = new Uint8Array(engine.memory.buffer, picture, raw.width * raw.height * 4);
      for (const [index, color] of raw.data.entries()) {
        const [r, g, b] = OURS[color];
        const pixel = index * 4;
        assert(rgba[pixel] === r && rgba[pixel+1] === g && rgba[pixel+2] === b && rgba[pixel+3] === 255,
               `Completed-frame layout mismatch for model ${model.id}, pixel ${index}`);
      }
    } finally {
      engine.c64_destroy(handle);
    }
  }
  const cases = [];
  let getDiagnosticFonts;
  const receiptDir = process.env.C64_WEBSITE_RECEIPTS;
  const reuseDir = process.env.C64_WEBSITE_REUSE;
  const queue = process.env.C64_WEBSITE_QUEUE;
  const claim = index => {
    if (!queue) return true;
    try {
      fs.writeFileSync(path.join(queue, `${index}.claim`), String(process.pid), {flag: 'wx'});
      return true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      return false;
    }
  };
  if (receiptDir) fs.mkdirSync(receiptDir, {recursive: true});
  let previewFile = process.env.C64_PREVIEW_FRAME;
  let lastPreview = 0;
  function preview(handle, model, row, force = false) {
    if (!previewFile || (!force && Date.now() - lastPreview < 125)) return;
    lastPreview = Date.now();
    try {
      const {width, height, data} = completedFrame(handle, model);
      const header = JSON.stringify({index: row.index, line: row.line, width, height, palette: OURS});
      fs.writeFileSync(previewFile + '.next', Buffer.concat([Buffer.from(header + '\n'), data]));
      fs.renameSync(previewFile + '.next', previewFile);
    } catch (cause) {
      console.error('Live preview unavailable:', cause.message);
      previewFile = undefined;
    }
  }
  const record = result => {
    results.push(result);
    if (receiptDir) {
      const name = `${String(result.index).padStart(4, '0')}.json`;
      const receipt = {build: release.build, wasmSha256: wasmDescriptor.sha256, ...result};
      const target = path.join(receiptDir, name);
      fs.writeFileSync(target + '.next', JSON.stringify(receipt) + '\n', {flag: 'wx', flush: true});
      fs.renameSync(target + '.next', target);
    }
  };
  if (planFile) {
    assert(indices.every(index => /^\d{1,4}$/.test(index) && Number(index) < 1544));
    const planBytes = fs.readFileSync(planFile);
    assert.equal(sha(planBytes), 'a3c2663899bd07187da90345a5a77c2bae5b2a0b3a57058ca7bdce743356f05d');
    const plan = JSON.parse(planBytes);
    const list = fs.readFileSync(path.join(corpus, 'testbench/x64sc-testlist.txt'));
    assert.equal(sha(list), plan.policy_context.suite.testlist.sha256);
    const assets = new Map(plan.assets.map(asset => [asset.id, asset]));
    if (process.env.C64_BALANCED28_SOURCE) {
      let fonts;
      getDiagnosticFonts = () => fonts ??= balancedFonts(assets, process.env.C64_BALANCED28_SOURCE);
    }
    const readAsset = id => {
      const asset = assets.get(id);
      assert.equal(asset.source.kind, 'upstream');
      return verifyBytes(fs.readFileSync(path.join(corpus, asset.path)), asset);
    };
    const selected = indices.length ? indices.map(Number) : plan.cases.map(row => row.index);
    assert.equal(new Set(selected).size, selected.length, 'Duplicate original index');
    for (const index of selected) {
      const row = plan.cases[index];
      assert.equal(row.index, index);
      const priorFile = reuseDir && path.join(reuseDir, `${String(index).padStart(4, '0')}.json`);
      if (priorFile && fs.existsSync(priorFile) && row.type === 'exitcode' && !row.preexecution_status) {
        const prior = JSON.parse(fs.readFileSync(priorFile));
        assert.equal(prior.wasmSha256, wasmDescriptor.sha256, 'Prior receipt uses another website engine');
        assert.equal(prior.build, release.build, 'Prior receipt uses another website release');
        assert.equal(prior.index, index);
        assert.equal(prior.line, row.line);
        if (['guest-ok', 'guest-error', 'guest-timeout'].includes(prior.status)) {
          assert.equal(prior.programSha256, assets.get(row.slots[4].asset).sha256);
          assert.equal(prior.expected, row.expected);
          assert.equal(prior.limitCycle - prior.bootCycle, Number(row.cycles));
          const event = prior.exit;
          if (prior.status === 'guest-timeout') {
            assert(event === null && prior.observedThrough >= prior.limitCycle);
          } else {
            assert(event?.address === 0xd7ff && event.cycle > prior.bootCycle && event.cycle <= prior.limitCycle);
            assert(Number.isInteger(event.value) && event.value >= 0 && event.value <= 255);
            assert.equal(prior.status, event.value === 0 ? 'guest-ok' : 'guest-error');
          }
          if (claim(index)) record(prior);
          continue;
        }
      }
      const {machine, native_flags, reu_kib} = row.profile;
      const unsupported = [];
      if (row.dispatch !== 'prg') unsupported.push(`dispatch:${row.dispatch}`);
      if (row.slots.slice(5).some(slot => slot.role !== 6 || ![2, 4].includes(slot.format)))
        unsupported.push('mounted-media');
      if (!Object.hasOwn(models, machine)) unsupported.push(`model:${machine}`);
      if (native_flags & ~3) unsupported.push(`chip-profile:${native_flags}`);
      if (reu_kib !== 0 && reu_kib !== 16384) unsupported.push(`reu-kib:${reu_kib}`);
      if (row.preexecution_status) {
        if (claim(index)) record({index, line: row.line, status: row.preexecution_status});
      } else if (unsupported.length) {
        if (claim(index)) record({index, line: row.line, status: 'unsupported-by-probe', unsupported});
      } else {
        cases.push({row, readAsset});
      }
    }
  } else {
    const program = fs.readFileSync(path.join(corpus, 'VICII/colorsplit/colorsplit.prg'));
    assert.equal(sha(program), 'b0e160c340dcdb3cd3debb46cdba651a7c94135cf1c9f08b4f8262e0967467f2');
    const reference = fs.readFileSync(path.join(corpus, 'VICII/colorsplit/references/colorsplit.prg.png'));
    assert.equal(sha(reference), '559647fbd1caf9dbf3d724045c11c6d42c8ce895eb0b70565328645727d184b7');
    cases.push({row: {index: 739, cycles: '14000000', expected: 'ok',
                      profile: {machine: 'pal', native_flags: 0}, comparison: {alignment: [32, 36, 32, 35]}}, program, reference});
  }
  for (const entry of cases) {
    const {row, readAsset} = entry;
    if (!claim(row.index)) continue;
    let program = entry.program;
    let reference = entry.reference;
    let disks = [];
    if (readAsset) {
      try {
        program = readAsset(row.slots[4].asset);
        reference = row.comparison ? readAsset(row.comparison.reference) : null;
        disks = row.slots.slice(5).map(slot => readAsset(slot.asset));
      } catch (cause) {
        record({index: row.index, line: row.line, status: 'input-unavailable', detail: cause.message});
        continue;
      }
    }
    const model = models[row.profile.machine];
    const observe = (approachCycle = Infinity, font = roms[0]) => {
      const handle = engine.c64_create_model(...[font, ...roms.slice(1)].flatMap(send), model.id);
      assert(handle);
      try {
        capture = undefined;
        frameAtExit = undefined;
        writes = [];
        engine.c64_watch_on(handle);
        for (const [index, disk] of disks.entries()) {
          if (!engine.c64_add_disk(handle, ...send(disk)))
            return {rejectedDisk: {slot: index + 5, sha256: sha(disk)}};
        }
        if (row.profile.reu_kib === 16384)
          assert(engine.c64_reu(handle, ...send(Uint8Array.of(0))), 'Website REU setup failed');
        assert(engine.c64_load_prg(handle, ...send(program)));
        if (row.profile.native_flags & 1) engine.c64_cia_6526a(handle);
        if (row.profile.native_flags & 2) engine.c64_sid_8580(handle);
        const boot = readClock(handle);
        const limit = boot + Number(row.cycles);
        if (reference) capture = {handle, model, boot, limit};
        let exit;
        let exactFrame;
        let finalClock = boot;
        for (let clock = boot; clock < limit && !exit && !error;) {
          const remaining = Math.min(limit, approachCycle) - clock;
          const samples = Math.min(4096, Math.max(1, Math.floor(remaining / 22)));
          const framesBefore = reference ? engine.c64_frames(handle) : 0;
          assert(engine.c64_run(handle, samples));
          const next = readClock(handle);
          assert(next > clock && next - clock < 2 ** 32, 'Invalid observation interval');
          clock = next;
          finalClock = next;
          exit = writes.find(event => event.address === 0xd7ff &&
                             event.cycle > boot && event.cycle <= limit);
          if (approachCycle === Infinity && font === roms[0])
            preview(handle, model, row, Boolean(exit) || clock >= limit);
          if (reference && (exit || clock >= limit)) {
            // The completed image and counter advance together, at most once
            // per tick. Over a span shorter than 2^32 ticks, equal counters
            // prove there was no frame replacement after the write.
            const framesAfter = engine.c64_frames(handle);
            if (exit && frameAtExit?.count === framesAfter) exactFrame = frameAtExit.image;
            if (!exit && (clock === limit || framesBefore === framesAfter))
              exactFrame = completedFrame(handle, model);
          }
        }
        if (error) throw error;
        if (nativeScreenshots && reference) {
          // The native reference completes two frames after the stop. Replay an
          // observed exit close enough to reach both frame boundaries in order.
          const countAtStop = exit ? frameAtExit?.count
                                  : exactFrame ? engine.c64_frames(handle) : undefined;
          exactFrame = undefined;
          if (countAtStop !== undefined && (!exit || approachCycle !== Infinity)) {
            const target = (countAtStop + 2) >>> 0;
            let count = engine.c64_frames(handle);
            assert(((target - count) >>> 0) <= 2, 'Passed the native screenshot boundary');
            while (count !== target) {
              assert(engine.c64_run(handle, 16));
              const previous = count;
              count = engine.c64_frames(handle);
              assert(((count - previous) >>> 0) <= 1, 'Skipped a completed frame');
            }
            exactFrame = completedFrame(handle, model);
          }
        }
        return {exit, exactFrame, boot, limit, finalClock};
      } finally {
        engine.c64_destroy(handle);
      }
    };
    const observeFrame = font => {
      const first = observe(Infinity, font);
      if (!reference || !first.exit || first.exactFrame) return first;
      const replay = observe(first.exit.cycle, font);
      assert.deepEqual(replay.exit, first.exit, 'Exit changed during exact-frame replay');
      return replay;
    };
    try {
      const {exit, exactFrame, boot, limit, finalClock, rejectedDisk} = observeFrame();
      if (rejectedDisk) {
        record({index: row.index, line: row.line, status: 'website-disk-rejected',
                programSha256: sha(program), rejectedDisk});
        continue;
      }
      const result = {index: row.index, line: row.line, programSha256: sha(program), exit: exit ?? null,
                      status: 'no-exit-observed', bootCycle: boot, limitCycle: limit, observedThrough: finalClock};
      if (reference && exactFrame) {
        const {width, height, rgb} = await decodePngRgb8(reference);
        const [ox, oy, rx, ry] = row.comparison.alignment;
        const alignment = {ox, oy, rx, ry};
        const expectedFrame = quantizeRGB({width, height, data: rgb}, PEPTO);
        const raw = compareIndexed(expectedFrame, exactFrame, alignment);
        let pixels = raw;
        result.referenceSha256 = sha(reference);
        if (raw.bad && getDiagnosticFonts && row.policy_ids?.length === 31) {
          const fonts = getDiagnosticFonts();
          const images = fonts.map(font => observeFrame(font).exactFrame);
          if (images.every(Boolean)) {
            const [ones, zeros, ...bits] = images;
            pixels = compareBalanced28Indexed(expectedFrame, exactFrame, ones, zeros, bits, alignment);
            result.glyphDiagnostics = {sourceSha256: glyphSourceSha, fonts: fonts.map(sha), rawDifferent: raw.bad};
          }
        }
        result.screenshot = {different: pixels.bad, total: pixels.total};
        if (nativeScreenshots) result.screenshot.capture = 'native-two-frames-after-stop';
        result.status = pixels.bad ? 'screenshot-differs' : 'screenshot-matches';
        result.screenshot.at = exit ? 'exit' : 'cycle-limit';
        result.screenshot.frameVerified = true;
      } else if (reference) {
        result.status = 'frame-boundary-unresolved';
      } else if (exit) {
        result.status = exit.value === 0 ? 'guest-ok' : 'guest-error';
      } else {
        assert(finalClock >= limit, 'Clock stopped before the original budget');
        result.status = 'guest-timeout';
      }
      result.expected = row.expected;
      record(result);
    } catch (cause) {
      if (error) throw error;
      record({index: row.index, line: row.line, status: 'observation-failed', detail: cause.message});
    }
  }
  console.log(JSON.stringify({build: release.build, wasmSha256: sha(wasm), results}, null, 2));
} finally {
  session.disconnect();
}
