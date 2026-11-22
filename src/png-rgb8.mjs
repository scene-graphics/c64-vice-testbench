import {inflateZlibBounded} from "./inflate-web.mjs";
export const PNG_LIMITS = Object.freeze({fileBytes: 4 * 1024 * 1024,
  width: 4096, height: 4096, pixels: 1024 * 1024, chunks: 1024, timeoutMs: 5000});
export class PngError extends Error {
  constructor(code, detail = "") { super(code + (detail ? ": " + detail : "")); this.code = code; }
}
const need = (ok, code) => { if (!ok) throw new PngError(code); };
const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; ++i) {
  let c = i;
  for (let bit = 0; bit < 8; ++bit) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
  crcTable[i] = c >>> 0;
}
function crc32(bytes, begin, end) {
  let c = 0xffffffff;
  for (let i = begin; i < end; ++i) c = crcTable[(c ^ bytes[i]) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function adler32(bytes) {
  let a = 1, b = 0;
  for (let i = 0; i < bytes.length; ++i) { a = (a + bytes[i]) % 65521; b = (b + a) % 65521; }
  return ((b << 16) | a) >>> 0;
}
const be32 = (b, at) => ((b[at] * 0x1000000) + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3]) >>> 0;
const paeth = (a, b, c) => {
  const p = a + b - c, x = Math.abs(p - a), y = Math.abs(p - b), z = Math.abs(p - c);
  return x <= y && x <= z ? a : y <= z ? b : c;
};

/** Source-prepared decoder, not authentication/benchmark acceptance.
 * Returns row-major RGB8 matching supported valid PNGs' Pillow.convert('RGB').
 * RGBA alpha/tRNS are dropped, not composited. Color/EXIF metadata is ignored.
 */
export async function decodePngRgb8(input, {signal, timeoutMs = 2000} = {}) {
  need(input instanceof Uint8Array && input.length >= 8 && input.length <= PNG_LIMITS.fileBytes, "PNG_FILE_CAP");
  need(!(typeof SharedArrayBuffer === "function" && input.buffer instanceof SharedArrayBuffer), "PNG_SHARED_INPUT_UNSUPPORTED");
  need(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= PNG_LIMITS.timeoutMs, "PNG_DEADLINE_ARGUMENT");
  const bytes = new Uint8Array(input); // Exclusive captured bytes before first await.
  const deadline = Date.now() + timeoutMs;
  const guard = () => {
    if (signal?.aborted) throw new PngError("PNG_ABORTED");
    if (Date.now() > deadline) throw new PngError("PNG_DEADLINE");
  };
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  need(signature.every((value, i) => bytes[i] === value), "PNG_SIGNATURE");
  let at = 8, count = 0, width, height, depth, color, palette;
  let idatStarted = false, idatClosed = false, ended = false, trnsSeen = false;
  let compressedBytes = 0;
  const parts = [];
  while (at < bytes.length) {
    guard(); need(++count <= PNG_LIMITS.chunks, "PNG_CHUNK_CAP");
    need(bytes.length - at >= 12, "PNG_CHUNK_TRUNCATED");
    const size = be32(bytes, at);
    need(size <= bytes.length - at - 12, "PNG_CHUNK_TRUNCATED");
    const typeBytes = bytes.subarray(at + 4, at + 8);
    need(typeBytes.every(c => (c >= 65 && c <= 90) || (c >= 97 && c <= 122)) && (typeBytes[2] & 32) === 0, "PNG_CHUNK_TYPE");
    const type = String.fromCharCode(...typeBytes), begin = at + 8, end = begin + size;
    need(crc32(bytes, at + 4, end) === be32(bytes, end), "PNG_CRC");
    if (count === 1) need(type === "IHDR", "PNG_IHDR_FIRST");
    if (idatStarted && type !== "IDAT") idatClosed = true;
    switch (type) {
      case "IHDR": {
        need(count === 1 && size === 13, "PNG_IHDR");
        width = be32(bytes, begin); height = be32(bytes, begin + 4);
        depth = bytes[begin + 8]; color = bytes[begin + 9];
        need(width > 0 && width <= PNG_LIMITS.width && height > 0 && height <= PNG_LIMITS.height && width * height <= PNG_LIMITS.pixels, "PNG_DIMENSION_CAP");
        need(bytes[begin + 10] === 0 && bytes[begin + 11] === 0, "PNG_METHOD_UNSUPPORTED");
        need(bytes[begin + 12] === 0, "PNG_INTERLACE_UNSUPPORTED");
        need(((color === 2 || color === 6) && depth === 8) || (color === 3 && [1, 2, 4, 8].includes(depth)), "PNG_COLOR_DEPTH_UNSUPPORTED");
        break;
      }
      case "PLTE":
        need(!palette && !idatStarted && size > 0 && size <= 768 && size % 3 === 0, "PNG_PALETTE");
        need(color !== 3 || size / 3 <= (1 << depth), "PNG_PALETTE");
        palette = bytes.subarray(begin, end); break;
      case "IDAT":
        need(!idatClosed && (color !== 3 || palette), "PNG_IDAT_ORDER");
        idatStarted = true; compressedBytes += size;
        need(compressedBytes <= PNG_LIMITS.fileBytes, "PNG_IDAT_CAP");
        parts.push(bytes.subarray(begin, end)); break;
      case "IEND":
        need(idatStarted && size === 0 && end + 4 === bytes.length, "PNG_IEND");
        ended = true; break;
      case "tRNS":
        need(!trnsSeen && !idatStarted && ((color === 3 && palette && size > 0 && size <= palette.length / 3) || (color === 2 && size === 6)), "PNG_TRNS");
        trnsSeen = true; break; // RGB conversion preserves stored RGB, discards alpha.
      case "acTL": case "fcTL": case "fdAT": throw new PngError("PNG_ANIMATION_UNSUPPORTED");
      default:
        need((typeBytes[0] & 32) !== 0, "PNG_CRITICAL_CHUNK_UNSUPPORTED");
        // iCCP/gAMA/sRGB/eXIf/bKGD/text/etc never alter stored pixel channels.
    }
    at = end + 4;
    if (ended) break;
  }
  need(ended && at === bytes.length && compressedBytes >= 6, "PNG_FRAMING");
  const channels = color === 6 ? 4 : color === 2 ? 3 : 1;
  const stride = Math.ceil(width * channels * depth / 8);
  const expectedBytes = (stride + 1) * height;
  need(Number.isSafeInteger(expectedBytes) && expectedBytes <= 4 * PNG_LIMITS.pixels + PNG_LIMITS.height, "PNG_INFLATE_CAP");
  const compressed = new Uint8Array(compressedBytes);
  let offset = 0; for (const part of parts) { compressed.set(part, offset); offset += part.length; }
  need((compressed[0] & 15) === 8 && (compressed[0] >>> 4) <= 7 && ((compressed[0] << 8) | compressed[1]) % 31 === 0 && (compressed[1] & 32) === 0, "PNG_ZLIB_HEADER");
  guard();
  let scanlines;
  try { scanlines = await inflateZlibBounded(compressed, expectedBytes, signal, Math.max(1, deadline - Date.now())); }
  catch (error) { throw new PngError("PNG_INFLATE_REJECTED", String(error?.message ?? error)); }
  need(adler32(scanlines) === be32(compressed, compressed.length - 4), "PNG_ADLER");
  const rgb = new Uint8Array(width * height * 3);
  let previous = new Uint8Array(stride), current = new Uint8Array(stride), out = 0, source = 0;
  const bpp = Math.max(1, Math.ceil(channels * depth / 8));
  for (let y = 0; y < height; ++y) {
    guard(); const filter = scanlines[source++]; need(filter <= 4, "PNG_FILTER");
    for (let x = 0; x < stride; ++x) {
      const left = x >= bpp ? current[x - bpp] : 0, up = previous[x], corner = x >= bpp ? previous[x - bpp] : 0;
      const predictor = filter === 0 ? 0 : filter === 1 ? left : filter === 2 ? up : filter === 3 ? Math.floor((left + up) / 2) : paeth(left, up, corner);
      current[x] = (scanlines[source++] + predictor) & 255;
    }
    for (let x = 0; x < width; ++x) {
      if (color === 3) {
        const bit = x * depth, index = (current[Math.floor(bit / 8)] >>> (8 - depth - (bit % 8))) & ((1 << depth) - 1);
        need(index * 3 + 2 < palette.length, "PNG_PALETTE_INDEX");
        rgb[out++] = palette[index * 3]; rgb[out++] = palette[index * 3 + 1]; rgb[out++] = palette[index * 3 + 2];
      } else {
        rgb[out++] = current[x * channels]; rgb[out++] = current[x * channels + 1]; rgb[out++] = current[x * channels + 2];
      }
    }
    [previous, current] = [current, previous];
  }
  return {width, height, rgb};
}
