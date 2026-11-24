// Generates the extension icons (plain blue square with a white "U") as PNG files.
// Only Node built-ins: zlib for compression, a hand-written CRC32 for the PNG chunks.
// Run:  node extension/dev/make_icons.mjs

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "icons");
const SIZES = [16, 32, 48, 128];
const BACKGROUND = [0x2b, 0x5c, 0x94, 255]; // plain blue
const LETTER = [255, 255, 255, 255];

// CRC32 as required by the PNG spec (polynomial 0xEDB88320).
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const typeAndData = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData));
  return Buffer.concat([length, typeAndData, crc]);
}

function encodePng(size, rgba) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0); // width
  header.writeUInt32BE(size, 4); // height
  header[8] = 8; // bit depth
  header[9] = 6; // colour type RGBA
  header[10] = 0; // compression
  header[11] = 0; // filter
  header[12] = 0; // no interlace
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter type "None" for each row
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), // PNG signature
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function drawIcon(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const pad = Math.round(size * 0.22);
  const stroke = Math.max(2, Math.round(size * 0.16));
  const top = pad;
  const bottom = size - pad;
  const left = pad;
  const right = size - pad;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const inside = y >= top && y < bottom && x >= left && x < right;
      const leftBar = x < left + stroke;
      const rightBar = x >= right - stroke;
      const bottomBar = y >= bottom - stroke;
      const color = inside && (leftBar || rightBar || bottomBar) ? LETTER : BACKGROUND;
      pixels.set(color, (y * size + x) * 4);
    }
  }
  return encodePng(size, pixels);
}

mkdirSync(OUT_DIR, { recursive: true });
for (const size of SIZES) {
  const file = join(OUT_DIR, "icon" + size + ".png");
  writeFileSync(file, drawIcon(size));
  console.log("wrote", file);
}
