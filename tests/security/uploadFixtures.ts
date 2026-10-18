/**
 * Security test fixtures for multipart upload limits and content validation.
 *
 * Buffers are built programmatically (with correct magic bytes) so tests can
 * exercise oversized, malformed and archive-bomb inputs against the upload
 * routes and the file security service without shipping binary blobs.
 */

import { deflateSync } from "zlib";

/** A minimal but structurally valid PDF body (correct magic bytes). */
export function validPdfBuffer(payload = "invoice evidence"): Buffer {
  return Buffer.concat([
    Buffer.from("%PDF-1.7\n", "latin1"),
    Buffer.from(payload, "latin1"),
    Buffer.from("\n%%EOF\n", "latin1"),
  ]);
}

/** A minimal PNG body: 8-byte magic followed by padding. */
export function validPngBuffer(sizeBytes = 64): Buffer {
  const magic = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([magic, Buffer.alloc(Math.max(0, sizeBytes - 8), 0x42)]);
}

/** A minimal JPEG body: SOI marker followed by padding. */
export function validJpegBuffer(sizeBytes = 64): Buffer {
  const magic = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
  return Buffer.concat([magic, Buffer.alloc(Math.max(0, sizeBytes - 4), 0x11)]);
}

/** A text body with no archive/execute signatures (valid text/plain). */
export function validTextBuffer(payload = "receipt notes"): Buffer {
  return Buffer.from(payload, "latin1");
}

/** A file that exceeds the given byte budget while claiming a valid PDF type. */
export function oversizedPdfBuffer(sizeBytes: number): Buffer {
  const header = Buffer.from("%PDF-1.7\n", "latin1");
  const padding = Buffer.alloc(Math.max(0, sizeBytes - header.length), 0x41);
  return Buffer.concat([header, padding]);
}

/** A script payload with no image magic — a spoofed .png upload. */
export function scriptAsImageBuffer(): Buffer {
  return Buffer.from(
    "<script>eval(atob('ZG9jdW1lbnQud3JpdGUoJ3hwcycp'))</script>",
    "latin1",
  );
}

/** An executable (MZ) smuggled into a .pdf upload. */
export function executableAsPdfBuffer(): Buffer {
  return Buffer.concat([
    Buffer.from("%PDF-1.7\n", "latin1"),
    Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03]),
    Buffer.alloc(32, 0x00),
  ]);
}

interface ZipEntrySpec {
  name: string;
  /** Raw (already compressed) payload stored in the archive. */
  data: Buffer;
  /** Declared decompressed size — may lie about the real expansion. */
  declaredUncompressedSize: number;
}

/**
 * Build a zip archive byte-for-byte (local headers + central directory +
 * EOCD) with fully controllable declared sizes. This lets tests forge
 * archive-bomb characteristics (huge declared decompressed size, extreme
 * compression ratio, huge entry counts) without a real zip library.
 */
export function buildZipBuffer(entries: ZipEntrySpec[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, "latin1");

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // local file header signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0, 6); // flags
    localHeader.writeUInt16LE(8, 8); // method: deflate
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0x21, 12); // mod date
    localHeader.writeUInt32LE(0, 14); // crc32
    localHeader.writeUInt32LE(entry.data.length, 18); // compressed size
    localHeader.writeUInt32LE(entry.declaredUncompressedSize, 22); // uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26); // filename length
    localHeader.writeUInt16LE(0, 28); // extra length

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // central directory signature
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0, 8); // flags
    centralHeader.writeUInt16LE(8, 10); // method: deflate
    centralHeader.writeUInt16LE(0, 12); // mod time
    centralHeader.writeUInt16LE(0x21, 14); // mod date
    centralHeader.writeUInt32LE(0, 16); // crc32
    centralHeader.writeUInt32LE(entry.data.length, 20); // compressed size
    centralHeader.writeUInt32LE(entry.declaredUncompressedSize, 24); // uncompressed size
    centralHeader.writeUInt16LE(nameBuf.length, 28); // filename length
    centralHeader.writeUInt16LE(0, 30); // extra length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk start
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE(0, 38); // external attrs
    centralHeader.writeUInt32LE(localOffset, 42); // local header offset

    localParts.push(localHeader, nameBuf, entry.data);
    centralParts.push(centralHeader, nameBuf);
    localOffset += localHeader.length + nameBuf.length + entry.data.length;
  }

  const centralDirectory = Buffer.concat(centralParts);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // central dir start disk
  eocd.writeUInt16LE(entries.length, 8); // entries on this disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(centralDirectory.length, 12); // central dir size
  eocd.writeUInt32LE(localOffset, 16); // central dir offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, centralDirectory, eocd]);
}

/** A legitimate small zip (one deflated entry, honest sizes). */
export function safeZipBuffer(): Buffer {
  const payload = deflateSync(Buffer.alloc(1024, 0x61)); // 1KB of 'a'
  return buildZipBuffer([
    {
      name: "content.txt",
      data: payload,
      declaredUncompressedSize: 1024,
    },
  ]);
}

/**
 * A classic zip bomb: a tiny deflated payload that declares a huge
 * decompressed size (512MB of zeros compresses to a few hundred bytes).
 */
export function zipBombBuffer(): Buffer {
  const payload = deflateSync(Buffer.alloc(1024 * 1024, 0x00)); // ~1MB zeros → tiny
  return buildZipBuffer([
    {
      name: "bomb.bin",
      data: payload,
      declaredUncompressedSize: 512 * 1024 * 1024, // claims 512MB
    },
  ]);
}

/** A zip bomb with an extreme number of entries (entry-count exhaustion). */
export function manyEntriesZipBuffer(entryCount = 200): Buffer {
  const payload = deflateSync(Buffer.from("x", "latin1"));
  const entries: ZipEntrySpec[] = [];
  for (let i = 0; i < entryCount; i++) {
    entries.push({
      name: `f${i}.txt`,
      data: payload,
      declaredUncompressedSize: 1,
    });
  }
  return buildZipBuffer(entries);
}

/** A docx-style upload: an OOXML file is a zip container under the hood. */
export function docxLikeBuffer(): Buffer {
  const payload = deflateSync(Buffer.from("[Content_Types].xml stub", "latin1"));
  return buildZipBuffer([
    {
      name: "[Content_Types].xml",
      data: payload,
      declaredUncompressedSize: 24,
    },
  ]);
}

/** A docx upload that is actually an archive bomb. */
export function docxBombBuffer(): Buffer {
  return zipBombBuffer();
}

/** Convenience: build a multer-compatible file object for unit tests. */
export function asMulterFile(overrides: {
  buffer: Buffer;
  mimetype: string;
  originalname?: string;
  size?: number;
}): Express.Multer.File {
  return {
    fieldname: "file",
    originalname: overrides.originalname ?? "upload.bin",
    encoding: "7bit",
    mimetype: overrides.mimetype,
    buffer: overrides.buffer,
    size: overrides.size ?? overrides.buffer.length,
  } as Express.Multer.File;
}
