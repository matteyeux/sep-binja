"""
firmware_parser.py — Pure struct parsing for Apple SEP firmware images.

No LIEF, no Binary Ninja imports — only stdlib.  The entry point is
`extract_all_modules(data: bytes) -> list[SepModule]`.

Ported from sepsplit-rs (Rust) and used by both the CLI tool (sepsplit.py)
and the Binary Ninja view plugin (sep_view.py).
"""

from __future__ import annotations

import struct
import uuid as uuid_mod
from dataclasses import dataclass, field
from typing import Optional


# ── Constants ─────────────────────────────────────────────────────────────────

SEPHDR_SIZE    = 224
SEPAPP_64_SIZE = 128

MACHO_MAGIC_32 = 0xFEEDFACE
MACHO_MAGIC_64 = 0xFEEDFACF


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SepModule:
    """Describes one extracted SEP module.

    Physical offsets are relative to the start of the firmware file.
    binja_idx is the relocation-step multiplier used by the BN view plugin.
    """
    kind: str           # 'boot' | 'kernel' | 'sepos' | 'app' | 'shlib'
    name: str
    uuid: str           # hyphenated UUID string, '' for boot / raw kernel
    phys_text: int      # firmware offset for the TEXT / raw region
    size_text: int      # byte count of TEXT / raw region
    phys_data: int      # firmware offset for DATA  (0 = contiguous with TEXT)
    size_data: int      # byte count of DATA  (0 = none / contiguous)
    virt: int           # original virtual base (inside the Mach-O)
    ventry: int         # entry-point offset (from Mach-O start for Mach-O modules)
    is_macho: bool
    is_shlib: bool
    binja_idx: int      # multiply by RELOC_STEP to get the BN virtual base


# ── Low-level struct helpers ───────────────────────────────────────────────────

def get_srcver_major(srcver: int) -> int:
    """Extract the 24-bit major field from a packed SrcVer u64.

    Bitfield layout (LSB → MSB):
        patch3[10] | patch2[10] | patch1[10] | minor[10] | major[24]
    """
    return (srcver >> 40) & 0xFFFFFF


def fmt_uuid(b: bytes | bytearray) -> str:
    """Format 16 raw bytes (little-endian) as a hyphenated UUID string."""
    return str(uuid_mod.UUID(bytes_le=bytes(b)))


def c_str(b: bytes | bytearray) -> str:
    """Decode a null / space-padded fixed-width ASCII name."""
    s = bytes(b).decode("ascii", errors="replace").rstrip("\x00").strip()
    return s.split()[0] if s else ""


def is_macho(data: bytes, offset: int = 0) -> bool:
    if offset + 4 > len(data):
        return False
    magic = struct.unpack_from("<I", data, offset)[0]
    return magic in (MACHO_MAGIC_32, MACHO_MAGIC_64)


# ── SEP header detection ───────────────────────────────────────────────────────

def is_sep_firmware(data: bytes) -> bool:
    """Return True if data looks like a raw 64-bit SEP firmware image."""
    if len(data) < 0x1100:
        return False
    # IMG4 container — caller must pre-extract
    if data[:2] == bytes([0x30, 0x83]):
        return False
    # LZVN compressed
    if data[8:16] == b"eGirBwRD":
        return False
    # Look for legion2 marker in the expected locations
    return (data[0x103c : 0x103c + 16] == b"Built by legion2"
            or data[0x1004 : 0x1004 + 16] == b"Built by legion2")


def find_off(data: bytes) -> tuple[int, int]:
    """Return (hdr_offset, ver) for the SEP data header.

    ver == 2  → old 64-bit format (D20 iOS 11.0)
    ver == 3  → standard 64-bit (iOS 15 and below, Legion64Old)
    ver == 4  → modern 64-bit  (iOS 16+, Legion64)
    """
    if data[0x103c : 0x103c + 16] == b"Built by legion2":
        # iOS 16+ — Legion64
        p = 0x1000
        p += 8 + 4 + 8 + 4          # unk1, uuidtext, unk2, unk3
        p += 16                      # uuid
        p += 8 + 8                   # unk4, unk5
        subversion, = struct.unpack_from("<I", data, p); p += 4
        p += 16                      # legionstr
        structoff, = struct.unpack_from("<H", data, p)
        return int(structoff), int(subversion)

    if data[0x1004 : 0x1004 + 16] == b"Built by legion2":
        # iOS 15 and below — Legion64Old
        p = 0x1000
        subversion, = struct.unpack_from("<I", data, p); p += 4
        p += 16                      # legionstr
        structoff, = struct.unpack_from("<H", data, p)
        off = int(structoff) if structoff != 0 else 0xFFFF
        return off, int(subversion)

    raise ValueError("Unrecognised or 32-bit SEP firmware (not supported)")


# ── SEPDataHDR64 parsing ───────────────────────────────────────────────────────

def _parse_sephdr64(data: bytes, hdr_offset: int, ver: int, is_old: bool) -> dict:
    """Parse SEPDataHDR64 at hdr_offset.

    Returns a dict of fields plus '_apps_off' (offset where SEPApp64 array begins).
    """
    p = hdr_offset

    kernel_uuid           = data[p : p + 16]; p += 16
    _kheap,               = struct.unpack_from("<Q", data, p); p += 8
    kernel_base_paddr,    = struct.unpack_from("<Q", data, p); p += 8
    kernel_max_paddr,     = struct.unpack_from("<Q", data, p); p += 8
    _app_base,            = struct.unpack_from("<Q", data, p); p += 8
    _app_max,             = struct.unpack_from("<Q", data, p); p += 8
    _paddr_max,           = struct.unpack_from("<Q", data, p); p += 8
    _tz0,                 = struct.unpack_from("<Q", data, p); p += 8
    _tz1,                 = struct.unpack_from("<Q", data, p); p += 8
    ar_min_size,          = struct.unpack_from("<Q", data, p); p += 8

    if ar_min_size != 0 or ver == 4:
        p += 8 * 3                   # non_ar_min_size, shm_base, shm_size

    init_base_paddr, = struct.unpack_from("<Q", data, p); p += 8
    init_base_vaddr, = struct.unpack_from("<Q", data, p); p += 8
    init_vsize,      = struct.unpack_from("<Q", data, p); p += 8
    init_ventry,     = struct.unpack_from("<Q", data, p); p += 8
    p += 8 * 2                       # stack_base_paddr, stack_base_vaddr
    stack_size,      = struct.unpack_from("<Q", data, p); p += 8

    if stack_size != 0 or ver == 4:
        p += 8 * 3                   # mem_size, antireplay_mem_size, heap_mem_size

    if ver == 4:
        p += 4 + 4 + 8 * 3          # compact_ver_start/end, _unk1-3

    init_name = data[p : p + 16]; p += 16
    init_uuid = data[p : p + 16]; p += 16

    if not is_old:
        srcver, = struct.unpack_from("<Q", data, p); p += 8
    else:
        srcver = 0

    p += 4 + 1                       # crc32, coredump_sup
    pad  = bytes(data[p : p + 3]); p += 3

    if pad == bytes([0x40, 0x04, 0x00]):
        p += 0x100

    n_apps,   = struct.unpack_from("<I", data, p); p += 4
    n_shlibs, = struct.unpack_from("<I", data, p); p += 4

    return dict(
        kernel_uuid      = kernel_uuid,
        kernel_base_paddr= kernel_base_paddr,
        kernel_max_paddr = kernel_max_paddr,
        init_base_paddr  = init_base_paddr,
        init_base_vaddr  = init_base_vaddr,
        init_vsize       = init_vsize,
        init_ventry      = init_ventry,
        init_name        = init_name,
        init_uuid        = init_uuid,
        srcver           = srcver,
        stack_size       = stack_size,
        n_apps           = n_apps,
        n_shlibs         = n_shlibs,
        _apps_off        = p,
    )


# ── SEPApp64 parsing ───────────────────────────────────────────────────────────

def _parse_sepapp64(data: bytes, off: int, ver: int, is_old: bool) -> dict:
    """Parse one SEPApp64 entry at *off* and return a field dict."""
    p = off

    phys_text, = struct.unpack_from("<Q", data, p); p += 8
    size_text, = struct.unpack_from("<Q", data, p); p += 8
    phys_data, = struct.unpack_from("<Q", data, p); p += 8
    size_data, = struct.unpack_from("<Q", data, p); p += 8
    virt,      = struct.unpack_from("<Q", data, p); p += 8
    ventry,    = struct.unpack_from("<Q", data, p); p += 8
    stack_size,= struct.unpack_from("<Q", data, p); p += 8

    if not is_old:
        p += 8 * 2                   # mem_size, non_antireplay_mem_size

    if stack_size != 0 or ver == 4:
        p += 8                       # heap_mem_size

    if ver == 4:
        p += 8 * 4                   # _unk1 .. _unk4

    p += 4 + 4                       # compact_ver_start, compact_ver_end
    app_name = data[p : p + 16]; p += 16
    app_uuid = data[p : p + 16]; p += 16

    if not is_old:
        srcver, = struct.unpack_from("<Q", data, p); p += 8
    else:
        srcver = 0

    return dict(
        phys_text = phys_text,
        size_text = size_text,
        phys_data = phys_data,
        size_data = size_data,
        virt      = virt,
        ventry    = ventry,
        app_name  = app_name,
        app_uuid  = app_uuid,
        srcver    = srcver,
    )


def _sepapp_stride(srcver_major: int, is_old: bool) -> int:
    """Byte stride between consecutive SEPApp64 entries."""
    size = SEPAPP_64_SIZE
    if is_old:
        size -= 24
    if srcver_major < 1300:
        size -= 8
    if srcver_major >= 2000:
        size += 36
    elif srcver_major >= 1700:
        size += 4
    return size


# ── calc_size (pure-Python fallback, no LIEF) ──────────────────────────────────

def calc_size_raw(data: bytes) -> int:
    """Compute Mach-O byte length by scanning segment file offsets (no LIEF)."""
    if len(data) < 1024:
        return 0
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (MACHO_MAGIC_32, MACHO_MAGIC_64):
        return 0
    is64   = (magic == MACHO_MAGIC_64)
    ncmds  = struct.unpack_from("<I", data, 16)[0]
    p      = 28 + (4 if is64 else 0)
    tsize  = 0
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", data, p)
        if cmd == 0x01:    # LC_SEGMENT
            fo = struct.unpack_from("<I", data, p + 32)[0]
            fs = struct.unpack_from("<I", data, p + 36)[0]
            tsize = max(tsize, fo + fs)
        elif cmd == 0x19:  # LC_SEGMENT_64
            fo = struct.unpack_from("<Q", data, p + 40)[0]
            fs = struct.unpack_from("<Q", data, p + 48)[0]
            tsize = max(tsize, fo + fs)
        p += csz
    return tsize


# ── High-level entry point ─────────────────────────────────────────────────────

def extract_all_modules(data: bytes) -> list[SepModule]:
    """Parse a 64-bit SEP firmware image and return all embedded modules.

    Module order and binja_idx layout (mirrors the IDA plugin):
        binja_idx 0   → boot stub + raw kernel  (va = physical address)
        binja_idx 1   → SEPOS root server
        binja_idx 2…N → apps
        binja_idx N+1 → shared library (if present)
    """
    hdr_offset, ver = find_off(data)

    if ver == 1:
        raise ValueError("32-bit SEP firmware is not supported")

    is_old = (hdr_offset == 0xFFFF)
    if is_old:
        hdr_offset = 0x10F8

    if ver == 2:
        return _extract_ver2(data, hdr_offset)

    hdr      = _parse_sephdr64(data, hdr_offset, ver, is_old)
    apps_off = hdr["_apps_off"]
    n_apps   = hdr["n_apps"]
    n_shlibs = hdr["n_shlibs"]

    if n_apps == 0:
        apps_off += 0x100
        n_apps   = struct.unpack_from("<I", data, hdr_offset + 0x210)[0]
        n_shlibs = struct.unpack_from("<I", data, hdr_offset + 0x214)[0]

    kbase = hdr["kernel_base_paddr"]
    kmax  = hdr["kernel_max_paddr"]

    # Compute kernel size
    ksize = calc_size_raw(data[kbase:])
    if ksize == 0:
        ksize = kmax - kbase

    srcver_major = get_srcver_major(hdr["srcver"])
    stride = _sepapp_stride(srcver_major, is_old)

    modules: list[SepModule] = []

    # ── Boot stub ────────────────────────────────────────────────────────────
    modules.append(SepModule(
        kind="boot", name="SEPBOOT", uuid="",
        phys_text=0,    size_text=kbase,
        phys_data=0,    size_data=0,
        virt=0, ventry=0,
        is_macho=False, is_shlib=False,
        binja_idx=0,
    ))

    # ── Kernel ────────────────────────────────────────────────────────────────
    modules.append(SepModule(
        kind="kernel", name="kernel", uuid=fmt_uuid(hdr["kernel_uuid"]),
        phys_text=kbase, size_text=ksize,
        phys_data=0,     size_data=0,
        virt=kbase, ventry=kbase,
        is_macho=is_macho(data, kbase),
        is_shlib=False,
        binja_idx=0,     # shares the low address space with boot
    ))

    # ── SEPOS root server ─────────────────────────────────────────────────────
    ibase = hdr["init_base_paddr"]
    isz   = calc_size_raw(data[ibase:])
    if isz == 0:
        isz = hdr["init_vsize"]
    modules.append(SepModule(
        kind="sepos", name=c_str(hdr["init_name"]) or "SEPOS",
        uuid=fmt_uuid(hdr["init_uuid"]),
        phys_text=ibase, size_text=isz,
        phys_data=0,     size_data=0,   # DATA is contiguous for SEPOS
        virt=hdr["init_base_vaddr"],
        ventry=hdr["init_ventry"],
        is_macho=is_macho(data, ibase),
        is_shlib=False,
        binja_idx=1,
    ))

    # ── Apps ──────────────────────────────────────────────────────────────────
    off = apps_off
    for i in range(n_apps):
        app = _parse_sepapp64(data, off, ver, is_old)
        modules.append(SepModule(
            kind="app", name=c_str(app["app_name"]),
            uuid=fmt_uuid(app["app_uuid"]),
            phys_text=app["phys_text"], size_text=app["size_text"],
            phys_data=app["phys_data"], size_data=app["size_data"],
            virt=app["virt"],
            ventry=app["ventry"],
            is_macho=is_macho(data, app["phys_text"]),
            is_shlib=False,
            binja_idx=i + 2,
        ))
        off += stride

    # ── Shared libraries ──────────────────────────────────────────────────────
    for i in range(n_shlibs):
        app = _parse_sepapp64(data, off, ver, is_old)
        modules.append(SepModule(
            kind="shlib", name=c_str(app["app_name"]),
            uuid=fmt_uuid(app["app_uuid"]),
            phys_text=app["phys_text"], size_text=app["size_text"],
            phys_data=app["phys_data"], size_data=app["size_data"],
            virt=app["virt"],
            ventry=app["ventry"],
            is_macho=is_macho(data, app["phys_text"]),
            is_shlib=True,
            binja_idx=n_apps + 2 + i,
        ))
        off += stride

    return modules


# ── Ver-2 extraction (iOS 11 D20, subversion 2) ───────────────────────────────

def _extract_ver2(data: bytes, hdr_offset: int) -> list[SepModule]:
    """Handle the old iOS 11.0 D20 64-bit SEP format (subversion 2)."""
    p = hdr_offset
    _kernel_uuid   = data[p : p + 16]; p += 16
    kbase,   = struct.unpack_from("<Q", data, p); p += 8
    kmax,    = struct.unpack_from("<Q", data, p); p += 8
    p += 8 * 3                                       # unk1–3
    ibase,   = struct.unpack_from("<Q", data, p); p += 8
    ivaddr,  = struct.unpack_from("<Q", data, p); p += 8
    ivsz,    = struct.unpack_from("<Q", data, p); p += 8
    ive,     = struct.unpack_from("<Q", data, p); p += 8
    p += 8 * 3                                       # stack fields
    iname    = data[p : p + 16]; p += 16
    iuuid    = data[p : p + 16]; p += 16
    p += 4 + 1 + 3                                   # crc32, cdump, pad
    n_apps,  = struct.unpack_from("<I", data, p); p += 4
    n_shlibs,= struct.unpack_from("<I", data, p); p += 4

    modules: list[SepModule] = []

    modules.append(SepModule(
        kind="boot", name="BOOTER", uuid="",
        phys_text=0, size_text=0x1000,
        phys_data=0, size_data=0,
        virt=0, ventry=0,
        is_macho=False, is_shlib=False, binja_idx=0,
    ))

    ksize = calc_size_raw(data[0x4000:])
    modules.append(SepModule(
        kind="kernel", name="kernel", uuid="",
        phys_text=0x4000, size_text=ksize,
        phys_data=0, size_data=0,
        virt=0x4000, ventry=0x4000,
        is_macho=is_macho(data, 0x4000), is_shlib=False, binja_idx=0,
    ))

    modules.append(SepModule(
        kind="sepos", name=c_str(iname) or "SEPOS",
        uuid=fmt_uuid(iuuid),
        phys_text=ibase, size_text=ivsz,
        phys_data=0, size_data=0,
        virt=ivaddr, ventry=ive,
        is_macho=is_macho(data, ibase), is_shlib=False, binja_idx=1,
    ))

    off       = 0x1198
    app_stride = 0x58
    for i in range(n_apps + n_shlibs):
        q = off
        pt,   = struct.unpack_from("<Q", data, q); q += 8
        virt, = struct.unpack_from("<Q", data, q); q += 8
        st,   = struct.unpack_from("<Q", data, q); q += 8
        ve,   = struct.unpack_from("<Q", data, q); q += 8
        q += 8 * 2                   # stack_size, compact_ver
        aname = data[q      : q + 16]
        auuid = data[q + 16 : q + 32]
        modules.append(SepModule(
            kind="shlib" if i >= n_apps else "app",
            name=c_str(aname), uuid=fmt_uuid(auuid),
            phys_text=pt, size_text=st,
            phys_data=0, size_data=0,
            virt=virt, ventry=ve,
            is_macho=is_macho(data, pt), is_shlib=(i >= n_apps),
            binja_idx=i + 2,
        ))
        off += app_stride

    return modules
