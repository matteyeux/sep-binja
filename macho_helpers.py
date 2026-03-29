"""
macho_helpers.py — LIEF-based Mach-O parsing helpers for the BN SEP plugin.

No Binary Ninja imports here; all functions return plain Python values so they
can also be used from the CLI tool.
"""

from __future__ import annotations

import struct
from typing import Optional

import lief

lief.logging.set_level(lief.logging.LEVEL.OFF)


# ── Private Apple SEP load commands ───────────────────────────────────────────
#
# These are not standard Mach-O.  LIEF reports them as "UNKNOWN".
#
#   0x80000001  (LC_SEGMENT | LC_SEP)  — shared-cache reference; formatted
#               like linkedit_data_command.  dataoff encodes the slide value.
#   0x80000002  (LC_SYMTAB  | LC_SEP)  — SEP symbol table variant
#   0x80000003  (LC_SYMSEG  | LC_SEP)  — SEP segment map variant

LC_SEP_SEGMENT  = 0x80000001
LC_SEP_SYMTAB   = 0x80000002
LC_SEP_SYMSEG   = 0x80000003


def parse_lief(data: bytes) -> Optional[lief.MachO.Binary]:
    """Parse Mach-O bytes with LIEF and return the first slice.

    Always returns a `Binary` (not `FatBinary`) regardless of input.
    Returns None if parsing fails.
    """
    try:
        result = lief.MachO.parse(bytes(data))
        if result is None:
            return None
        # lief.MachO.parse always returns FatBinary
        return result.at(0)
    except Exception:
        return None


def find_lc_sep_slide(data: bytes) -> Optional[int]:
    """Scan raw Mach-O bytes for the 0x80000001 load command and return its
    dataoff field, which encodes the shared-cache slide as:

        slide = (dataoff & 0xFFFFF) - imagebase

    Returns None if the command is not present.
    """
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return None
    is64  = (magic == 0xFEEDFACF)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    p     = 28 + (4 if is64 else 0)
    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, csz = struct.unpack_from("<II", data, p)
        if cmd == LC_SEP_SEGMENT and csz >= 16:
            dataoff, = struct.unpack_from("<I", data, p + 8)
            return dataoff
        p += csz
    return None


def compute_shared_cache_slide(lc_sep_dataoff: int, imagebase: int) -> int:
    """Convert the raw LC_SEP_SEGMENT dataoff to a slide value.

    Mirrors the IDA plugin formula:  slide = (dataoff & 0xFFFFF) - imagebase
    """
    return (lc_sep_dataoff & 0xFFFFF) - imagebase


def get_entry_point_va(binary: lief.MachO.Binary, module_base: int) -> Optional[int]:
    """Return the absolute BN virtual address of the binary's entry point.

    Handles both LC_UNIXTHREAD (raw PC) and LC_MAIN (offset from imagebase).
    Returns None if no entry point command is present.
    """
    try:
        if binary.thread_command:
            return module_base + binary.thread_command.pc
    except Exception:
        pass
    try:
        if binary.main_command:
            return module_base + binary.imagebase + binary.main_command.entrypoint
    except Exception:
        pass
    return None


def iter_segments(binary: lief.MachO.Binary):
    """Yield every non-PAGEZERO, non-LINKEDIT segment."""
    for seg in binary.segments:
        if seg.name not in ("__PAGEZERO", "__LINKEDIT"):
            yield seg


def fw_offset_for(seg_file_offset: int,
                  phys_text: int, phys_data: int,
                  size_text: int) -> int:
    """Convert a Mach-O file offset to a firmware physical offset.

    TEXT segments (file_offset < size_text) are at phys_text.
    DATA segments (file_offset >= size_text) are at phys_data when that
    address differs from what the Mach-O file layout would imply.
    If phys_data == 0 the whole binary is contiguous at phys_text.
    """
    if phys_data == 0 or seg_file_offset < size_text:
        return phys_text + seg_file_offset
    return phys_data + (seg_file_offset - size_text)
