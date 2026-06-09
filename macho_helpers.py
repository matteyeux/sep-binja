"""
Pure-struct mach-o parsing helpers for the binary ninja SEP plugin.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


LC_SEGMENT = 0x00000001
LC_SYMTAB = 0x00000002
LC_UNIXTHREAD = 0x00000005
LC_LOAD_DYLIB = 0x0000000C
LC_ID_DYLIB = 0x0000000D
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LAZY_LOAD_DYLIB = 0x00000020
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_SEGMENT_64 = 0x00000019
LC_MAIN = 0x80000028

# SEP load commands
LC_SEP_SEGMENT = 0x80000001

# Section type constants (low 8 bits of section.flags)
S_REGULAR = 0x00
S_ZEROFILL = 0x01
S_CSTRING_LITERALS = 0x02
S_4BYTE_LITERALS = 0x03
S_8BYTE_LITERALS = 0x04
S_LITERAL_POINTERS = 0x05
S_NON_LAZY_SYMBOL_POINTERS = 0x06
S_LAZY_SYMBOL_POINTERS = 0x07
S_SYMBOL_STUBS = 0x08
S_MOD_INIT_FUNC_POINTERS = 0x09
S_MOD_TERM_FUNC_POINTERS = 0x0A
S_COALESCED = 0x0B
S_GB_ZEROFILL = 0x0C
S_INTERPOSING = 0x0D
S_16BYTE_LITERALS = 0x0E
S_DTRACE_DOF = 0x0F
S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10
S_THREAD_LOCAL_REGULAR = 0x11
S_THREAD_LOCAL_ZEROFILL = 0x12
S_THREAD_LOCAL_VARIABLES = 0x13
S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15
S_INIT_FUNC_OFFSETS = 0x16
SECTION_TYPE_MASK = 0xFF

# Section attribute bits (high 24 bits of section.flags)
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

_DYLIB_CMDS = frozenset(
    {
        LC_LOAD_DYLIB,
        LC_LOAD_WEAK_DYLIB,
        LC_REEXPORT_DYLIB,
        LC_LAZY_LOAD_DYLIB,
        LC_LOAD_UPWARD_DYLIB,
    }
)
_ZEROFILL_TYPES = frozenset({S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL})


@dataclass
class MachOSection:
    name: str
    segment_name: str
    virtual_address: int
    size: int
    offset: int  # file offset within the binary bytes
    flags: int

    @property
    def sect_type(self) -> int:
        return self.flags & SECTION_TYPE_MASK

    @property
    def is_zerofill(self) -> bool:
        return self.sect_type in _ZEROFILL_TYPES


@dataclass
class MachOSegment:
    name: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    init_protection: int
    sections: list[MachOSection] = field(default_factory=list)


@dataclass
class MachOBinary:
    imagebase: int
    segments: list[MachOSegment]
    entry_pc: Optional[int]  # raw PC from LC_UNIXTHREAD
    entry_main: Optional[int]  # entrypoint offset from LC_MAIN
    symbols: list[tuple[str, int]]  # (name, vm_value)
    libraries: list[str] = field(default_factory=list)  # LC_LOAD_DYLIB names


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_macho(data: bytes) -> Optional[MachOBinary]:
    """Parse raw Mach-O bytes and return a MachOBinary.  Returns None on error."""
    if len(data) < 32:
        return None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:
        is64 = True
    elif magic == 0xFEEDFACE:
        is64 = False
    else:
        return None

    ncmds = struct.unpack_from("<I", data, 16)[0]
    p = 32 if is64 else 28  # Mach-O header size

    segments: list[MachOSegment] = []
    entry_pc: Optional[int] = None
    entry_main: Optional[int] = None
    sym_offset: Optional[int] = None
    sym_count: int = 0
    str_offset: Optional[int] = None
    libraries: list[str] = []

    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, csz = struct.unpack_from("<II", data, p)
        if csz < 8:
            break

        if cmd == LC_SEGMENT_64 and is64 and p + 72 <= len(data):
            segname = _cstr(data[p + 8 : p + 24])
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", data, p + 24
            )
            _maxprot, initprot, nsects, _flags = struct.unpack_from(
                "<IIII", data, p + 56
            )
            sections = _parse_sections_64(data, p + 72, nsects)
            segments.append(
                MachOSegment(
                    segname, vmaddr, vmsize, fileoff, filesize, initprot, sections
                )
            )

        elif cmd == LC_SEGMENT and not is64 and p + 56 <= len(data):
            segname = _cstr(data[p + 8 : p + 24])
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<IIII", data, p + 24
            )
            _maxprot, initprot, nsects, _flags = struct.unpack_from(
                "<IIII", data, p + 40
            )
            sections = _parse_sections_32(data, p + 56, nsects)
            segments.append(
                MachOSegment(
                    segname, vmaddr, vmsize, fileoff, filesize, initprot, sections
                )
            )

        elif cmd == LC_UNIXTHREAD:
            # ARM64 thread state: cmd(4)+cmdsize(4)+flavor(4)+count(4) = 16 byte header,
            # then x0-x28(232)+fp(8)+lr(8)+sp(8) = 256 bytes before pc.
            pc_off = p + 16 + 256
            if pc_off + 8 <= len(data):
                entry_pc = struct.unpack_from("<Q", data, pc_off)[0]

        elif cmd == LC_MAIN and p + 16 <= len(data):
            entry_main = struct.unpack_from("<Q", data, p + 8)[0]

        elif cmd == LC_SYMTAB and p + 24 <= len(data):
            sym_offset, sym_count, str_offset, _strsize = struct.unpack_from(
                "<IIII", data, p + 8
            )

        elif cmd in _DYLIB_CMDS and p + 24 <= len(data):
            (name_off,) = struct.unpack_from("<I", data, p + 8)
            if 0 < name_off < csz:
                start = p + name_off
                end_limit = p + csz
                end = data.find(b"\x00", start, end_limit)
                if end == -1:
                    end = end_limit
                name = data[start:end].decode("ascii", errors="replace").rstrip()
                if name:
                    libraries.append(name)

        p += csz

    non_pz = [s for s in segments if s.name != "__PAGEZERO"]
    imagebase = min((s.virtual_address for s in non_pz), default=0)

    symbols = _parse_symbols(data, sym_offset, sym_count, str_offset)

    return MachOBinary(imagebase, segments, entry_pc, entry_main, symbols, libraries)


def _cstr(b: bytes) -> str:
    end = b.find(b"\x00")
    return (
        b[:end].decode("ascii", errors="replace")
        if end != -1
        else b.decode("ascii", errors="replace")
    )


def _parse_sections_64(data: bytes, base: int, n: int) -> list[MachOSection]:
    # section_64: sectname[16] segname[16] addr[8] size[8] offset[4] align[4]
    #             reloff[4] nreloc[4] flags[4] reserved1[4] reserved2[4] reserved3[4]
    # total: 80 bytes
    sections = []
    p = base
    for _ in range(n):
        if p + 80 > len(data):
            break
        sname = _cstr(data[p : p + 16])
        segname = _cstr(data[p + 16 : p + 32])
        addr, sz = struct.unpack_from("<QQ", data, p + 32)
        offset = struct.unpack_from("<I", data, p + 48)[0]
        flags = struct.unpack_from("<I", data, p + 64)[0]
        sections.append(MachOSection(sname, segname, addr, sz, offset, flags))
        p += 80
    return sections


def _parse_sections_32(data: bytes, base: int, n: int) -> list[MachOSection]:
    # section: sectname[16] segname[16] addr[4] size[4] offset[4] align[4]
    #          reloff[4] nreloc[4] flags[4] reserved1[4] reserved2[4]
    # total: 68 bytes
    sections = []
    p = base
    for _ in range(n):
        if p + 68 > len(data):
            break
        sname = _cstr(data[p : p + 16])
        segname = _cstr(data[p + 16 : p + 32])
        addr, sz = struct.unpack_from("<II", data, p + 32)
        offset = struct.unpack_from("<I", data, p + 40)[0]
        flags = struct.unpack_from("<I", data, p + 56)[0]
        sections.append(MachOSection(sname, segname, addr, sz, offset, flags))
        p += 68
    return sections


def _parse_symbols(
    data: bytes, sym_offset: Optional[int], sym_count: int, str_offset: Optional[int]
) -> list[tuple[str, int]]:
    if not sym_offset or not str_offset or sym_count == 0:
        return []
    # nlist_64: n_strx[4] n_type[1] n_sect[1] n_desc[2] n_value[8] — 16 bytes
    symbols = []
    for i in range(sym_count):
        off = sym_offset + i * 16
        if off + 16 > len(data):
            break
        n_strx = struct.unpack_from("<I", data, off)[0]
        n_value = struct.unpack_from("<Q", data, off + 8)[0]
        if n_value == 0:
            continue
        str_start = str_offset + n_strx
        str_end = data.find(b"\x00", str_start)
        if str_end == -1:
            continue
        name = data[str_start:str_end].decode("ascii", errors="replace")
        if name:
            symbols.append((name, n_value))
    return symbols


def find_lc_sep_slide(data: bytes) -> Optional[int]:
    """Scan raw Mach-O bytes for the LC_SEP_SEGMENT (0x80000001) load command
    and return its dataoff field.  Returns None if not present."""
    if len(data) < 32:
        return None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return None
    is64 = magic == 0xFEEDFACF
    ncmds = struct.unpack_from("<I", data, 16)[0]
    p = 32 if is64 else 28
    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, csz = struct.unpack_from("<II", data, p)
        if csz < 8:
            break
        if cmd == LC_SEP_SEGMENT and csz >= 16:
            (dataoff,) = struct.unpack_from("<I", data, p + 8)
            return dataoff
        p += csz
    return None


def compute_shared_cache_slide(lc_sep_dataoff: int, imagebase: int) -> int:
    """Convert the raw LC_SEP_SEGMENT dataoff to a slide value."""
    return (lc_sep_dataoff & 0xFFFFF) - imagebase


def get_entry_point_va(binary: MachOBinary, module_base: int) -> Optional[int]:
    """Return the absolute BN virtual address of the binary's entry point."""
    if binary.entry_pc is not None:
        return module_base + binary.entry_pc
    if binary.entry_main is not None:
        return module_base + binary.imagebase + binary.entry_main
    return None


def iter_segments(binary: MachOBinary):
    """Yield every non-PAGEZERO, non-LINKEDIT segment."""
    for seg in binary.segments:
        if seg.name not in ("__PAGEZERO", "__LINKEDIT"):
            yield seg


def fw_offset_for(
    seg_file_offset: int, phys_text: int, phys_data: int, size_text: int
) -> int:
    """Convert a Mach-O file offset to a firmware physical offset."""
    if phys_data == 0 or seg_file_offset < size_text:
        return phys_text + seg_file_offset
    return phys_data + (seg_file_offset - size_text)
