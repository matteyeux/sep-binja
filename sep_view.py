"""
sep_view.py — Binary Ninja BinaryView plugin for Apple SEP firmware.

Maps every embedded Mach-O module at a distinct 4 GiB-aligned virtual
address range, creates typed sections, adds entry points, LIEF-derived
symbols, and resolves shared-library GOT references.

Virtual-address layout (same scheme as the IDA plugin):
    [0x0000_0000_0000, 0x0000_ffff_ffff]   boot stub + raw kernel
    [0x0001_0000_0000, …]                  SEPOS root server
    [0x0002_0000_0000, …]                  app[0]  (SEPD, …)
    …
    [0x000N_0000_0000, …]                  app[N-3]
    [0x000N+1_0000_0000, …]                shared library
"""

from __future__ import annotations

import struct
import traceback
from typing import Optional

import lief
from binaryninja import (
    Architecture,
    BinaryView,
    SectionSemantics,
    SegmentFlag,
    StructureBuilder,
    Symbol,
    SymbolType,
    Type,
    log_error,
    log_info,
    log_warn,
)

from .firmware_parser import (
    SepModule,
    _parse_sephdr64,
    _sepapp_stride,
    extract_all_modules,
    find_off,
    get_srcver_major,
    is_sep_firmware,
)
from .macho_helpers import (
    compute_shared_cache_slide,
    find_lc_sep_slide,
    fw_offset_for,
    get_entry_point_va,
    iter_segments,
    parse_lief,
)

# 4 GiB gap between every module
RELOC_STEP: int = 0x1_0000_0000


# ── Section-semantics helpers ─────────────────────────────────────────────────

_CODE_SECTION_NAMES = frozenset({
    "__text", "__auth_stubs", "__stubs", "__stub_helper",
    "__textcoal_nt", "__symbol_stub",
})

_ZEROFILL_TYPES = frozenset({
    lief.MachO.Section.TYPE.ZEROFILL,
    lief.MachO.Section.TYPE.GB_ZEROFILL,
    lief.MachO.Section.TYPE.THREAD_LOCAL_ZEROFILL,
})


def _seg_flags(seg: lief.MachO.SegmentCommand) -> SegmentFlag:
    flags = SegmentFlag.SegmentReadable
    prot  = int(seg.init_protection)
    if prot & 0x2:
        flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
    if prot & 0x4:
        flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
    if not (prot & 0x2) and not (prot & 0x4):
        # Read-only data (e.g. __DATA_CONST)
        flags |= SegmentFlag.SegmentContainsData
    return flags


def _section_semantics(sect: lief.MachO.Section) -> SectionSemantics:
    if sect.type in _ZEROFILL_TYPES:
        return SectionSemantics.ReadWriteDataSectionSemantics
    if sect.name in _CODE_SECTION_NAMES:
        return SectionSemantics.ReadOnlyCodeSectionSemantics
    seg_name = sect.segment_name
    if seg_name in ("__DATA", "__DATA_DIRTY", "__SEPOS", "STACK", "__BOOTARGS", "__LEGION"):
        return SectionSemantics.ReadWriteDataSectionSemantics
    if seg_name == "__DATA_CONST":
        return SectionSemantics.ReadOnlyDataSectionSemantics
    if seg_name == "__TEXT":
        return SectionSemantics.ReadOnlyDataSectionSemantics
    return SectionSemantics.DefaultSectionSemantics


# ── Main view ─────────────────────────────────────────────────────────────────

class SEPFirmwareView(BinaryView):
    name      = "SEP Firmware"
    long_name = "Apple SEP Firmware"

    # ── Detection ─────────────────────────────────────────────────────────────

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        raw = data.read(0, 0x1200)
        return is_sep_firmware(bytes(raw))

    # ── Construction ──────────────────────────────────────────────────────────

    def __init__(self, data: BinaryView) -> None:
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.arch     = Architecture['aarch64']
        self.platform = self.arch.standalone_platform
        self.data     = data

    # ── Load ──────────────────────────────────────────────────────────────────

    def perform_get_address_size(self) -> int:
        return 8

    def init(self) -> bool:
        self._plat = self.platform
        try:
            return self._load()
        except Exception:
            log_error(f"[SEP] load failed:\n{traceback.format_exc()}")
            return False

    def _load(self) -> bool:
        self.binary = self.data.read(0, self.data.length)
        self.arch = Architecture['aarch64']
        self.platform = self.arch.standalone_platform

        fw_size = self.data.length
        fw      = bytes(self.parent_view.read(0, fw_size))

        log_info("[SEP] parsing firmware …")
        modules = extract_all_modules(fw)
        log_info(f"[SEP] found {len(modules)} modules")

        # Locate the shared library first so we have its base address and
        # slide ready before processing the apps that reference it.
        shlib_base:  int = 0
        shlib_slide: int = 0
        for mod in modules:
            if mod.is_shlib and mod.is_macho:
                shlib_base = RELOC_STEP * mod.binja_idx
                lc_off = find_lc_sep_slide(fw[mod.phys_text : mod.phys_text + mod.size_text])
                if lc_off is not None:
                    shlib_slide = compute_shared_cache_slide(lc_off, mod.virt or 0x8000)
                    log_info(f"[SEP] shared-lib slide = {shlib_slide:#x}, base = {shlib_base:#x}")
                break

        for mod in modules:
            log_info(f"[SEP] loading {mod.kind:6s}  {mod.name}")
            self._load_module(fw, mod, shlib_base, shlib_slide)

        try:
            self._define_firmware_types(fw)
        except Exception:
            log_warn(f"[SEP] could not annotate firmware types:\n{traceback.format_exc()}")

        return True

    # ── Per-module loader ─────────────────────────────────────────────────────

    def _load_module(self, fw: bytes, mod: SepModule,
                     shlib_base: int, shlib_slide: int) -> None:
        module_base = RELOC_STEP * mod.binja_idx

        # Boot stub and raw kernel both live in the low address range with
        # their virtual address equal to their firmware physical offset.
        if mod.kind == "boot":
            self._map_raw(fw_offset=0, va=0, size=mod.size_text,
                          section_name="SEPBOOT",
                          flags=( SegmentFlag.SegmentReadable
                                | SegmentFlag.SegmentExecutable
                                | SegmentFlag.SegmentContainsCode ))
            self.add_entry_point(0)
            return

        if not mod.is_macho:
            # Raw kernel (AArch64 reset vector code, no Mach-O wrapper)
            va = mod.phys_text   # keep at physical offset in the low range
            self._map_raw(fw_offset=mod.phys_text, va=va, size=mod.size_text,
                          section_name=mod.name,
                          flags=( SegmentFlag.SegmentReadable
                                | SegmentFlag.SegmentExecutable
                                | SegmentFlag.SegmentContainsCode ))
            self.add_entry_point(va)
            return

        # Parse the Mach-O (TEXT region only; DATA comes from phys_data)
        raw_text = fw[mod.phys_text : mod.phys_text + mod.size_text]
        binary   = parse_lief(raw_text)
        if binary is None:
            log_warn(f"[SEP] LIEF could not parse Mach-O for '{mod.name}'; mapping raw")
            self._map_raw(fw_offset=mod.phys_text, va=module_base,
                          size=mod.size_text, section_name=mod.name,
                          flags=( SegmentFlag.SegmentReadable
                                | SegmentFlag.SegmentExecutable
                                | SegmentFlag.SegmentContainsCode ))
            return

        self._load_macho(fw, mod, binary, module_base, shlib_base, shlib_slide)

    # ── Mach-O loader ─────────────────────────────────────────────────────────

    def _load_macho(self, fw: bytes, mod: SepModule,
                    binary: lief.MachO.Binary, module_base: int,
                    shlib_base: int, shlib_slide: int) -> None:

        # ── Mach-O header section ────────────────────────────────────────────
        imagebase    = int(binary.imagebase)
        hdr_va_start = module_base + imagebase
        hdr_size     = binary.sections[0].offset if binary.sections else 0x100
        self.add_auto_segment(
            hdr_va_start, hdr_size,
            mod.phys_text, hdr_size,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData,
        )
        self.add_auto_section(
            f"{mod.name}:HEADER", hdr_va_start, hdr_size,
            SectionSemantics.ReadOnlyDataSectionSemantics,
        )

        # ── Per-segment mapping ───────────────────────────────────────────────
        for seg in iter_segments(binary):
            seg_va      = module_base + int(seg.virtual_address)
            seg_vsz     = int(seg.virtual_size) or int(seg.file_size)
            seg_fw_off  = fw_offset_for(int(seg.file_offset),
                                        mod.phys_text, mod.phys_data, mod.size_text)
            seg_file_sz = int(seg.file_size)
            seg_flags   = _seg_flags(seg)

            self.add_auto_segment(
                seg_va, seg_vsz,
                seg_fw_off, seg_file_sz,
                seg_flags,
            )

            # ── Per-section mapping ───────────────────────────────────────────
            for sect in seg.sections:
                sect_va   = module_base + int(sect.virtual_address)
                sect_size = int(sect.size)
                if sect_size == 0:
                    continue

                sect_fw_off = fw_offset_for(int(sect.offset),
                                            mod.phys_text, mod.phys_data, mod.size_text)
                semantics   = _section_semantics(sect)
                sect_name   = f"{mod.name}:{sect.segment_name}:{sect.name}"

                self.add_auto_section(sect_name, sect_va, sect_size, semantics)

                # ── Data fixups ───────────────────────────────────────────────
                if sect.name in ("__mod_init_func", "__init_offsets", "__auth_ptr"):
                    self._fix_init_funcs(sect_va, sect_size,
                                         module_base + imagebase, fw, sect_fw_off)

                if sect.name in ("__auth_got", "__got") and shlib_base:
                    self._fix_got(sect_va, sect_size,
                                  shlib_base, shlib_slide, fw, sect_fw_off)

                if sect.name == "__const":
                    self._fix_tagged_pointers(sect_va, sect_size,
                                              module_base + imagebase,
                                              fw, sect_fw_off,
                                              binary)

        # ── Entry point + entry symbol ────────────────────────────────────────
        entry_va = get_entry_point_va(binary, module_base)
        if entry_va is not None:
            self.add_entry_point(entry_va)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, entry_va, f"{mod.name}_start")
            )

        # ── LIEF-derived symbols ──────────────────────────────────────────────
        for sym in binary.symbols:
            if not sym.name:
                continue
            sym_va = module_base + int(sym.value)
            if sym_va == module_base:
                continue
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, sym_va, sym.name)
            )

    # ── Firmware type annotations ─────────────────────────────────────────────

    def _define_firmware_types(self, fw: bytes) -> None:
        """Define Legion64BootArgs, SEPRootserver and SEPApp64 types and apply them.

        Legion64BootArgs is applied at 0x1000 (the hardware header base).
        SEPApp64 instances are applied at apps_off, apps_off+stride, …
        """
        hdr_offset, ver = find_off(fw)
        if ver < 3:
            return  # ver-2 layout not worth annotating

        is_old = (hdr_offset == 0xFFFF)
        if is_old:
            hdr_offset = 0x10F8

        BOOT_START: int = 0x1000   # Legion64 header always starts here

        hdr          = _parse_sephdr64(fw, hdr_offset, ver, is_old)
        srcver_major = get_srcver_major(hdr["srcver"])
        apps_off     = hdr["_apps_off"]
        n_apps       = hdr["n_apps"]
        n_shlibs     = hdr["n_shlibs"]

        if n_apps == 0:
            apps_off += 0x100
            n_apps   = struct.unpack_from("<I", fw, hdr_offset + 0x210)[0]
            n_shlibs = struct.unpack_from("<I", fw, hdr_offset + 0x214)[0]

        stride = _sepapp_stride(srcver_major, is_old)

        u8  = Type.int(1, False)
        u16 = Type.int(2, False)
        u32 = Type.int(4, False)
        u64 = Type.int(8, False)

        # ── SEPApp64 / _boot_file_descriptor64 ────────────────────────────────
        a      = StructureBuilder.create()
        a.packed = True
        app_sz = [0]

        def af(name: str, t: Type, size: int) -> None:
            a.append(t, name)
            app_sz[0] += size

        af("phys_text",               u64, 8)
        af("size_text",               u64, 8)
        af("phys_data",               u64, 8)
        af("size_data",               u64, 8)
        af("virt",                    u64, 8)
        af("ventry",                  u64, 8)
        af("stack_size",              u64, 8)
        if not is_old:
            af("mem_size",            u64, 8)
            af("non_ar_mem_size",     u64, 8)
        if ver == 4:
            af("heap_mem_size",       u64, 8)
            af("_unk1",               u64, 8)
            af("_unk2",               u64, 8)
            af("_unk3",               u64, 8)
            af("_unk4",               u64, 8)
        af("compact_ver_start",       u32, 4)
        af("compact_ver_end",         u32, 4)
        af("app_name",                Type.array(Type.char(), 16), 16)
        af("app_uuid",                Type.array(Type.char(), 16), 16)
        if not is_old:
            af("srcver",              u64, 8)
        if stride > app_sz[0]:
            a.append(Type.array(u8, stride - app_sz[0]), "_pad")

        self.define_user_type("SEPApp64", Type.structure_type(a))

        # ── SEPRootserver (rootserver_info nested struct) ──────────────────────
        rs = StructureBuilder.create()
        rs.append(u64, "phys_base")
        rs.append(u64, "virt_base")
        rs.append(u64, "virt_size")
        rs.append(u64, "virt_entry")
        rs.append(u64, "stack_phys_base")
        rs.append(u64, "stack_virt_base")
        rs.append(u64, "stack_size")
        if hdr["stack_size"] != 0 or ver == 4:
            rs.append(u64, "normal_memory_size")
            rs.append(u64, "non_ar_memory_size")
            rs.append(u64, "heap_memory_size")
        if ver == 4:
            rs.append(u64, "virtual_memory_size")
            rs.append(u64, "dart_memory_size")
            rs.append(u64, "thread_count")
            rs.append(u64, "cnode_count")
        rs.append(Type.array(u8, 16), "name")
        rs.append(Type.array(u8, 16), "uuid")
        if not is_old:
            rs.append(u64, "source_version")
        rs_type = Type.structure_type(rs)
        self.define_user_type("SEPRootserver", rs_type)

        # ── Legion64BootArgs — built with insert() so BN pads unknown gaps ────
        #
        # Verified field positions for Legion64 (ver==4) in j236c:
        #   +0x00  uuid_offset
        #   +0x08  astris_uuid[16]
        #   +0x18  unknown 32 bytes (seprom_boot_args_v2 / memory_map prefix)
        #   +0x38  subversion          ┐
        #   +0x3c  legion_string[16]   │ legion_version
        #   +0x4c  sepos_boot_args_offset │
        #   +0x4e  __reserved[2]       ┘
        #   +0x50 … hdr_rel-1   unknown (rest of seprom + memory_map)
        #   hdr_rel = hdr_offset - BOOT_START   ← sepos_boot_args begins here
        #
        b     = StructureBuilder.create()
        hdr_rel = hdr_offset - BOOT_START   # sepos_boot_args base relative to struct

        # Header region
        b.insert(0x00, u64,                    "uuid_offset")
        b.insert(0x08, Type.array(u8, 16),     "astris_uuid")
        b.insert(0x38, u32,                    "subversion")
        b.insert(0x3c, Type.array(Type.char(), 16),     "legion_string")
        b.insert(0x4c, u16,                    "sepos_boot_args_offset")
        b.insert(0x4e, Type.array(u8, 2),      "_legion_reserved")

        # sepos_boot_args fields (inlined; p tracks struct-relative position)
        p = hdr_rel
        def bf(name: str, t: Type, size: int) -> None:
            nonlocal p
            b.insert(p, t, name)
            p += size

        bf("kern_uuid",                       Type.array(u8, 16), 16)
        bf("kern_heap_size",                  u64, 8)
        bf("kern_ro_start",                   u64, 8)
        bf("kern_ro_end",                     u64, 8)
        bf("app_ro_start",                    u64, 8)
        bf("app_ro_end",                      u64, 8)
        bf("end_of_payload",                  u64, 8)
        bf("required_tz0_size",               u64, 8)
        bf("required_tz1_size",               u64, 8)
        bf("required_ar_plaintext_size",      u64, 8)
        ar_min_size, = struct.unpack_from("<Q", fw, hdr_offset + 16 + 8 * 8)
        if ar_min_size != 0 or ver == 4:
            bf("required_non_ar_plaintext_size", u64, 8)
            bf("shm_base",                    u64, 8)
            bf("shm_size",                    u64, 8)
        bf("rootserver_info",  self.get_type_by_name("SEPRootserver"),
                               self.get_type_by_name("SEPRootserver").width)
        # sepos_crc32 + kern_no_ar_mem are both u32 (16 bytes of iommu size, not u8)
        bf("sepos_crc32",                     u32, 4)
        bf("kern_no_ar_mem",                  u32, 4)
        # dynamic_objects is always MAX_DYNAMIC_OBJECTS(16) × 16-byte entries = 0x100 bytes
        dyn_obj = StructureBuilder.create()
        dyn_obj.append(u32, "handle")
        dyn_obj.append(u32, "sep_offset")
        dyn_obj.append(u32, "dart_offset")
        dyn_obj.append(u32, "sep_size")
        self.define_user_type("SEPDynamicObject", Type.structure_type(dyn_obj))
        bf("dynamic_objects",
           Type.array(self.get_type_by_name("SEPDynamicObject"), 16),
           0x100)
        bf("num_apps",                        u32, 4)
        bf("num_shlibs",                      u32, 4)
        bf("app_list",
           Type.array(self.get_type_by_name("SEPApp64"), n_apps + n_shlibs),
           stride * (n_apps + n_shlibs))

        self.define_user_type("Legion64BootArgs", Type.structure_type(b))
        self.define_data_var(BOOT_START, self.get_type_by_name("Legion64BootArgs"))
        log_info(f"[SEP] applied Legion64BootArgs at {BOOT_START:#x} "
                 f"({n_apps} apps + {n_shlibs} shlibs)")

    # ── Raw segment helper ────────────────────────────────────────────────────

    def _map_raw(self, fw_offset: int, va: int, size: int,
                 section_name: str, flags: SegmentFlag) -> None:
        self.add_auto_segment(va, size, fw_offset, size, flags)
        semantics = (SectionSemantics.ReadOnlyCodeSectionSemantics
                     if flags & SegmentFlag.SegmentContainsCode
                     else SectionSemantics.DefaultSectionSemantics)
        self.add_auto_section(section_name, va, size, semantics)

    # ── Pointer fixups ────────────────────────────────────────────────────────

    def _fix_init_funcs(self, va: int, size: int, imagebase: int,
                        fw: bytes, fw_off: int) -> None:
        """Rewrite __mod_init_func / __init_offsets entries to absolute VAs.

        Original values are relative offsets (< 2^32) or tagged 64-bit
        pointers (low 32 bits = relative offset).
        """
        n = size // 8
        buf = bytearray(fw[fw_off : fw_off + size])
        for i in range(n):
            orig = struct.unpack_from("<Q", buf, i * 8)[0]
            if orig == 0:
                continue
            if orig < 0x1_0000_0000:
                new_va = imagebase + orig
            else:
                new_va = imagebase + (orig & 0xFFFFFFFF)
            struct.pack_into("<Q", buf, i * 8, new_va)
        self.write(va, bytes(buf))

    def _fix_got(self, va: int, size: int,
                 shlib_base: int, shlib_slide: int,
                 fw: bytes, fw_off: int) -> None:
        """Rewrite __auth_got / __got entries to point into the shared library.

        Formula (mirrors IDA plugin):
            target = shlib_base + (orig & 0xFFFFF) - shlib_slide
        """
        n = size // 8
        buf = bytearray(fw[fw_off : fw_off + size])
        for i in range(n):
            orig = struct.unpack_from("<Q", buf, i * 8)[0]
            if orig == 0:
                continue
            new_va = shlib_base + (orig & 0xFFFFF) - shlib_slide
            struct.pack_into("<Q", buf, i * 8, new_va)
        self.write(va, bytes(buf))

    def _fix_tagged_pointers(self, va: int, size: int, imagebase: int,
                             fw: bytes, fw_off: int,
                             binary: lief.MachO.Binary) -> None:
        """Untag ARM64e tagged pointers in __const sections.

        A tagged pointer has the form:  type[16] | tag[16] | offset[32]
        where type & 0xF000 is 0x8000 or 0x9000, tag != 0, and
        imagebase + offset falls within __text.

        Only those entries that match are rewritten; others are left alone.
        """
        try:
            text_start = int(binary.get_section("__text").virtual_address)
            text_end   = text_start + int(binary.get_section("__text").size)
        except Exception:
            return  # no __text section, nothing to do

        n = size // 8
        buf = bytearray(fw[fw_off : fw_off + size])
        changed = False
        for i in range(n):
            orig   = struct.unpack_from("<Q", buf, i * 8)[0]
            pt_type   = (orig >> 48) & 0xFFFF
            pt_tag    = (orig >> 32) & 0xFFFF
            pt_offset = orig & 0xFFFFFFFF

            if pt_tag == 0:
                continue
            if (pt_type & 0xF000) not in (0x8000, 0x9000):
                continue
            target = imagebase + pt_offset
            if not (text_start + imagebase <= target < text_end + imagebase):
                continue

            struct.pack_into("<Q", buf, i * 8, target)
            changed = True

        if changed:
            self.write(va, bytes(buf))

