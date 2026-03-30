"""
Binary Ninja BinaryView plugin for Apple SEP firmware.
"""

import struct
import traceback

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
    MachOBinary,
    compute_shared_cache_slide,
    find_lc_sep_slide,
    fw_offset_for,
    get_entry_point_va,
    iter_segments,
    parse_macho,
)

# 4 GiB gap between every module
RELOC_STEP: int = 0x100000000

_LC_CMD_TYPES: dict[int, str] = {
    0x02: "symtab_command",  # LC_SYMTAB
    0x0B: "dysymtab_command",  # LC_DYSYMTAB
    0x0C: "dylib_command",  # LC_LOAD_DYLIB
    0x0D: "dylib_command",  # LC_ID_DYLIB
    0x0E: "dylinker_command",  # LC_LOAD_DYLINKER
    0x0F: "dylinker_command",  # LC_ID_DYLINKER
    0x19: "segment_command_64",  # LC_SEGMENT_64
    0x1B: "uuid_command",  # LC_UUID
    0x1D: "linkedit_data_command",  # LC_CODE_SIGNATURE
    0x1E: "linkedit_data_command",  # LC_SEGMENT_SPLIT_INFO
    0x22: "dyld_info_command",  # LC_DYLD_INFO
    0x24: "linkedit_data_command",  # LC_DYLD_CHAINED_FIXUPS (older)
    0x26: "linkedit_data_command",  # LC_FUNCTION_STARTS
    0x29: "linkedit_data_command",  # LC_DATA_IN_CODE
    0x2A: "source_version_command",  # LC_SOURCE_VERSION
    0x32: "build_version_command",  # LC_BUILD_VERSION
    0x80000022: "dyld_info_command",  # LC_DYLD_INFO_ONLY
    0x80000028: "entry_point_command",  # LC_MAIN
    0x80000033: "linkedit_data_command",  # LC_DYLD_EXPORTS_TRIE
    0x80000034: "linkedit_data_command",  # LC_DYLD_CHAINED_FIXUPS
    0x08000001: "sep_shlib_chain_command",  # LC_SEP_SHLIB_CHAIN
    0x08000002: "sep_chained_fixup_command",  # LC_SEP_CHAINED_FIXUPS
    0x08000003: "sep_prebind_slide_command",  # LC_SEP_PREBIND_SLIDE
}


_CODE_SECTION_NAMES = frozenset(
    {
        "__text",
        "__auth_stubs",
        "__stubs",
        "__stub_helper",
        "__textcoal_nt",
        "__symbol_stub",
    }
)


def _seg_flags(seg) -> SegmentFlag:
    flags = SegmentFlag.SegmentReadable
    prot = seg.init_protection
    if prot & 0x2:
        flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
    if prot & 0x4:
        flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
    if not (prot & 0x2) and not (prot & 0x4):
        flags |= SegmentFlag.SegmentContainsData
    return flags


def _section_semantics(sect) -> SectionSemantics:
    if sect.is_zerofill:
        return SectionSemantics.ReadWriteDataSectionSemantics
    if sect.name in _CODE_SECTION_NAMES:
        return SectionSemantics.ReadOnlyCodeSectionSemantics
    seg_name = sect.segment_name
    if seg_name in (
        "__DATA",
        "__DATA_DIRTY",
        "__SEPOS",
        "STACK",
        "__BOOTARGS",
        "__LEGION",
    ):
        return SectionSemantics.ReadWriteDataSectionSemantics
    if seg_name == "__DATA_CONST":
        return SectionSemantics.ReadOnlyDataSectionSemantics
    if seg_name == "__TEXT":
        return SectionSemantics.ReadOnlyDataSectionSemantics
    return SectionSemantics.DefaultSectionSemantics


class SEPFirmwareView(BinaryView):
    name = "SEP Firmware"
    long_name = "Apple SEP Firmware"

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        raw = data.read(0, 0x1200)
        return is_sep_firmware(bytes(raw))

    def __init__(self, data: BinaryView) -> None:
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.arch = Architecture["aarch64"]
        self.platform = self.arch.standalone_platform
        self.data = data

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
        self.arch = Architecture["aarch64"]
        self.platform = self.arch.standalone_platform

        fw_size = self.data.length
        fw = bytes(self.parent_view.read(0, fw_size))

        log_info("[SEP] parsing firmware…")
        modules = extract_all_modules(fw)
        log_info(f"[SEP] found {len(modules)} modules")

        # Locate the shared library first so we have its base address and
        # slide ready before processing the apps that reference it
        shlib_base = 0
        shlib_slide = 0
        for mod in modules:
            if mod.is_shlib and mod.is_macho:
                shlib_base = RELOC_STEP * mod.binja_idx
                lc_off = find_lc_sep_slide(
                    fw[mod.phys_text : mod.phys_text + mod.size_text]
                )
                if lc_off is not None:
                    shlib_slide = compute_shared_cache_slide(lc_off, mod.virt or 0x8000)
                    log_info(
                        f"[SEP] shared-lib slide = {shlib_slide:#x}, base = {shlib_base:#x}"
                    )
                break

        self._define_macho_header_types()

        for mod in modules:
            log_info(f"[SEP] loading {mod.kind:6s}  {mod.name}")
            self._load_module(fw, mod, shlib_base, shlib_slide)

        try:
            self._define_firmware_types(fw)
        except Exception:
            log_warn(
                f"[SEP] could not annotate firmware types:\n{traceback.format_exc()}"
            )

        return True

    def _load_module(
        self, fw: bytes, mod: SepModule, shlib_base: int, shlib_slide: int
    ) -> None:
        """Per-module loader."""
        module_base = RELOC_STEP * mod.binja_idx

        # Boot stub and raw kernel both live in the low address range with
        # their virtual address equal to their firmware physical offset.
        if mod.kind == "boot":
            self._map_raw(
                fw_offset=0,
                va=0,
                size=mod.size_text,
                section_name="SEPBOOT",
                flags=(
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentExecutable
                    | SegmentFlag.SegmentContainsCode
                ),
            )
            self.add_entry_point(0)
            return

        if not mod.is_macho:
            # Raw kernel (AArch64 reset vector code, no Mach-O wrapper)
            # SEPFW kernel is not a mach-o anymore
            va = mod.phys_text
            self._map_raw(
                fw_offset=mod.phys_text,
                va=va,
                size=mod.size_text,
                section_name=mod.name,
                flags=(
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentExecutable
                    | SegmentFlag.SegmentContainsCode
                ),
            )
            self.add_entry_point(va)
            return

        # Parse the Mach-O (TEXT region only; DATA comes from phys_data)
        raw_text = fw[mod.phys_text : mod.phys_text + mod.size_text]
        binary = parse_macho(raw_text)
        if binary is None:
            log_warn(f"[SEP] could not parse Mach-O for '{mod.name}'; mapping raw")
            self._map_raw(
                fw_offset=mod.phys_text,
                va=module_base,
                size=mod.size_text,
                section_name=mod.name,
                flags=(
                    SegmentFlag.SegmentReadable
                    | SegmentFlag.SegmentExecutable
                    | SegmentFlag.SegmentContainsCode
                ),
            )
            return

        self._load_macho(fw, mod, binary, module_base, shlib_base, shlib_slide)

    def _load_macho(
        self,
        fw: bytes,
        mod: SepModule,
        binary: MachOBinary,
        module_base: int,
        shlib_base: int,
        shlib_slide: int,
    ) -> None:
        imagebase = binary.imagebase
        hdr_va_start = module_base + imagebase
        all_offsets = [
            s.offset for seg in binary.segments for s in seg.sections if s.offset > 0
        ]
        hdr_size = min(all_offsets) if all_offsets else 0x100
        self.add_auto_segment(
            hdr_va_start,
            hdr_size,
            mod.phys_text,
            hdr_size,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData,
        )
        self.add_auto_section(
            f"{mod.name}:HEADER",
            hdr_va_start,
            hdr_size,
            SectionSemantics.ReadOnlyDataSectionSemantics,
        )

        mach_hdr_type = self.get_type_by_name("mach_header_64")
        if mach_hdr_type is not None:
            self.define_data_var(hdr_va_start, mach_hdr_type, f"{mod.name}_mach_header")

        raw_hdr = fw[mod.phys_text : mod.phys_text + hdr_size]
        self._apply_macho_load_commands(hdr_va_start, raw_hdr)

        text_start_va, text_end_va = None, None

        for seg in binary.segments:
            for sect in seg.sections:
                if sect.name == "__text":
                    text_start_va = sect.virtual_address
                    text_end_va = sect.virtual_address + sect.size
                    break

        for seg in iter_segments(binary):
            seg_va = module_base + seg.virtual_address
            seg_vsz = seg.virtual_size or seg.file_size
            seg_fw_off = fw_offset_for(
                seg.file_offset, mod.phys_text, mod.phys_data, mod.size_text
            )
            seg_flags = _seg_flags(seg)

            self.add_auto_segment(
                seg_va,
                seg_vsz,
                seg_fw_off,
                seg.file_size,
                seg_flags,
            )
            for sect in seg.sections:
                sect_va = module_base + sect.virtual_address
                sect_size = sect.size
                if sect_size == 0:
                    continue

                sect_fw_off = fw_offset_for(
                    sect.offset, mod.phys_text, mod.phys_data, mod.size_text
                )
                semantics = _section_semantics(sect)
                sect_name = f"{mod.name}:{sect.segment_name}:{sect.name}"

                self.add_auto_section(sect_name, sect_va, sect_size, semantics)

                if sect.name in ("__mod_init_func", "__init_offsets", "__auth_ptr"):
                    self._fix_init_funcs(
                        sect_va, sect_size, module_base + imagebase, fw, sect_fw_off
                    )

                if sect.name in ("__auth_got", "__got") and shlib_base:
                    self._fix_got(
                        sect_va, sect_size, shlib_base, shlib_slide, fw, sect_fw_off
                    )

                if sect.name == "__const" and text_start_va is not None:
                    self._fix_tagged_pointers(
                        sect_va,
                        sect_size,
                        module_base + imagebase,
                        fw,
                        sect_fw_off,
                        module_base + imagebase + text_start_va,
                        module_base + imagebase + text_end_va,
                    )

        entry_va = get_entry_point_va(binary, module_base)
        if entry_va is not None:
            self.add_entry_point(entry_va)
            self.define_auto_symbol(
                Symbol(SymbolType.FunctionSymbol, entry_va, f"{mod.name}_start")
            )

        for sym_name, sym_value in binary.symbols:
            sym_va = module_base + sym_value
            if sym_va == module_base:
                continue
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, sym_va, sym_name))

    def _define_macho_header_types(self) -> None:
        """Define mach_header_64 and all common Mach-O load command types."""
        u8 = Type.int(1, False)
        u32 = Type.int(4, False)
        i32 = Type.int(4, True)
        u64 = Type.int(8, False)

        def _s(*fields: tuple) -> Type:
            """Build a packed structure type from (type, name) pairs."""
            b = StructureBuilder.create()
            b.packed = True
            for t, name in fields:
                b.append(t, name)
            return Type.structure_type(b)

        char16 = Type.array(Type.char(), 16)

        self.define_user_type(
            "mach_header_64",
            _s(
                (u32, "magic"),
                (i32, "cputype"),
                (i32, "cpusubtype"),
                (u32, "filetype"),
                (u32, "ncmds"),
                (u32, "sizeofcmds"),
                (u32, "flags"),
                (u32, "reserved"),
            ),
        )

        self.define_user_type(
            "load_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
            ),
        )

        self.define_user_type(
            "segment_command_64",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (char16, "segname"),
                (u64, "vmaddr"),
                (u64, "vmsize"),
                (u64, "fileoff"),
                (u64, "filesize"),
                (i32, "maxprot"),
                (i32, "initprot"),
                (u32, "nsects"),
                (u32, "flags"),
            ),
        )

        self.define_user_type(
            "section_64",
            _s(
                (char16, "sectname"),
                (char16, "segname"),
                (u64, "addr"),
                (u64, "size"),
                (u32, "offset"),
                (u32, "align"),
                (u32, "reloff"),
                (u32, "nreloc"),
                (u32, "flags"),
                (u32, "reserved1"),
                (u32, "reserved2"),
                (u32, "reserved3"),
            ),
        )

        self.define_user_type(
            "symtab_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "symoff"),
                (u32, "nsyms"),
                (u32, "stroff"),
                (u32, "strsize"),
            ),
        )

        self.define_user_type(
            "dysymtab_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "ilocalsym"),
                (u32, "nlocalsym"),
                (u32, "iextdefsym"),
                (u32, "nextdefsym"),
                (u32, "iundefsym"),
                (u32, "nundefsym"),
                (u32, "tocoff"),
                (u32, "ntoc"),
                (u32, "modtaboff"),
                (u32, "nmodtab"),
                (u32, "extrefsymoff"),
                (u32, "nextrefsyms"),
                (u32, "indirectsymoff"),
                (u32, "nindirectsyms"),
                (u32, "extreloff"),
                (u32, "nextrel"),
                (u32, "locreloff"),
                (u32, "nlocrel"),
            ),
        )

        # dylib_command fixed header, the library name string follows at
        # the byte offset stored in the `name` lc_str field
        self.define_user_type(
            "dylib_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "name"),
                (u32, "timestamp"),
                (u32, "current_version"),
                (u32, "compatibility_version"),
            ),
        )

        self.define_user_type(
            "dylinker_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "name"),
            ),
        )

        self.define_user_type(
            "uuid_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (Type.array(u8, 16), "uuid"),
            ),
        )

        self.define_user_type(
            "entry_point_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u64, "entryoff"),
                (u64, "stacksize"),
            ),
        )

        self.define_user_type(
            "linkedit_data_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "dataoff"),
                (u32, "datasize"),
            ),
        )

        self.define_user_type(
            "source_version_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u64, "version"),
            ),
        )

        self.define_user_type(
            "build_version_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "platform"),
                (u32, "minos"),
                (u32, "sdk"),
                (u32, "ntools"),
            ),
        )

        self.define_user_type(
            "build_tool_version",
            _s(
                (u32, "tool"),
                (u32, "version"),
            ),
        )

        self.define_user_type(
            "dyld_info_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "rebase_off"),
                (u32, "rebase_size"),
                (u32, "bind_off"),
                (u32, "bind_size"),
                (u32, "weak_bind_off"),
                (u32, "weak_bind_size"),
                (u32, "lazy_bind_off"),
                (u32, "lazy_bind_size"),
                (u32, "export_off"),
                (u32, "export_size"),
            ),
        )

        # SEP-specific load commands
        self.define_user_type(
            "sep_shlib_chain_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (i32, "offset"),
                (u32, "flags"),
            ),
        )

        self.define_user_type(
            "sep_chained_fixup_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (u32, "flags"),
            ),
        )

        self.define_user_type(
            "sep_prebind_slide_command",
            _s(
                (u32, "cmd"),
                (u32, "cmdsize"),
                (i32, "slide"),
                (u32, "flags"),
            ),
        )

    def _apply_macho_load_commands(self, hdr_va_start: int, raw_hdr: bytes) -> None:
        """Walk load commands in raw_hdr and apply struct annotations in the view."""
        if len(raw_hdr) < 32:
            return
        magic = struct.unpack_from("<I", raw_hdr, 0)[0]
        is64 = magic == 0xFEEDFACF
        lc_start = 32 if is64 else 28
        ncmds = struct.unpack_from("<I", raw_hdr, 16)[0]

        sect64_type = self.get_type_by_name("section_64")
        p = lc_start
        for _ in range(ncmds):
            if p + 8 > len(raw_hdr):
                break
            cmd, csz = struct.unpack_from("<II", raw_hdr, p)
            if csz < 8:
                break

            type_name = _LC_CMD_TYPES.get(cmd, "load_command")
            lc_type = self.get_type_by_name(type_name)
            if lc_type is not None:
                self.define_data_var(hdr_va_start + p, lc_type)

            # Annotate each section_64 that follows a LC_SEGMENT_64
            if cmd == 0x19 and sect64_type is not None and p + 72 <= len(raw_hdr):
                nsects = struct.unpack_from("<I", raw_hdr, p + 64)[0]
                for i in range(nsects):
                    sect_off = p + 72 + i * 80
                    if sect_off + 80 > len(raw_hdr):
                        break
                    self.define_data_var(hdr_va_start + sect_off, sect64_type)

            # Annotate build_tool_version entries that trail build_version_command
            if cmd == 0x32 and p + 24 <= len(raw_hdr):
                ntools = struct.unpack_from("<I", raw_hdr, p + 20)[0]
                tool_type = self.get_type_by_name("build_tool_version")
                if tool_type is not None:
                    for i in range(ntools):
                        tool_off = p + 24 + i * 8
                        if tool_off + 8 > len(raw_hdr):
                            break
                        self.define_data_var(hdr_va_start + tool_off, tool_type)

            # Annotate the name string that trails dylib_command / dylinker_command
            if cmd in (0x0C, 0x0D, 0x0E, 0x0F) and p + 12 <= len(raw_hdr):
                name_off = struct.unpack_from("<I", raw_hdr, p + 8)[0]
                str_size = csz - name_off
                if 0 < str_size <= csz and name_off + str_size <= len(raw_hdr) - p:
                    self.define_data_var(
                        hdr_va_start + p + name_off,
                        Type.array(Type.char(), str_size),
                    )

            p += csz

    def _define_firmware_types(self, fw: bytes) -> None:
        """Define SEPFW bootargs, SEPRootserver and SEPApp64 types and apply them.

        Legion64BootArgs is applied at 0x1000 (the hardware header base).
        SEPApp64 instances are applied at apps_off, apps_off+stride, …
        """
        hdr_offset, ver = find_off(fw)
        if ver < 3:
            return  # ver-2 layout not worth annotating

        is_old = hdr_offset == 0xFFFF
        if is_old:
            hdr_offset = 0x10F8

        # Legion64 header always starts at 0x1000 before it's boot insts and reset vector
        BOOT_START: int = 0x1000

        hdr = _parse_sephdr64(fw, hdr_offset, ver, is_old)
        srcver_major = get_srcver_major(hdr["srcver"])
        apps_off = hdr["_apps_off"]
        n_apps = hdr["n_apps"]
        n_shlibs = hdr["n_shlibs"]

        if n_apps == 0:
            apps_off += 0x100
            n_apps = struct.unpack_from("<I", fw, hdr_offset + 0x210)[0]
            n_shlibs = struct.unpack_from("<I", fw, hdr_offset + 0x214)[0]

        stride = _sepapp_stride(srcver_major, is_old)

        u8 = Type.int(1, False)
        u16 = Type.int(2, False)
        u32 = Type.int(4, False)
        u64 = Type.int(8, False)

        # ── SEPApp64 / _boot_file_descriptor64 ────────────────────────────────
        a = StructureBuilder.create()
        a.packed = True
        app_sz = [0]

        def af(name: str, t: Type, size: int) -> None:
            a.append(t, name)
            app_sz[0] += size

        af("phys_text", u64, 8)
        af("size_text", u64, 8)
        af("phys_data", u64, 8)
        af("size_data", u64, 8)
        af("virt", u64, 8)
        af("ventry", u64, 8)
        af("stack_size", u64, 8)
        if not is_old:
            af("mem_size", u64, 8)
            af("non_ar_mem_size", u64, 8)
        if ver == 4:
            af("heap_mem_size", u64, 8)
            af("_unk1", u64, 8)
            af("_unk2", u64, 8)
            af("_unk3", u64, 8)
            af("_unk4", u64, 8)
        af("compact_ver_start", u32, 4)
        af("compact_ver_end", u32, 4)
        af("app_name", Type.array(Type.char(), 16), 16)
        af("app_uuid", Type.array(Type.char(), 16), 16)
        if not is_old:
            af("srcver", u64, 8)
        if stride > app_sz[0]:
            a.append(Type.array(u8, stride - app_sz[0]), "_pad")

        self.define_user_type("SEPApp64", Type.structure_type(a))

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
        # ~merci le Claude
        b = StructureBuilder.create()
        hdr_rel = hdr_offset - BOOT_START

        # header
        b.insert(0x00, u64, "uuid_offset")
        b.insert(0x08, Type.array(u8, 16), "astris_uuid")
        b.insert(0x38, u32, "subversion")
        b.insert(0x3C, Type.array(Type.char(), 16), "legion_string")
        b.insert(0x4C, u16, "sepos_boot_args_offset")
        b.insert(0x4E, Type.array(u8, 2), "_legion_reserved")

        # sepos_boot_args
        p = hdr_rel

        def bf(name: str, t: Type, size: int) -> None:
            nonlocal p
            b.insert(p, t, name)
            p += size

        bf("kern_uuid", Type.array(u8, 16), 16)
        bf("kern_heap_size", u64, 8)
        bf("kern_ro_start", u64, 8)
        bf("kern_ro_end", u64, 8)
        bf("app_ro_start", u64, 8)
        bf("app_ro_end", u64, 8)
        bf("end_of_payload", u64, 8)
        bf("required_tz0_size", u64, 8)
        bf("required_tz1_size", u64, 8)
        bf("required_ar_plaintext_size", u64, 8)
        (ar_min_size,) = struct.unpack_from("<Q", fw, hdr_offset + 16 + 8 * 8)
        if ar_min_size != 0 or ver == 4:
            bf("required_non_ar_plaintext_size", u64, 8)
            bf("shm_base", u64, 8)
            bf("shm_size", u64, 8)
        bf(
            "rootserver_info",
            self.get_type_by_name("SEPRootserver"),
            self.get_type_by_name("SEPRootserver").width,
        )

        bf("sepos_crc32", u32, 4)
        bf("kern_no_ar_mem", u32, 4)

        dyn_obj = StructureBuilder.create()
        dyn_obj.append(u32, "handle")
        dyn_obj.append(u32, "sep_offset")
        dyn_obj.append(u32, "dart_offset")
        dyn_obj.append(u32, "sep_size")
        self.define_user_type("SEPDynamicObject", Type.structure_type(dyn_obj))
        bf(
            "dynamic_objects",
            Type.array(self.get_type_by_name("SEPDynamicObject"), 16),
            0x100,
        )
        bf("num_apps", u32, 4)
        bf("num_shlibs", u32, 4)
        bf(
            "app_list",
            Type.array(self.get_type_by_name("SEPApp64"), n_apps + n_shlibs),
            stride * (n_apps + n_shlibs),
        )

        self.define_user_type("Legion64BootArgs", Type.structure_type(b))
        self.define_user_data_var(BOOT_START, self.get_type_by_name("Legion64BootArgs"))
        log_info(
            f"[SEP] applied Legion64BootArgs at {BOOT_START:#x} "
            f"({n_apps} apps + {n_shlibs} shlibs)"
        )

    def _map_raw(
        self, fw_offset: int, va: int, size: int, section_name: str, flags: SegmentFlag
    ) -> None:
        self.add_auto_segment(va, size, fw_offset, size, flags)
        semantics = (
            SectionSemantics.ReadOnlyCodeSectionSemantics
            if flags & SegmentFlag.SegmentContainsCode
            else SectionSemantics.DefaultSectionSemantics
        )
        self.add_auto_section(section_name, va, size, semantics)

    def _fix_init_funcs(
        self, va: int, size: int, imagebase: int, fw: bytes, fw_off: int
    ) -> None:
        """Rewrite __mod_init_func / __init_offsets entries to absolute VA.

        Original values are relative offsets (< 2^32) or tagged 64-bit pointers (low 32 bits = relative offset).
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

    def _fix_got(
        self,
        va: int,
        size: int,
        shlib_base: int,
        shlib_slide: int,
        fw: bytes,
        fw_off: int,
    ) -> None:
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

    def _fix_tagged_pointers(
        self,
        va: int,
        size: int,
        imagebase: int,
        fw: bytes,
        fw_off: int,
        text_start_va: int,
        text_end_va: int,
    ) -> None:
        """Untag ARM64e tagged pointers in __const sections.

        A tagged pointer has the form: type[16] | tag[16] | offset[32]
        where type & 0xF000 is 0x8000 or 0x9000, tag != 0, and
        imagebase + offset falls within __text.

        Only those entries that match are rewritten; others are left alone.
        """
        n = size // 8
        buf = bytearray(fw[fw_off : fw_off + size])
        changed = False
        for i in range(n):
            orig = struct.unpack_from("<Q", buf, i * 8)[0]
            pt_type = (orig >> 48) & 0xFFFF
            pt_tag = (orig >> 32) & 0xFFFF
            pt_offset = orig & 0xFFFFFFFF

            if pt_tag == 0:
                continue
            if (pt_type & 0xF000) not in (0x8000, 0x9000):
                continue
            target = imagebase + pt_offset
            if not (text_start_va <= target < text_end_va):
                continue

            struct.pack_into("<Q", buf, i * 8, target)
            changed = True

        if changed:
            self.write(va, bytes(buf))
