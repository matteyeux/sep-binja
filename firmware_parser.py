"""
Pure struct parsing for Apple SEP firmware images.

Ported from sepsplit-rs (Rust) and used by both the CLI tool (sepsplit.py)
and the Binary Ninja view plugin (sep_view.py).
"""

import struct
import uuid as uuid_mod
from dataclasses import dataclass


SEPHDR_SIZE = 224
SEPAPP_64_SIZE = 128

MACHO_MAGIC_64 = 0xFEEDFACF

#: Build marker legion2 stamps into every image, and the two offsets it lands
#: at. Which one holds it is the only reliable discriminator between the two
#: legion header layouts, so everything that needs to tell them apart goes
#: through legion_marker_offset() rather than re-testing the bytes.
LEGION_MARKER = b"Built by legion2"
LEGION_MARKER_OFF = 0x103C  # Legion64     (iOS 16+)
LEGION_MARKER_OFF_OLD = 0x1004  # Legion64Old  (iOS 15 and below)

#: LEGION64_PAGE_SIZE. Every region legion places starts on one of these, which
#: makes it the granularity to round the header's end up to when working out
#: what follows it.
LEGION64_PAGE_SIZE = 0x4000

#: astris_uuid_t.magic, 'uuid' little-endian: what astris scans an image (or a
#: live SEP) for to recover the kernel UUID.
ASTRIS_UUID_MAGIC = 0x64697575
ASTRIS_UUID_SIZE = 0x30

#: Base that the legion header's uuid_offset is measured from. Not the image
#: base: the reset-vector array at 0x800, which the four-instruction boot stub
#: at offset 0 loads into VBAR_EL1 (`adr x2, #0x7fc` / `msr VBAR_EL1, x2`).
#: 0x800 + uuid_offset lands on astris_uuid — 0x808 → 0x1008 in every image
#: seen so far, iOS 18 and iOS 26 alike.
ASTRIS_UUID_BASE = 0x800

# Source-version major at/after which SEPApp64 gained an extra u64: a fourth
# memory size, between dart_memory_size and thread_count. Empirically: 3151
# (iOS 26.5, stride 0xa4) has no field, 3485 (iOS 27.0, stride 0xac) has it, and
# it reads 0 for every app but eispAppl_d7x. The exact Apple boundary is
# unknown; adjust if a firmware between these majors disagrees.
SEPAPP_EXTRA_MEM_SRCVER_MAJOR = 3400


@dataclass
class SepModule:
    """Describes one extracted SEP module.

    Physical offsets are relative to the start of the firmware file.
    binja_idx is the relocation-step multiplier used by the BN view plugin.
    """

    kind: str  # 'boot' | 'kernel' | 'sepos' | 'app' | 'shlib'
    name: str
    uuid: str  # hyphenated UUID string, '' for boot / raw kernel
    phys_text: int  # firmware offset for the TEXT / raw region
    size_text: int  # byte count of TEXT / raw region
    phys_data: int  # firmware offset for DATA  (0 = contiguous with TEXT)
    size_data: int  # byte count of DATA  (0 = none / contiguous)
    virt: int  # original virtual base (inside the Mach-O)
    ventry: int  # entry-point offset (from Mach-O start for Mach-O modules)
    is_macho: bool
    is_shlib: bool
    binja_idx: int  # multiply by RELOC_STEP to get the BN virtual base
    srcver: int = 0  # packed SrcVer u64; 0 when the header carries none


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
    return magic == MACHO_MAGIC_64


def legion_marker_offset(data: bytes) -> int | None:
    """Offset of the legion2 build marker, or None if the image has none.

    LEGION_MARKER_OFF for the iOS 16+ header, LEGION_MARKER_OFF_OLD for the
    iOS 15-and-below one.
    """
    for off in (LEGION_MARKER_OFF, LEGION_MARKER_OFF_OLD):
        if data[off : off + len(LEGION_MARKER)] == LEGION_MARKER:
            return off
    return None


def is_sep_firmware(data: bytes) -> bool:
    """Return True if data looks like a raw 64-bit SEP firmware image."""
    if len(data) < 0x1100:
        return False
    # IMG4 container — caller must pre-extract
    if data[:2] == bytes([0x30, 0x83]):
        return False
    # LZVN compressed, but we should never branch here it's only for 32 bit
    if data[8:16] == b"eGirBwRD":
        return False
    return legion_marker_offset(data) is not None


def find_astris_uuid(data: bytes) -> int | None:
    """File offset of the astris_uuid_t, or None if it cannot be located.

    The header does not place the struct at a fixed offset; it stores where it
    put it in uuid_offset, relative to ASTRIS_UUID_BASE. Resolve that rather
    than assume 0x1008, and only believe the answer if the magic is there.
    """
    if legion_marker_offset(data) != LEGION_MARKER_OFF:
        return None  # the old header has no uuid_offset, and no astris_uuid
    (uuid_offset,) = struct.unpack_from("<Q", data, 0x1000)
    off = ASTRIS_UUID_BASE + uuid_offset
    if off + ASTRIS_UUID_SIZE > len(data):
        return None
    (magic,) = struct.unpack_from("<I", data, off)
    return off if magic == ASTRIS_UUID_MAGIC else None


def find_off(data: bytes) -> tuple[int, int]:
    """Return (hdr_offset, ver) for the SEP data header.

    ver == 2 old 64-bit format (D20 iOS 11.0)
    ver == 3 standard 64-bit (iOS 15 and below, Legion64Old)
    ver == 4 modern 64-bit  (iSO 16+, Legion64)
    """
    marker_off = legion_marker_offset(data)
    if marker_off is None:
        raise ValueError("Unrecognised or 32-bit SEP firmware (not supported)")

    # subversion sits immediately before the marker and the SEP data header's
    # own offset immediately after it, in both layouts. The iOS 16+ header
    # differs only in what precedes subversion: uuid_offset and astris_uuid.
    (subversion,) = struct.unpack_from("<I", data, marker_off - 4)
    (structoff,) = struct.unpack_from("<H", data, marker_off + len(LEGION_MARKER))

    if marker_off == LEGION_MARKER_OFF_OLD and structoff == 0:
        # D20-era images leave it blank; the header is at a known fixed offset.
        return 0xFFFF, int(subversion)
    return int(structoff), int(subversion)


def _parse_sephdr64(data: bytes, hdr_offset: int, ver: int, is_old: bool) -> dict:
    """Parse SEPDataHDR64 at hdr_offset.

    Returns a dict of fields plus '_apps_off' (offset where SEPApp64 array begins).
    """
    p = hdr_offset

    kernel_uuid = data[p : p + 16]
    p += 16
    (_kheap,) = struct.unpack_from("<Q", data, p)
    p += 8
    (kernel_base_paddr,) = struct.unpack_from("<Q", data, p)
    p += 8
    (kernel_max_paddr,) = struct.unpack_from("<Q", data, p)
    p += 8
    (_app_base,) = struct.unpack_from("<Q", data, p)
    p += 8
    (_app_max,) = struct.unpack_from("<Q", data, p)
    p += 8
    (_paddr_max,) = struct.unpack_from("<Q", data, p)
    p += 8
    (_tz0,) = struct.unpack_from("<Q", data, p)
    p += 8
    (_tz1,) = struct.unpack_from("<Q", data, p)
    p += 8
    (ar_min_size,) = struct.unpack_from("<Q", data, p)
    p += 8

    if ar_min_size != 0 or ver == 4:
        p += 8 * 3  # non_ar_min_size, shm_base, shm_size

    (init_base_paddr,) = struct.unpack_from("<Q", data, p)
    p += 8
    (init_base_vaddr,) = struct.unpack_from("<Q", data, p)
    p += 8
    (init_vsize,) = struct.unpack_from("<Q", data, p)
    p += 8
    (init_ventry,) = struct.unpack_from("<Q", data, p)
    p += 8
    p += 8 * 2  # stack_base_paddr, stack_base_vaddr
    (stack_size,) = struct.unpack_from("<Q", data, p)
    p += 8

    if stack_size != 0 or ver == 4:
        p += 8 * 3  # mem_size, antireplay_mem_size, heap_mem_size

    if ver == 4:
        p += 4 + 4 + 8 * 3  # compact_ver_start/end, _unk1-3

    init_name = data[p : p + 16]
    p += 16
    init_uuid = data[p : p + 16]
    p += 16

    if not is_old:
        (srcver,) = struct.unpack_from("<Q", data, p)
        p += 8
    else:
        srcver = 0

    p += 4 + 1  # crc32, coredump_sup
    pad = bytes(data[p : p + 3])
    p += 3

    if pad == bytes([0x40, 0x04, 0x00]):
        p += 0x100

    (n_apps,) = struct.unpack_from("<I", data, p)
    p += 4
    (n_shlibs,) = struct.unpack_from("<I", data, p)
    p += 4

    return dict(
        kernel_uuid=kernel_uuid,
        kernel_base_paddr=kernel_base_paddr,
        kernel_max_paddr=kernel_max_paddr,
        init_base_paddr=init_base_paddr,
        init_base_vaddr=init_base_vaddr,
        init_vsize=init_vsize,
        init_ventry=init_ventry,
        init_name=init_name,
        init_uuid=init_uuid,
        srcver=srcver,
        stack_size=stack_size,
        n_apps=n_apps,
        n_shlibs=n_shlibs,
        _apps_off=p,
    )


def _parse_sepapp64(
    data: bytes, off: int, ver: int, is_old: bool, srcver_major: int = 0
) -> dict:
    """Parse one SEPApp64 entry at *off* and return a field dict."""
    p = off

    (phys_text,) = struct.unpack_from("<Q", data, p)
    p += 8
    (size_text,) = struct.unpack_from("<Q", data, p)
    p += 8
    (phys_data,) = struct.unpack_from("<Q", data, p)
    p += 8
    (size_data,) = struct.unpack_from("<Q", data, p)
    p += 8
    (virt,) = struct.unpack_from("<Q", data, p)
    p += 8
    (ventry,) = struct.unpack_from("<Q", data, p)
    p += 8
    (stack_size,) = struct.unpack_from("<Q", data, p)
    p += 8

    if not is_old:
        p += 8 * 2  # mem_size, non_antireplay_mem_size

    if stack_size != 0 or ver == 4:
        p += 8  # heap_mem_size

    if ver == 4:
        # virtual_memory_size, dart_memory_size, thread_count, cnode_count
        p += 8 * 4

    # A fourth memory size, which iOS 27 wedged in between dart_memory_size and
    # thread_count. Only the total matters here, so it is added at the end of
    # the run rather than in the middle of it; SEPApp64 in the view places it.
    if srcver_major >= SEPAPP_EXTRA_MEM_SRCVER_MAJOR:
        p += 8

    p += 4 + 4  # compact_ver_start, compact_ver_end

    app_name = data[p : p + 16]
    p += 16
    app_uuid = data[p : p + 16]
    p += 16

    if not is_old:
        (srcver,) = struct.unpack_from("<Q", data, p)
        p += 8
    else:
        srcver = 0

    return dict(
        phys_text=phys_text,
        size_text=size_text,
        phys_data=phys_data,
        size_data=size_data,
        virt=virt,
        ventry=ventry,
        app_name=app_name,
        app_uuid=app_uuid,
        srcver=srcver,
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
    if srcver_major >= SEPAPP_EXTRA_MEM_SRCVER_MAJOR:
        size += 8  # the extra memory size, new in iOS 27
    return size


@dataclass
class LegionLayout:
    """Where everything is in a ver >= 3 image, resolved once.

    The walk that produces this — find_off, the SEPDataHDR64 fields, the
    n_apps == 0 fixup, the SEPApp64 stride — used to be repeated by every
    caller that needed any part of it, and each copy had to stay in step with
    the others.
    """

    marker_off: int  # where the legion2 marker was found
    hdr_offset: int  # SEPDataHDR64 / sepos_boot_args
    ver: int  # legion subversion
    is_old: bool  # D20-era header with no srcver and a short SEPApp64
    hdr: dict  # _parse_sephdr64 output
    srcver_major: int
    apps_off: int  # first SEPApp64
    n_apps: int
    n_shlibs: int
    stride: int  # bytes between SEPApp64 entries

    @property
    def is_legion64(self) -> bool:
        """True for the iOS 16+ header, which has uuid_offset and astris_uuid."""
        return self.marker_off == LEGION_MARKER_OFF

    @property
    def apps_end(self) -> int:
        """First byte past the SEPApp64 array — the end of the header proper."""
        return self.apps_off + self.stride * (self.n_apps + self.n_shlibs)


def parse_legion_layout(data: bytes) -> LegionLayout | None:
    """Resolve a ver >= 3 image's header layout, or None for anything older."""
    marker_off = legion_marker_offset(data)
    if marker_off is None:
        raise ValueError("Unrecognised or 32-bit SEP firmware (not supported)")

    hdr_offset, ver = find_off(data)
    if ver < 3:
        return None

    is_old = hdr_offset == 0xFFFF
    if is_old:
        hdr_offset = 0x10F8

    hdr = _parse_sephdr64(data, hdr_offset, ver, is_old)
    apps_off = hdr["_apps_off"]
    n_apps = hdr["n_apps"]
    n_shlibs = hdr["n_shlibs"]

    if n_apps == 0:
        # 0x100 of padding sits between the header and the app array in some
        # builds, and the real counts sit past it.
        apps_off += 0x100
        (n_apps,) = struct.unpack_from("<I", data, hdr_offset + 0x210)
        (n_shlibs,) = struct.unpack_from("<I", data, hdr_offset + 0x214)

    srcver_major = get_srcver_major(hdr["srcver"])
    return LegionLayout(
        marker_off=marker_off,
        hdr_offset=hdr_offset,
        ver=ver,
        is_old=is_old,
        hdr=hdr,
        srcver_major=srcver_major,
        apps_off=apps_off,
        n_apps=n_apps,
        n_shlibs=n_shlibs,
        stride=_sepapp_stride(srcver_major, is_old),
    )


def kernel_phys_base(data: bytes, layout: LegionLayout) -> int:
    """Firmware offset the kernel image starts at.

    kern_ro_start — what kernel_base_paddr parses as — was that offset up to and
    including iOS 26, where it reads 0x4000. iOS 27 widened the kernel's
    read-only region to take in the boot page and the legion header, so there
    the field reads 0 while the image itself still starts at 0x4000. Taken at
    face value that maps the kernel over the header at address 0, and since the
    view re-applies the boot-args struct there afterwards, the kernel's code
    disappears rather than failing outright.

    So believe the field only when it points past the header, and otherwise take
    the first legion page after the header with anything in it.
    """
    kbase = layout.hdr["kernel_base_paddr"]
    page_mask = LEGION64_PAGE_SIZE - 1
    first_page = (layout.apps_end + page_mask) & ~page_mask
    if kbase >= first_page:
        return kbase
    limit = min(layout.hdr["kernel_max_paddr"], len(data))
    for off in range(first_page, limit, LEGION64_PAGE_SIZE):
        if any(data[off : off + LEGION64_PAGE_SIZE]):
            return off
    return first_page


def calc_size_raw(data: bytes) -> int:
    """Compute Mach-O byte length by scanning segment file offsets (no LIEF)."""
    if len(data) < 1024:
        return 0
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MACHO_MAGIC_64:
        return 0
    is64 = magic == MACHO_MAGIC_64
    ncmds = struct.unpack_from("<I", data, 16)[0]
    p = 28 + (4 if is64 else 0)
    tsize = 0
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", data, p)
        if cmd == 0x01:  # LC_SEGMENT
            fo = struct.unpack_from("<I", data, p + 32)[0]
            fs = struct.unpack_from("<I", data, p + 36)[0]
            tsize = max(tsize, fo + fs)
        elif cmd == 0x19:  # LC_SEGMENT_64
            fo = struct.unpack_from("<Q", data, p + 40)[0]
            fs = struct.unpack_from("<Q", data, p + 48)[0]
            tsize = max(tsize, fo + fs)
        p += csz
    return tsize


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

    if ver == 2:
        return _extract_ver2(data, 0x10F8 if hdr_offset == 0xFFFF else hdr_offset)

    layout = parse_legion_layout(data)
    if layout is None:  # ver >= 3 always resolves; keeps the reads below honest
        raise ValueError(f"unsupported SEP header version {ver}")
    is_old = layout.is_old
    hdr = layout.hdr
    apps_off = layout.apps_off
    n_apps = layout.n_apps
    n_shlibs = layout.n_shlibs
    srcver_major = layout.srcver_major
    stride = layout.stride

    kbase = kernel_phys_base(data, layout)
    kmax = hdr["kernel_max_paddr"]

    # Compute kernel size
    ksize = calc_size_raw(data[kbase:])
    if ksize == 0:
        ksize = kmax - kbase

    modules: list[SepModule] = []

    # sepboot
    modules.append(
        SepModule(
            kind="boot",
            name="SEPBOOT",
            uuid="",
            phys_text=0,
            size_text=kbase,
            phys_data=0,
            size_data=0,
            virt=0,
            ventry=0,
            is_macho=False,
            is_shlib=False,
            binja_idx=0,
        )
    )

    # kernel
    modules.append(
        SepModule(
            kind="kernel",
            name="kernel",
            uuid=fmt_uuid(hdr["kernel_uuid"]),
            phys_text=kbase,
            size_text=ksize,
            phys_data=0,
            size_data=0,
            virt=kbase,
            ventry=kbase,
            is_macho=is_macho(data, kbase),
            is_shlib=False,
            binja_idx=0,  # shares the low address space with boot
            srcver=hdr["srcver"],
        )
    )

    # sepos
    ibase = hdr["init_base_paddr"]
    isz = calc_size_raw(data[ibase:])
    if isz == 0:
        isz = hdr["init_vsize"]
    modules.append(
        SepModule(
            kind="sepos",
            name=c_str(hdr["init_name"]) or "SEPOS",
            uuid=fmt_uuid(hdr["init_uuid"]),
            phys_text=ibase,
            size_text=isz,
            phys_data=0,
            size_data=0,  # DATA is contiguous for SEPOS
            virt=hdr["init_base_vaddr"],
            ventry=hdr["init_ventry"],
            is_macho=is_macho(data, ibase),
            is_shlib=False,
            binja_idx=1,
            srcver=hdr["srcver"],
        )
    )

    # apps
    off = apps_off
    for i in range(n_apps):
        app = _parse_sepapp64(data, off, ver, is_old, srcver_major)
        modules.append(
            SepModule(
                kind="app",
                name=c_str(app["app_name"]),
                uuid=fmt_uuid(app["app_uuid"]),
                phys_text=app["phys_text"],
                size_text=app["size_text"],
                phys_data=app["phys_data"],
                size_data=app["size_data"],
                virt=app["virt"],
                ventry=app["ventry"],
                is_macho=is_macho(data, app["phys_text"]),
                is_shlib=False,
                binja_idx=i + 2,
                srcver=app["srcver"],
            )
        )
        off += stride

    # shlibs
    for i in range(n_shlibs):
        app = _parse_sepapp64(data, off, ver, is_old, srcver_major)
        modules.append(
            SepModule(
                kind="shlib",
                name=c_str(app["app_name"]),
                uuid=fmt_uuid(app["app_uuid"]),
                phys_text=app["phys_text"],
                size_text=app["size_text"],
                phys_data=app["phys_data"],
                size_data=app["size_data"],
                virt=app["virt"],
                ventry=app["ventry"],
                is_macho=is_macho(data, app["phys_text"]),
                is_shlib=True,
                binja_idx=n_apps + 2 + i,
                srcver=app["srcver"],
            )
        )
        off += stride

    return modules


def _extract_ver2(data: bytes, hdr_offset: int) -> list[SepModule]:
    """Handle the old iOS 11.0 D20 64-bit SEP format (subversion 2)."""
    p = hdr_offset
    _kernel_uuid = data[p : p + 16]
    p += 16
    (kbase,) = struct.unpack_from("<Q", data, p)
    p += 8
    (kmax,) = struct.unpack_from("<Q", data, p)
    p += 8
    p += 8 * 3  # unk1–3
    (ibase,) = struct.unpack_from("<Q", data, p)
    p += 8
    (ivaddr,) = struct.unpack_from("<Q", data, p)
    p += 8
    (ivsz,) = struct.unpack_from("<Q", data, p)
    p += 8
    (ive,) = struct.unpack_from("<Q", data, p)
    p += 8
    p += 8 * 3  # stack fields
    iname = data[p : p + 16]
    p += 16
    iuuid = data[p : p + 16]
    p += 16
    p += 4 + 1 + 3  # crc32, cdump, pad
    (n_apps,) = struct.unpack_from("<I", data, p)
    p += 4
    (n_shlibs,) = struct.unpack_from("<I", data, p)
    p += 4

    modules: list[SepModule] = []

    modules.append(
        SepModule(
            kind="boot",
            name="BOOTER",
            uuid="",
            phys_text=0,
            size_text=0x1000,
            phys_data=0,
            size_data=0,
            virt=0,
            ventry=0,
            is_macho=False,
            is_shlib=False,
            binja_idx=0,
        )
    )

    ksize = calc_size_raw(data[0x4000:])
    modules.append(
        SepModule(
            kind="kernel",
            name="kernel",
            uuid="",
            phys_text=0x4000,
            size_text=ksize,
            phys_data=0,
            size_data=0,
            virt=0x4000,
            ventry=0x4000,
            is_macho=is_macho(data, 0x4000),
            is_shlib=False,
            binja_idx=0,
        )
    )

    modules.append(
        SepModule(
            kind="sepos",
            name=c_str(iname) or "SEPOS",
            uuid=fmt_uuid(iuuid),
            phys_text=ibase,
            size_text=ivsz,
            phys_data=0,
            size_data=0,
            virt=ivaddr,
            ventry=ive,
            is_macho=is_macho(data, ibase),
            is_shlib=False,
            binja_idx=1,
        )
    )

    off = 0x1198
    app_stride = 0x58
    for i in range(n_apps + n_shlibs):
        q = off
        (pt,) = struct.unpack_from("<Q", data, q)
        q += 8
        (virt,) = struct.unpack_from("<Q", data, q)
        q += 8
        (st,) = struct.unpack_from("<Q", data, q)
        q += 8
        (ve,) = struct.unpack_from("<Q", data, q)
        q += 8
        q += 8 * 2  # stack_size, compact_ver
        aname = data[q : q + 16]
        auuid = data[q + 16 : q + 32]
        modules.append(
            SepModule(
                kind="shlib" if i >= n_apps else "app",
                name=c_str(aname),
                uuid=fmt_uuid(auuid),
                phys_text=pt,
                size_text=st,
                phys_data=0,
                size_data=0,
                virt=virt,
                ventry=ve,
                is_macho=is_macho(data, pt),
                is_shlib=(i >= n_apps),
                binja_idx=i + 2,
            )
        )
        off += app_stride

    return modules
