#!/usr/bin/env python3
"""
sepsplit.py — split an Apple SEP firmware image into its individual modules.

A pure-Python port of sepsplit-rs (the bundled Rust tool). It reuses the
struct parsing in firmware_parser.py and reimplements the Mach-O fix-ups
(LINKEDIT relocation + DATA segment restoration) so each dumped module is a
standalone, loadable file.

Usage:
    python3 sepsplit.py <sep-firmware.bin> [output-dir]

The firmware must already be decrypted and extracted (no IMG4 wrapper, no
LZVN compression).
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    from .firmware_parser import (
        SepModule,
        extract_all_modules,
        is_sep_firmware,
    )
except ImportError:
    from firmware_parser import (
        SepModule,
        extract_all_modules,
        is_sep_firmware,
    )

MACHO_MAGIC_64 = 0xFEEDFACF

LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_SEGMENT_64 = 0x19

SEG_DATA = b"__DATA"
SEG_PAGEZERO = b"__PAGEZERO"
SEG_LINKEDIT = b"__LINKEDIT"


def _seg_name(raw: bytes) -> bytes:
    """Strip the trailing NUL padding from a 16-byte Mach-O segment name."""
    return raw.split(b"\x00", 1)[0]


def _iter_load_commands(image: bytes):
    """Yield (offset, cmd, cmdsize) for each Mach-O load command.

    Yields nothing when the buffer is not a Mach-O.
    """
    if len(image) < 32:
        return
    if struct.unpack_from("<I", image, 0)[0] != MACHO_MAGIC_64:
        return
    ncmds = struct.unpack_from("<I", image, 16)[0]
    p = 32
    for _ in range(ncmds):
        if p + 8 > len(image):
            break
        cmd, csz = struct.unpack_from("<II", image, p)
        if csz < 8:
            break
        yield p, cmd, csz
        p += csz


def _is_macho(image: bytes) -> bool:
    if len(image) < 4:
        return False
    return struct.unpack_from("<I", image, 0)[0] == MACHO_MAGIC_64


def fix_linkedit(image: bytearray) -> None:
    """Relocate the __LINKEDIT segment's file offset and clear stale symbol
    tables, mirroring sepsplit-rs::fix_linkedit.

    SEP modules are linked so that file offsets equal (vmaddr - lowest vmaddr).
    The __LINKEDIT fileoff is rewritten to that value; LC_SYMTAB/LC_DYSYMTAB
    bodies are zeroed because the embedded offsets don't survive the split.
    """
    if not _is_macho(image):
        raise ValueError("not a Mach-O")

    min_vmaddr = None
    for p, cmd, _csz in _iter_load_commands(image):
        body = p + 8
        if cmd != LC_SEGMENT_64:
            continue
        name = _seg_name(image[body : body + 16])
        vmaddr = struct.unpack_from("<Q", image, body + 16)[0]
        if name != SEG_PAGEZERO and (min_vmaddr is None or vmaddr < min_vmaddr):
            min_vmaddr = vmaddr
    if min_vmaddr is None:
        min_vmaddr = 0

    for p, cmd, _csz in _iter_load_commands(image):
        body = p + 8
        if cmd == LC_SEGMENT_64:
            if _seg_name(image[body : body + 16]) == SEG_LINKEDIT:
                vmaddr = struct.unpack_from("<Q", image, body + 16)[0]
                struct.pack_into("<Q", image, body + 32, vmaddr - min_vmaddr)
        elif cmd == LC_SYMTAB:
            struct.pack_into("<IIII", image, body, 0, 0, 0, 0)
        elif cmd == LC_DYSYMTAB:
            struct.pack_into("<" + "I" * 18, image, body, *([0] * 18))


def fix_data_segment(image: bytearray, data: bytes, dataoff: int | None) -> None:
    """Copy the module's read/write bytes into its __DATA segment slot,
    mirroring sepsplit-rs::fix_data_segment.

    For apps the destination is the __DATA segment's own file offset; for
    shared libraries the caller forces it to size_text (dataoff).
    """
    if not _is_macho(image):
        raise ValueError("not a Mach-O")
    if not data:
        return
    for p, cmd, _csz in _iter_load_commands(image):
        body = p + 8
        if cmd != LC_SEGMENT_64:
            continue
        if _seg_name(image[body : body + 16]) == SEG_DATA:
            off = (
                dataoff
                if dataoff is not None
                else struct.unpack_from("<Q", image, body + 32)[0]
            )
            image[off : off + len(data)] = data


def _file_tail(mod: SepModule) -> str:
    """Filename suffix for a module, matching sepsplit-rs naming."""
    if mod.kind == "boot":
        return "boot"
    return mod.name or mod.kind


def _build_image(fw: bytes, mod: SepModule) -> bytes:
    """Reconstruct a single module's bytes with the SEP fix-ups applied."""
    if mod.kind == "boot":
        return fw[mod.phys_text : mod.phys_text + mod.size_text]

    total = mod.size_text + mod.size_data
    image = bytearray(fw[mod.phys_text : mod.phys_text + total])

    try:
        fix_linkedit(image)
    except ValueError:
        # Raw (non-Mach-O) module — e.g. the modern kernel; leave as-is.
        return bytes(image)

    if mod.size_data:
        data = fw[mod.phys_data : mod.phys_data + mod.size_data]
        dataoff = mod.size_text if mod.is_shlib else None
        fix_data_segment(image, data, dataoff)

    return bytes(image)


def split(fw: bytes, outdir: Path, verbose: bool = True) -> list[Path]:
    """Split the firmware into modules under outdir and return written paths."""
    modules = extract_all_modules(fw)
    outdir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for index, mod in enumerate(modules):
        image = _build_image(fw, mod)
        path = outdir / f"sepdump{index:02d}_{_file_tail(mod)}"
        path.write_bytes(image)
        written.append(path)
        if verbose:
            uuid = f"  UUID {mod.uuid}" if mod.uuid else ""
            print(
                f"sepdump{index:02d}  {mod.kind:<7} {_file_tail(mod):<16} "
                f"size {len(image):#x}{uuid}"
            )
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Split an Apple SEP firmware image into its modules "
        "(Python port of sepsplit-rs)."
    )
    parser.add_argument("firmware", help="decrypted, extracted SEP firmware image")
    parser.add_argument(
        "outdir",
        nargs="?",
        default=".",
        help="output directory (default: current directory)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="suppress per-module output"
    )
    args = parser.parse_args(argv)

    fw = Path(args.firmware).read_bytes()

    if fw[:2] == bytes([0x30, 0x83]):
        print(
            "[!] IMG4 header detected — extract and decrypt the SEP firmware first.",
            file=sys.stderr,
        )
        return 1
    if fw[8:16] == b"eGirBwRD":
        print(
            "[!] LZVN-compressed image detected — decompress it first.",
            file=sys.stderr,
        )
        return 1
    if not is_sep_firmware(fw):
        print("[!] Not a recognised 64-bit SEP firmware image.", file=sys.stderr)
        return 1

    paths = split(fw, Path(args.outdir), verbose=not args.quiet)
    if not args.quiet:
        print(f"\nWrote {len(paths)} modules to {Path(args.outdir).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
