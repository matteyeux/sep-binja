#!/usr/bin/env python3
# Copyright 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Diff two Apple SEP firmware images.

Answers the question you actually have when a new SEP ships: what moved? Which
apps are new, which are gone, which were rebuilt, what did the kernel gain, and
which strings and sections appeared or vanished along the way.

    sep-diff.py sep_26.5.bin sep.27.0.bin
    sep-diff.py old.bin new.bin --only SEPD --only sks
    sep-diff.py old.bin new.bin --strings --limit 0    # every string, no cap
    sep-diff.py old.bin new.bin --json > diff.json

No Binary Ninja, no LIEF, no third-party anything — just firmware_parser and
macho_helpers, so this runs anywhere python3 does.

A note on what "changed" means here. Every module is prebound at a physical
offset, so anything that grows shifts everything after it and the raw bytes of
an untouched app can still differ. The signals worth trusting are the ones this
reports: the source version, section sizes, dylib dependencies, symbols and
strings.

Build UUIDs are deliberately not among them. Every rebuild mints a new one, in
the header and in LC_UUID both, so reporting them makes every module in every
image pair look changed and buries the few that really are. A module whose only
difference is its UUID is treated as unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from .firmware_parser import (
        SepModule,
        extract_all_modules,
        get_srcver_major,
        is_sep_firmware,
        parse_legion_layout,
    )
    from .macho_helpers import MachOBinary, parse_macho
except ImportError:
    from firmware_parser import (
        SepModule,
        extract_all_modules,
        get_srcver_major,
        is_sep_firmware,
        parse_legion_layout,
    )
    from macho_helpers import MachOBinary, parse_macho

#: Runs of printable ASCII (plus tab) at least this long count as a string.
#: 8 rather than the 4 strings(1) uses: ARM64 code is full of six-byte runs that
#: happen to be printable, and they drown a diff. Lower it if you are hunting
#: something short and know what you are looking at.
DEFAULT_MIN_STRING = 8

#: How many entries of any one added/removed list to print before summarising.
DEFAULT_LIMIT = 20


def fmt_srcver(srcver: int) -> str:
    """A packed SrcVer as major.minor.p1.p2.p3, the way Apple writes it."""
    if srcver == 0:
        return "-"
    fields = (
        get_srcver_major(srcver),
        (srcver >> 30) & 0x3FF,
        (srcver >> 20) & 0x3FF,
        (srcver >> 10) & 0x3FF,
        srcver & 0x3FF,
    )
    return ".".join(str(f) for f in fields)


def fmt_size(n: int) -> str:
    return f"{n:#x}"


def fmt_delta(old: int, new: int, formatter=fmt_size) -> str:
    """Render a change as `old -> new (+delta)`, or bare when unchanged."""
    if old == new:
        return formatter(new)
    sign = "+" if new > old else "-"
    return f"{formatter(old)} -> {formatter(new)} ({sign}{formatter(abs(new - old))})"


# ── One side of the comparison ────────────────────────────────────────────────


@dataclass
class Module:
    """A module plus everything about it that is worth comparing.

    The expensive parts — the Mach-O parse, the string scan — are computed on
    first use, so restricting a run with --only really does less work.
    """

    mod: SepModule
    image: Image
    _macho: MachOBinary | None = None
    _macho_done: bool = False
    _strings: set[str] | None = None

    @property
    def name(self) -> str:
        return self.mod.name

    @property
    def text(self) -> bytes:
        return self.image.raw[
            self.mod.phys_text : self.mod.phys_text + self.mod.size_text
        ]

    @property
    def data(self) -> bytes:
        if not self.mod.size_data:
            return b""
        return self.image.raw[
            self.mod.phys_data : self.mod.phys_data + self.mod.size_data
        ]

    @property
    def digest(self) -> str:
        h = hashlib.sha256()
        h.update(self.text)
        h.update(self.data)
        return h.hexdigest()

    @property
    def macho(self) -> MachOBinary | None:
        if not self._macho_done:
            self._macho_done = True
            if self.mod.is_macho:
                self._macho = parse_macho(self.text)
        return self._macho

    @property
    def sections(self) -> dict[str, int]:
        """{"__TEXT:__text": size}. Empty for the raw boot stub and kernel."""
        binary = self.macho
        if binary is None:
            return {}
        return {
            f"{sect.segment_name}:{sect.name}": sect.size
            for seg in binary.segments
            for sect in seg.sections
        }

    @property
    def segments(self) -> dict[str, int]:
        binary = self.macho
        if binary is None:
            return {}
        return {seg.name: seg.virtual_size for seg in binary.segments}

    @property
    def libraries(self) -> set[str]:
        binary = self.macho
        return set(binary.libraries) if binary else set()

    @property
    def symbols(self) -> set[str]:
        binary = self.macho
        return {name for name, _ in binary.symbols} if binary else set()

    def strings(self, min_len: int) -> set[str]:
        if self._strings is None:
            pattern = re.compile(rb"[ -~\t]{%d,}" % min_len)
            found = set()
            for blob in (self._string_scan_region(), self.data):
                for match in pattern.finditer(blob):
                    found.add(match.group().decode("ascii"))
            self._strings = found
        return self._strings

    def _string_scan_region(self) -> bytes:
        """The TEXT bytes worth scanning for strings.

        For the boot stub that means skipping the legion header, which shares
        its range: every name in there is a struct field this already compares
        properly, and scanning it just yields each app's name glued to whatever
        printable byte follows it.
        """
        if self.mod.kind != "boot":
            return self.text
        layout = self.image.layout
        start = layout.apps_end if layout else 0
        return self.text[start:] if start < len(self.text) else b""


@dataclass
class Image:
    """A firmware image, parsed."""

    path: Path
    raw: bytes
    modules: dict[str, Module] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> Image:
        raw = path.read_bytes()
        if not is_sep_firmware(raw):
            raise ValueError(
                f"{path.name} is not a raw SEP firmware image "
                "(decrypt and unwrap the IMG4 first)"
            )
        image = cls(path=path, raw=raw)
        for mod in extract_all_modules(raw):
            # Duplicate names have never been seen, but a silently dropped
            # module would be a bad way to find out.
            key = mod.name
            suffix = 2
            while key in image.modules:
                key = f"{mod.name}#{suffix}"
                suffix += 1
            image.modules[key] = Module(mod=mod, image=image)
        return image

    @property
    def layout(self):
        return parse_legion_layout(self.raw)


# ── Diffing ───────────────────────────────────────────────────────────────────


def diff_sets(old: set, new: set) -> tuple[list, list]:
    """(added, removed), both sorted."""
    return sorted(new - old), sorted(old - new)


def diff_sized(old: dict[str, int], new: dict[str, int]) -> dict:
    """Compare two name -> size maps."""
    added, removed = diff_sets(set(old), set(new))
    resized = [
        {"name": name, "old": old[name], "new": new[name]}
        for name in sorted(set(old) & set(new))
        if old[name] != new[name]
    ]
    return {"added": added, "removed": removed, "resized": resized}


def diff_image_header(old: Image, new: Image) -> dict:
    """Whole-image facts: sizes, header layout, counts."""
    ol, nl = old.layout, new.layout
    report = {
        "file_size": {"old": len(old.raw), "new": len(new.raw)},
        "module_count": {"old": len(old.modules), "new": len(new.modules)},
    }
    if ol is None or nl is None:
        return report
    report.update(
        {
            "legion_subversion": {"old": ol.ver, "new": nl.ver},
            "sepos_boot_args_offset": {"old": ol.hdr_offset, "new": nl.hdr_offset},
            "app_struct_stride": {"old": ol.stride, "new": nl.stride},
            "apps": {"old": ol.n_apps, "new": nl.n_apps},
            "shlibs": {"old": ol.n_shlibs, "new": nl.n_shlibs},
            "srcver_major": {"old": ol.srcver_major, "new": nl.srcver_major},
        }
    )
    return report


def diff_module(old: Module, new: Module, opts: argparse.Namespace) -> dict:
    """Everything that differs about one module present in both images."""
    report: dict = {"name": new.name, "kind": new.mod.kind}

    # No "uuid" here on purpose — see the module docstring.
    for label, attr in (
        ("srcver", "srcver"),
        ("size_text", "size_text"),
        ("size_data", "size_data"),
        ("phys_text", "phys_text"),
        ("phys_data", "phys_data"),
        ("virt", "virt"),
        ("ventry", "ventry"),
    ):
        ov, nv = getattr(old.mod, attr), getattr(new.mod, attr)
        if ov != nv:
            report[label] = {"old": ov, "new": nv}

    report["bytes_differ"] = old.digest != new.digest
    if not report["bytes_differ"]:
        return report

    # A Mach-O that stopped parsing (or started) is worth saying out loud.
    if (old.macho is None) != (new.macho is None):
        report["macho_parse"] = {
            "old": old.macho is not None,
            "new": new.macho is not None,
        }

    sections = diff_sized(old.sections, new.sections)
    if any(sections.values()):
        report["sections"] = sections
    segments = diff_sized(old.segments, new.segments)
    if any(segments.values()):
        report["segments"] = segments

    added, removed = diff_sets(old.libraries, new.libraries)
    if added or removed:
        report["libraries"] = {"added": added, "removed": removed}

    if opts.symbols:
        added, removed = diff_sets(old.symbols, new.symbols)
        if added or removed:
            report["symbols"] = {"added": added, "removed": removed}

    if opts.strings:
        added, removed = diff_sets(old.strings(opts.min_len), new.strings(opts.min_len))
        if added or removed:
            report["strings"] = {"added": added, "removed": removed}

    return report


#: LC_UUID, and the width of the uuid it carries.
LC_UUID = 0x1B
UUID_LEN = 16


def byte_differences(a: bytes, b: bytes) -> tuple[int, int | None, int | None]:
    """(count, first offset, last offset) over the length the two share."""
    count = 0
    first = last = None
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            count += 1
            if first is None:
                first = i
            last = i
    return count, first, last


def find_lc_uuid(data: bytes) -> tuple[int, int] | None:
    """Byte range of LC_UUID's payload in a Mach-O, or None if it has none."""
    if len(data) < 32:
        return None
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return None
    (ncmds,) = struct.unpack_from("<I", data, 16)
    p = 32 if magic == 0xFEEDFACF else 28
    for _ in range(ncmds):
        if p + 8 > len(data):
            break
        cmd, csz = struct.unpack_from("<II", data, p)
        if csz < 8:
            break
        if cmd == LC_UUID and p + 8 + UUID_LEN <= len(data):
            return p + 8, p + 8 + UUID_LEN
        p += csz
    return None


def diff_content(old: Module, new: Module) -> dict:
    """How much of a module's bytes moved, and where it starts.

    Worth having even for a Mach-O, where the structural diff can come up empty:
    "differs from byte 8 onward" and "differs in 40 bytes near the end" are very
    different findings, and neither shows up as a section or a string.
    """
    report: dict = {}
    for label, a, b in (("text", old.text, new.text), ("data", old.data, new.data)):
        if a == b:
            continue
        count, first, last = byte_differences(a, b)
        if (
            label == "text"
            and first is not None
            and confined_to_lc_uuid(a, b, first, last)
        ):
            # A point release rebuilds every module and each one gets a fresh
            # LC_UUID. Reporting that is reporting nothing, so drop the region
            # entirely; if this leaves the module with no difference at all, it
            # is classed as unchanged.
            continue
        entry: dict = {
            "differing_bytes": count,
            "compared_bytes": min(len(a), len(b)),
            "size": {"old": len(a), "new": len(b)},
        }
        if first is not None:
            entry["first_difference"] = first
            entry["last_difference"] = last
        report[label] = entry
    return report


def confined_to_lc_uuid(a: bytes, b: bytes, first: int, last: int) -> bool:
    """True when every differing byte falls inside a shared LC_UUID payload."""
    if len(a) != len(b):
        return False
    span = find_lc_uuid(a)
    return bool(
        span and span == find_lc_uuid(b) and span[0] <= first and last < span[1]
    )


def build_report(old: Image, new: Image, opts: argparse.Namespace) -> dict:
    wanted = set(opts.only) if opts.only else None
    added, removed = diff_sets(set(old.modules), set(new.modules))
    if wanted is not None:
        added = [n for n in added if n in wanted]
        removed = [n for n in removed if n in wanted]

    def describe(image: Image, name: str) -> dict:
        mod = image.modules[name].mod
        return {
            "name": name,
            "kind": mod.kind,
            "uuid": mod.uuid,
            "size_text": mod.size_text,
            "size_data": mod.size_data,
            "srcver": mod.srcver,
            "is_macho": mod.is_macho,
        }

    changed = []
    unchanged = []
    for name in sorted(set(old.modules) & set(new.modules)):
        if wanted is not None and name not in wanted:
            continue
        report = diff_module(old.modules[name], new.modules[name], opts)
        if report["bytes_differ"]:
            content = diff_content(old.modules[name], new.modules[name])
            if content:
                report["content"] = content
        # Nothing left once the UUID is out of the picture — which is the whole
        # story for most modules of a point release — means unchanged, even
        # though the bytes are not identical.
        if not [k for k in report if k not in ("name", "kind", "bytes_differ")]:
            unchanged.append(name)
            continue
        changed.append(report)

    return {
        "old": str(old.path),
        "new": str(new.path),
        "image": diff_image_header(old, new),
        "modules_added": [describe(new, n) for n in added],
        "modules_removed": [describe(old, n) for n in removed],
        "modules_changed": changed,
        "modules_unchanged": unchanged,
    }


# ── Text rendering ────────────────────────────────────────────────────────────


class Printer:
    def __init__(self, limit: int) -> None:
        self.limit = limit

    def heading(self, text: str) -> None:
        print(f"\n{text}")
        print("─" * len(text))

    def listing(self, marker: str, label: str, items: list) -> None:
        """A capped +/- list. The cap keeps a string diff readable."""
        if not items:
            return
        shown = items if self.limit == 0 else items[: self.limit]
        print(f"    {label} ({len(items)})")
        for item in shown:
            text = item if isinstance(item, str) else str(item)
            print(f"      {marker} {text}")
        if len(items) > len(shown):
            print(f"      … {len(items) - len(shown)} more (--limit 0 for all)")


def render_image(report: dict, p: Printer) -> None:
    p.heading("Image")
    image = report["image"]
    rows = [
        ("file size", fmt_delta(image["file_size"]["old"], image["file_size"]["new"])),
        (
            "modules",
            fmt_delta(image["module_count"]["old"], image["module_count"]["new"], str),
        ),
    ]
    if "srcver_major" in image:
        rows += [
            (
                "srcver major",
                fmt_delta(
                    image["srcver_major"]["old"], image["srcver_major"]["new"], str
                ),
            ),
            (
                "legion subversion",
                fmt_delta(
                    image["legion_subversion"]["old"],
                    image["legion_subversion"]["new"],
                    str,
                ),
            ),
            (
                "sepos_boot_args at",
                fmt_delta(
                    image["sepos_boot_args_offset"]["old"],
                    image["sepos_boot_args_offset"]["new"],
                ),
            ),
            (
                "SEPApp64 stride",
                fmt_delta(
                    image["app_struct_stride"]["old"], image["app_struct_stride"]["new"]
                ),
            ),
            (
                "apps / shlibs",
                fmt_delta(image["apps"]["old"], image["apps"]["new"], str)
                + "  /  "
                + fmt_delta(image["shlibs"]["old"], image["shlibs"]["new"], str),
            ),
        ]
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"  {label:<{width}}  {value}")


def render_presence(report: dict, p: Printer) -> None:
    for key, marker, title in (
        ("modules_added", "+", "Modules added"),
        ("modules_removed", "-", "Modules removed"),
    ):
        entries = report[key]
        if not entries:
            continue
        p.heading(f"{title} ({len(entries)})")
        for entry in entries:
            kind = entry["kind"]
            macho = "Mach-O" if entry["is_macho"] else "raw"
            print(
                f"  {marker} {entry['name']:<20s} {kind:<7s} {macho:<6s} "
                f"text={fmt_size(entry['size_text'])} data={fmt_size(entry['size_data'])}"
            )
            print(f"      uuid   {entry['uuid'] or '-'}")
            print(f"      srcver {fmt_srcver(entry['srcver'])}")


def render_changed(report: dict, p: Printer) -> None:
    changed = report["modules_changed"]
    if not changed:
        return
    p.heading(f"Modules changed ({len(changed)})")
    for entry in changed:
        print(f"\n  {entry['name']}  [{entry['kind']}]")

        if "srcver" in entry:
            print(
                f"    srcver     {fmt_srcver(entry['srcver']['old'])} -> "
                f"{fmt_srcver(entry['srcver']['new'])}"
            )
        for label in ("size_text", "size_data", "virt", "ventry"):
            if label in entry:
                print(
                    f"    {label:<10s} {fmt_delta(entry[label]['old'], entry[label]['new'])}"
                )
        # Physical moves are a consequence of anything earlier resizing, so they
        # are noted but never the headline.
        moves = [label for label in ("phys_text", "phys_data") if label in entry]
        if moves:
            parts = (
                f"{m}={fmt_delta(entry[m]['old'], entry[m]['new'])}" for m in moves
            )
            print(f"    relocated  {'  '.join(parts)}")
        if "macho_parse" in entry:
            parsed_before = entry["macho_parse"]["old"]
            print(
                f"    Mach-O parse {'stopped working' if parsed_before else 'now works'}"
            )

        for label, block in entry.get("content", {}).items():
            if "first_difference" not in block:
                print(
                    f"    {label:<10s} identical up to {block['compared_bytes']:#x}, "
                    f"then {fmt_delta(block['size']['old'], block['size']['new'])}"
                )
                continue
            pct = 100.0 * block["differing_bytes"] / max(block["compared_bytes"], 1)
            print(
                f"    {label:<10s} {block['differing_bytes']:#x} of "
                f"{block['compared_bytes']:#x} bytes differ ({pct:.1f}%), "
                f"{block['first_difference']:#x}..{block['last_difference']:#x}"
            )

        for key, title in (("segments", "segment"), ("sections", "section")):
            if key not in entry:
                continue
            block = entry[key]
            p.listing("+", f"{title}s added", block["added"])
            p.listing("-", f"{title}s removed", block["removed"])
            resized = [
                f"{r['name']}  {fmt_delta(r['old'], r['new'])}"
                for r in block["resized"]
            ]
            p.listing("~", f"{title}s resized", resized)

        if "libraries" in entry:
            p.listing("+", "dylibs added", entry["libraries"]["added"])
            p.listing("-", "dylibs removed", entry["libraries"]["removed"])
        if "symbols" in entry:
            p.listing("+", "symbols added", entry["symbols"]["added"])
            p.listing("-", "symbols removed", entry["symbols"]["removed"])
        if "strings" in entry:
            p.listing("+", "strings added", entry["strings"]["added"])
            p.listing("-", "strings removed", entry["strings"]["removed"])

        structural = any(
            k in entry
            for k in ("segments", "sections", "libraries", "symbols", "strings")
        )
        if entry["bytes_differ"] and not structural:
            print(
                "    (no section, dylib or string changed — a rebuild of the same code)"
            )


def render(report: dict, opts: argparse.Namespace) -> None:
    p = Printer(opts.limit)
    old, new = Path(report["old"]).name, Path(report["new"]).name
    print(f"{old}  ->  {new}")
    render_image(report, p)
    render_presence(report, p)
    render_changed(report, p)

    unchanged = report["modules_unchanged"]
    if unchanged and not opts.quiet:
        p.heading(f"Modules unchanged ({len(unchanged)})")
        print("  identical, or rebuilt with nothing but a new UUID")
        print("  " + ", ".join(unchanged))

    total = (
        len(report["modules_added"])
        + len(report["modules_removed"])
        + len(report["modules_changed"])
    )
    print(f"\n{total} module(s) differ, {len(unchanged)} unchanged")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sep-diff.py",
        description="Diff two Apple SEP firmware images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Strings are compared as sets, so a reordered binary shows nothing\n"
            "while a new log message or entitlement shows up immediately. Some\n"
            "noise is unavoidable — compiled ARM64 contains byte runs that are\n"
            "printable by accident — so raise --min-len when a module is mostly\n"
            "code, and lower it when you are hunting something short.\n"
        ),
    )
    parser.add_argument("old", help="the earlier SEP firmware image")
    parser.add_argument("new", help="the later SEP firmware image")
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME",
        help="restrict to this module (repeatable)",
    )
    strings = parser.add_mutually_exclusive_group()
    strings.add_argument(
        "--strings",
        action="store_true",
        default=True,
        help="diff ASCII strings per module (default)",
    )
    strings.add_argument(
        "--no-strings", dest="strings", action="store_false", help="skip string diffing"
    )
    parser.add_argument(
        "--symbols", action="store_true", help="diff symbol names too (noisy)"
    )
    parser.add_argument(
        "--min-len",
        type=int,
        default=DEFAULT_MIN_STRING,
        metavar="N",
        help=f"shortest run of ASCII counted as a string (default {DEFAULT_MIN_STRING})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        metavar="N",
        help=f"entries per list before summarising, 0 for all (default {DEFAULT_LIMIT})",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="leave out the identical-modules list",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    opts = parse_args(argv)
    if opts.min_len < 1:
        print("error: --min-len must be at least 1", file=sys.stderr)
        return 2

    try:
        old = Image.load(Path(opts.old))
        new = Image.load(Path(opts.new))
    except FileNotFoundError as exc:
        print(f"error: no such file: {exc.filename}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if opts.only:
        known = set(old.modules) | set(new.modules)
        unknown = [name for name in opts.only if name not in known]
        if unknown:
            print(f"error: no module called {', '.join(unknown)}", file=sys.stderr)
            print(f"In these images: {', '.join(sorted(known))}", file=sys.stderr)
            return 1

    report = build_report(old, new, opts)
    if opts.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        render(report, opts)

    differs = (
        len(report["modules_added"])
        + len(report["modules_removed"])
        + len(report["modules_changed"])
    )
    # Exit 1 when the images differ, like diff(1), so this is usable in a script.
    return 1 if differs else 0


if __name__ == "__main__":
    raise SystemExit(main())
