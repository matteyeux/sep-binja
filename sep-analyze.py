#!/usr/bin/env python3
# Copyright 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Analyze a SEP firmware headlessly and save a database.

Loading a SEP image in the GUI, picking modules in the triage view and waiting
for analysis is fine once; it is not something to repeat for every firmware in
a directory. This does the same thing from a shell and writes a `.bndb`, which
is what every other tool — including a diff — wants to be handed anyway.

    sep-analyze.py --list sep-firmware.bin
    sep-analyze.py -m SEPOS -m SEPD sep-firmware.bin
    sep-analyze.py --all sep-firmware.bin -o sep-26.5.bndb
    sep-analyze.py sep-firmware.bin            # asks which modules

It needs a *headless* Binary Ninja licence and this plugin installed, since the
loader is what turns the file into something with modules in it.

**Modules are mapped before the analysis runs, never after.** Binary Ninja's
initial analysis happens once, and a SEP view starts empty: analyze first and
the modules mapped afterwards only contribute what recursive descent reaches
from an entry point, never the linear sweep. Measured on a 26-module image,
same file both ways: 31499 functions mapping first, 26896 analyzing first. It
does not fail, it just quietly finds 15% less.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# A script's own directory goes on sys.path, and this one lives in the plugin
# directory, where `sep_view`, `sep_api` and friends would shadow anything of
# those names. Nothing here imports them — the loader API is looked up in
# sys.modules, where the running plugin publishes it — so drop the entry.
sys.path[:] = [entry for entry in sys.path if Path(entry or ".").resolve() != HERE]

#: sep_api.REGISTRY_KEY. Looked up rather than imported: importing the plugin's
#: package pulls in the UI half, and its module name is whatever folder it was
#: installed under.
API_KEY = "sep_binja_api"

SEP_VIEW = "SEP Firmware"


def loader_api():
    """The running plugin's loader API, or ``None`` if it is absent or old."""

    api = sys.modules.get(API_KEY)
    if api is None or getattr(api, "API_VERSION", 0) < 1:
        return None
    return api


def note(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def choose(names: list[str], loaded: set[str]) -> list[str] | None:
    """Ask which modules to analyze. ``None`` if the user gave up."""

    print("Modules in this firmware:\n")
    for index, name in enumerate(names, 1):
        print(f"  {index:2d}. {name}{'  (already loaded)' if name in loaded else ''}")
    print("\nEnter numbers or names, separated by spaces — or 'all'. Empty to cancel.")
    try:
        answer = input("> ").strip()
    except EOFError:
        return None
    if not answer:
        return None
    if answer.lower() == "all":
        return list(names)

    chosen: list[str] = []
    for token in answer.replace(",", " ").split():
        if token.isdigit() and 1 <= int(token) <= len(names):
            chosen.append(names[int(token) - 1])
        elif token in names:
            chosen.append(token)
        else:
            note(f"No module called {token!r}")
            return None
    return chosen


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sep-analyze.py",
        description="Analyze a SEP firmware headlessly and write a .bndb.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Analyzing every module of a full image takes a few minutes and\n"
            "produces a database of a few hundred megabytes. Naming the two or\n"
            "three modules you care about is usually the better trade.\n"
        ),
    )
    parser.add_argument("firmware", help="SEP firmware image")
    parser.add_argument("--list", action="store_true", help="list the modules and exit")
    parser.add_argument(
        "-m", "--module", action="append", default=[], metavar="NAME", help="analyze this module"
    )
    parser.add_argument("--all", action="store_true", help="analyze every module in the image")
    parser.add_argument(
        "-o", "--output", metavar="PATH", help="database to write (default: <firmware>.bndb)"
    )
    parser.add_argument("-f", "--force", action="store_true", help="overwrite an existing database")
    parser.add_argument(
        "--no-save", action="store_true", help="analyze but write nothing, to see what you get"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    firmware = Path(args.firmware)
    if not firmware.exists():
        note(f"error: no such file: {firmware}")
        return 1

    try:
        import binaryninja
    except ImportError as exc:
        note(f"error: Binary Ninja is not importable: {exc}")
        note("Run this with the interpreter its API is installed in.")
        return 1

    output = Path(args.output) if args.output else firmware.with_suffix(firmware.suffix + ".bndb")
    if not args.no_save and output.exists() and not args.force:
        note(f"error: {output} exists (use --force to overwrite)")
        return 1

    started = time.monotonic()
    note(f"Opening {firmware.name}...")
    # No analysis yet: the view has no module in it, and analyzing an empty one
    # is what costs functions later (see the module docstring).
    bv = binaryninja.load(str(firmware), update_analysis=False)
    if bv is None:
        note(f"error: Binary Ninja could not open {firmware}")
        return 1

    try:
        if bv.view_type != SEP_VIEW:
            note(f"error: {firmware.name} opened as {bv.view_type!r}, not a SEP firmware.")
            note("Install sep-binja, or check that this really is a SEP image.")
            return 1

        api = loader_api()
        if api is None:
            note("error: this sep-binja does not publish its loader API (needs sep_api).")
            return 1

        names = api.module_names(bv)
        if not names:
            note("error: no modules found in this image")
            return 1
        loaded = {name for name in names if api.is_module_loaded(bv, name)}

        if args.list:
            print(f"{firmware.name}: {len(names)} modules")
            for name in names:
                print(f"  {'*' if name in loaded else ' '} {name}")
            return 0

        if args.all:
            wanted = list(names)
        elif args.module:
            unknown = [name for name in args.module if name not in names]
            if unknown:
                note(f"error: no module called {', '.join(unknown)}")
                note(f"Modules in this image: {', '.join(names)}")
                return 1
            wanted = args.module
        elif sys.stdin.isatty():
            picked = choose(names, loaded)
            if not picked:
                note("nothing chosen")
                return 1
            wanted = picked
        else:
            note("error: nothing to analyze — pass --module NAME, --all, or --list")
            return 1

        load_all = getattr(api, "load_all_modules", None)
        if args.all and load_all is not None:
            # One analysis at the end rather than one per module: load_module
            # settles the view every time, which for a whole image is two dozen
            # analyses of the same thing.
            note(f"Mapping all {len(wanted)} modules...")
            if not load_all(bv):
                note("error: could not load the modules")
                return 1
        else:
            for index, name in enumerate(wanted, 1):
                note(f"[{index}/{len(wanted)}] mapping {name}")
                if not api.load_module(bv, name):
                    note(f"error: could not load {name}")
                    return 1

        note(f"Analyzing {len(wanted)} module(s)...")
        bv.update_analysis_and_wait()
        elapsed = time.monotonic() - started
        print(f"{len(bv.functions)} functions in {', '.join(wanted)} ({elapsed:.0f}s)")

        if args.no_save:
            return 0

        note(f"Writing {output}...")
        if not bv.create_database(str(output)):
            note(f"error: could not write {output}")
            return 1
        size = output.stat().st_size / (1024 * 1024)
        print(f"{output} ({size:.0f} MB, {time.monotonic() - started:.0f}s total)")
        return 0
    except KeyboardInterrupt:
        note("cancelled")
        return 130
    finally:
        bv.file.close()


if __name__ == "__main__":
    raise SystemExit(main())
