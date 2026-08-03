# Copyright 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""A small surface other plugins can drive this loader through.

``binaryninja.load()`` hands back a generic ``BinaryView`` wrapper, not the
``SEPFirmwareView`` instance the core built, so ``load_module`` is out of reach
from outside — ``BinaryViewType.open()`` returns ``None`` and re-constructing
the view raises "view type not registered". Without a way across that gap, a
tool such as binja-diff can only work with whatever modules a human already
loaded in the triage UI.

So the view registers itself here, keyed by the address of the core object it
wraps, which every wrapper of that view shares. Callers look themselves up with
the plain ``BinaryView`` they were given.

This module imports nothing from ``binaryninjaui`` and must not: it is the half
of the plugin that has to keep working in a headless process.
"""

from __future__ import annotations

import ctypes
import sys
import weakref

#: 2 added load_all_modules, 3 load_modules. Bumped when the functions below
#: change shape. A consumer should check it
#: rather than assume, since the two plugins are versioned separately.
API_VERSION = 3

#: Where this module publishes itself, independent of the folder the plugin
#: happens to be installed under (Binary Ninja keys plugin modules by directory
#: name, which the user chooses). A consumer does
#: ``sys.modules.get("sep_binja_api")`` and needs no import and no path.
REGISTRY_KEY = "sep_binja_api"

#: Live views, keyed by core handle. Weak, so closing a tab drops the entry.
_VIEWS: weakref.WeakValueDictionary = weakref.WeakValueDictionary()


def _handle_key(bv) -> int | None:
    """The address of the core view behind a wrapper.

    Two Python objects for one view — the ``SEPFirmwareView`` the core built
    and the ``BinaryView`` handed to a plugin — differ as objects but point at
    the same core structure, and that address is what ties them together.
    """

    handle = getattr(bv, "handle", None)
    if handle is None:
        return None
    try:
        return ctypes.cast(handle, ctypes.c_void_p).value
    except Exception:
        return None


def register_view(view) -> None:
    """Called by SEPFirmwareView once its modules are known."""

    key = _handle_key(view)
    if key is not None:
        _VIEWS[key] = view


def view_for(bv):
    """The SEPFirmwareView behind ``bv``, or ``None`` if this is not one."""

    key = _handle_key(bv)
    return _VIEWS.get(key) if key is not None else None


def module_names(bv) -> list[str]:
    """Every module in the image, loaded or not, in firmware order."""

    view = view_for(bv)
    if view is None:
        return []
    return [mod.name for mod in view.modules]


def is_module_loaded(bv, name: str) -> bool:
    view = view_for(bv)
    if view is None:
        return False
    module = next((m for m in view.modules if m.name == name), None)
    return bool(module is not None and view.is_module_loaded(module))


def load_module(bv, name: str) -> bool:
    """Map one module's code in and analyze it. False if there is no such module.

    Already-loaded modules report True: the caller wants the module present,
    not to know who put it there.
    """

    view = view_for(bv)
    if view is None:
        return False
    module = next((m for m in view.modules if m.name == name), None)
    if module is None:
        return False
    view.load_module(module)
    view.update_analysis_and_wait()
    return True


def load_modules(bv, names) -> bool:
    """Map several modules, then analyze once.

    Not a convenience wrapper around load_module: Binary Ninja sweeps a view
    on its *first* analysis only, so a module mapped after one has completed
    contributes just what recursive descent reaches from an entry point.
    Measured over a whole 26-module image, one module at a time against all of
    them first: 26959 functions against 31499. Map everything you mean to
    analyze before anything settles the view.
    """

    view = view_for(bv)
    if view is None:
        return False
    wanted = set(names)
    modules = [module for module in view.modules if module.name in wanted]
    if len(modules) != len(wanted):
        return False
    for module in modules:
        view.load_module(module)
    view.update_analysis_and_wait()
    return True


def load_all_modules(bv) -> bool:
    """Map every module in the image and analyze once, at the end."""

    view = view_for(bv)
    if view is None:
        return False
    return load_modules(bv, [module.name for module in view.modules])


def publish() -> None:
    """Expose this module under the well-known key."""

    sys.modules.setdefault(REGISTRY_KEY, sys.modules[__name__])
