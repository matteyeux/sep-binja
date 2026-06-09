"""
SEP firmware triage view.

Registers a UI-side `ViewType` that activates when the current BinaryView
is a parsed SEP Firmware and presents a navigable directory of the
embedded modules (boot, kernel, SEPOS, apps, shared lib) plus a filterable
symbol list.

Mirrors the architectural pattern used by the C++ kernelcache plugin's
KCTriageView but expressed with the Binary Ninja Python UI API
(binaryninjaui + PySide6).
"""

import binaryninjaui
from binaryninja.enums import SymbolType
from binaryninja.log import log_warn
from binaryninjaui import (
    FilterTarget,
    UIContext,
    View,
    ViewFrame,
    ViewType,
)
from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMenu,
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .firmware_parser import extract_all_modules
from .sep_view import SEPFirmwareView

SEP_VIEW_NAME = "SEP Firmware"
DEFAULT_RELOC_STEP = 0x100000000


class _ModulesModel(QAbstractTableModel):
    COLUMNS = ("Loaded", "Address", "Kind", "Name", "UUID", "Size")

    def __init__(self, modules, va_fn, is_loaded_fn) -> None:
        super().__init__()
        self._is_loaded = is_loaded_fn
        self._all: list[tuple] = []
        for mod in modules:
            va = va_fn(mod)
            self._all.append(
                (va, mod.kind, mod.name or "(unnamed)", mod.uuid, mod.size_text, mod)
            )
        self._entries = list(self._all)
        self._sort_col = 1
        self._sort_order = Qt.AscendingOrder

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        va, kind, name, uuid, size, mod = self._entries[index.row()]
        col = index.column()
        if col == 0:
            return "✓" if self._is_loaded(mod) else ""
        if col == 1:
            return f"0x{va:x}"
        if col == 2:
            return kind
        if col == 3:
            return name
        if col == 4:
            return uuid
        if col == 5:
            return f"0x{size:x}"
        return None

    def address_for_row(self, row: int) -> int | None:
        if 0 <= row < len(self._entries):
            return self._entries[row][0]
        return None

    def module_for_row(self, row: int):
        if 0 <= row < len(self._entries):
            return self._entries[row][5]
        return None

    def _key(self, col, row):
        va, kind, name, uuid, size, mod = row
        if col == 0:
            return 1 if self._is_loaded(mod) else 0
        if col == 1:
            return va
        if col == 2:
            return kind
        if col == 3:
            return name.lower()
        if col == 4:
            return uuid
        if col == 5:
            return size
        return 0

    def sort(self, col, order=Qt.AscendingOrder):
        self.beginResetModel()
        self._sort_col = col
        self._sort_order = order
        self._entries.sort(
            key=lambda r: self._key(col, r), reverse=order != Qt.AscendingOrder
        )
        self.endResetModel()

    def set_filter(self, text: str) -> None:
        needle = text.lower().strip()
        self.beginResetModel()
        if not needle:
            self._entries = list(self._all)
        else:
            self._entries = [
                r
                for r in self._all
                if needle in r[1].lower()
                or needle in r[2].lower()
                or needle in r[3].lower()
                or needle in f"0x{r[0]:x}"
            ]
        self._entries.sort(
            key=lambda r: self._key(self._sort_col, r),
            reverse=self._sort_order != Qt.AscendingOrder,
        )
        self.endResetModel()

    def refresh_loaded(self) -> None:
        """Tell Qt the Loaded column data has changed without resorting."""
        if not self._entries:
            return
        top = self.index(0, 0)
        bottom = self.index(len(self._entries) - 1, 0)
        self.dataChanged.emit(top, bottom, [Qt.DisplayRole])


class _SymbolsModel(QAbstractTableModel):
    COLUMNS = ("Address", "Module", "Name")

    def __init__(self, data, modules, reloc_step: int) -> None:
        super().__init__()
        self._all: list[tuple[int, str, str]] = []
        self._entries: list[tuple[int, str, str]] = []
        self._sort_col = 0
        self._sort_order = Qt.AscendingOrder
        self.reload(data, modules, reloc_step)

    def reload(self, data, modules, reloc_step: int) -> None:
        ranges: list[tuple[int, int, str]] = []
        for mod in modules:
            if mod.binja_idx:
                base = reloc_step * mod.binja_idx
                end = base + reloc_step
            else:
                base = mod.phys_text
                end = base + max(mod.size_text, 1)
            ranges.append((base, end, mod.name or mod.kind))
        ranges.sort()

        def containing(addr: int) -> str:
            for start, end, name in ranges:
                if start <= addr < end:
                    return name
            return ""

        self.beginResetModel()
        self._all = []
        for sym in data.get_symbols():
            if sym.type not in (SymbolType.FunctionSymbol, SymbolType.DataSymbol):
                continue
            self._all.append((sym.address, containing(sym.address), sym.full_name))
        self._entries = list(self._all)
        self._entries.sort(
            key=lambda r: self._key(self._sort_col, r),
            reverse=self._sort_order != Qt.AscendingOrder,
        )
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        addr, module, name = self._entries[index.row()]
        col = index.column()
        if col == 0:
            return f"0x{addr:x}"
        if col == 1:
            return module
        if col == 2:
            return name
        return None

    def address_for_row(self, row: int) -> int | None:
        if 0 <= row < len(self._entries):
            return self._entries[row][0]
        return None

    def _key(self, col, row):
        addr, module, name = row
        if col == 0:
            return addr
        if col == 1:
            return module.lower()
        if col == 2:
            return name.lower()
        return 0

    def sort(self, col, order=Qt.AscendingOrder):
        self.beginResetModel()
        self._sort_col = col
        self._sort_order = order
        self._entries.sort(
            key=lambda r: self._key(col, r), reverse=order != Qt.AscendingOrder
        )
        self.endResetModel()

    def set_filter(self, text: str) -> None:
        needle = text.lower().strip()
        self.beginResetModel()
        if not needle:
            self._entries = list(self._all)
        else:
            self._entries = [
                r
                for r in self._all
                if needle in r[1].lower()
                or needle in r[2].lower()
                or needle in f"0x{r[0]:x}"
            ]
        self._entries.sort(
            key=lambda r: self._key(self._sort_col, r),
            reverse=self._sort_order != Qt.AscendingOrder,
        )
        self.endResetModel()


class _FilterableTableView(QTableView, FilterTarget):
    """QTableView wired up to a filterable model via the FilterTarget API."""

    def __init__(self, parent, model) -> None:
        QTableView.__init__(self, parent)
        FilterTarget.__init__(self)
        self._model = model
        self.setModel(model)
        self.setFont(binaryninjaui.getMonospaceFont(self))
        self.setSelectionBehavior(QTableView.SelectRows)
        self.setSelectionMode(QTableView.ExtendedSelection)
        self.setEditTriggers(QTableView.NoEditTriggers)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.AscendingOrder)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.resizeColumnsToContents()

    def setFilter(self, filterText) -> None:
        if hasattr(filterText, "toStdString"):
            filterText = filterText.toStdString()
        self._model.set_filter(str(filterText))

    def scrollToFirstItem(self) -> None:
        self.scrollToTop()

    def scrollToCurrentItem(self) -> None:
        self.scrollTo(self.currentIndex())

    def ensureSelection(self) -> None:
        if not self.currentIndex().isValid() and self._model.rowCount() > 0:
            self.setCurrentIndex(self._model.index(0, 0))

    def activateSelection(self) -> None:
        self.ensureSelection()
        idx = self.currentIndex()
        if idx.isValid():
            self.activated.emit(idx)


class SEPTriageView(QWidget, View):
    """Directory / triage view for a parsed SEP firmware."""

    def __init__(self, parent, data) -> None:
        QWidget.__init__(self, parent)
        View.__init__(self)
        View.setBinaryDataNavigable(self, True)
        self.setupView(self)
        self.data = data
        self._current_offset = 0

        # The BinaryView wrapper handed to ViewType.create isn't guaranteed
        # to be the same Python instance that ran _load(), so fall back to
        # re-parsing the firmware from the parent view when the cached
        # module list isn't available.
        self._modules = self._get_modules()
        self._reloc_step = getattr(data, "reloc_step", DEFAULT_RELOC_STEP)

        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._build_modules_tab(), "Modules")
        self._tabs.addTab(self._build_symbols_tab(), "Symbols")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self._tabs, 1)
        self.setLayout(layout)

    def _sep_view(self) -> "SEPFirmwareView | None":
        return SEPFirmwareView.for_view(self.data)

    def _get_modules(self) -> list:
        sep = self._sep_view()
        if sep is not None and sep.modules:
            return list(sep.modules)
        parent = self.data.parent_view
        if parent is None:
            return []
        try:
            fw = bytes(parent.read(0, parent.length))
            return extract_all_modules(fw)
        except Exception as exc:
            log_warn(f"[SEP] triage view: could not re-parse firmware: {exc}")
            return []

    def _module_va(self, mod) -> int:
        sep = self._sep_view()
        if sep is not None:
            try:
                return sep.module_display_va(mod)
            except Exception:
                pass
        if mod.binja_idx:
            return self._reloc_step * mod.binja_idx
        return mod.phys_text

    def _build_modules_tab(self) -> QWidget:
        self._modules_model = _ModulesModel(
            self._modules, self._module_va, self._is_module_loaded
        )
        self._modules_table = _FilterableTableView(self, self._modules_model)
        self._modules_table.sortByColumn(1, Qt.AscendingOrder)
        self._modules_table.activated.connect(self._navigate_modules_row)
        self._modules_table.selectionModel().currentRowChanged.connect(
            self._modules_row_changed
        )
        self._modules_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._modules_table.customContextMenuRequested.connect(self._show_modules_menu)

        self._load_selected_btn = QPushButton("Load selected", self)
        self._load_selected_btn.clicked.connect(self._on_load_selected)

        self._load_all_btn = QPushButton("Load entire firmware", self)
        self._load_all_btn.clicked.connect(self._on_load_all)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.addWidget(self._load_selected_btn)
        btn_row.addWidget(self._load_all_btn)
        btn_row.addStretch(1)

        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._modules_table, 1)
        layout.addLayout(btn_row)
        container.setLayout(layout)
        container.setMinimumSize(UIContext.getScaledWindowSize(100, 196))
        return container

    def _build_symbols_tab(self) -> QWidget:
        self._symbols_model = _SymbolsModel(self.data, self._modules, self._reloc_step)
        self._symbols_table = _FilterableTableView(self, self._symbols_model)
        self._symbols_table.activated.connect(self._navigate_symbols_row)
        self._symbols_table.selectionModel().currentRowChanged.connect(
            self._symbols_row_changed
        )

        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._symbols_table, 1)
        container.setLayout(layout)
        return container

    def _navigate_to(self, addr: int | None) -> None:
        if addr is None:
            return
        frame = ViewFrame.viewFrameForWidget(self)
        if frame is None:
            return
        data_type = frame.getCurrentDataType() or SEP_VIEW_NAME
        frame.navigate(f"Linear:{data_type}", addr)

    def _is_module_loaded(self, mod) -> bool:
        sep = self._sep_view()
        return sep.is_module_loaded(mod) if sep is not None else False

    def _navigate_modules_row(self, index) -> None:
        row = index.row()
        mod = self._modules_model.module_for_row(row)
        sep = self._sep_view()
        if mod is not None and sep is not None and sep.load_module(mod):
            self._after_load_changed()
        self._navigate_to(self._modules_model.address_for_row(row))

    def _on_load_all(self) -> None:
        sep = self._sep_view()
        if sep is None:
            log_warn("[SEP] triage view: could not find SEPFirmwareView instance")
            return
        sep.load_all()
        self._after_load_changed()

    def _on_load_selected(self) -> None:
        sep = self._sep_view()
        if sep is None:
            log_warn("[SEP] triage view: could not find SEPFirmwareView instance")
            return
        rows = {
            idx.row() for idx in self._modules_table.selectionModel().selectedRows()
        }
        changed = False
        for row in sorted(rows):
            mod = self._modules_model.module_for_row(row)
            if mod is not None and sep.load_module(mod):
                changed = True
        if changed:
            self._after_load_changed()

    def _show_modules_menu(self, pos) -> None:
        rows = {
            idx.row() for idx in self._modules_table.selectionModel().selectedRows()
        }
        clicked = self._modules_table.indexAt(pos)
        if clicked.isValid() and clicked.row() not in rows:
            self._modules_table.selectRow(clicked.row())
            rows = {clicked.row()}
        if not rows:
            return
        label = "Load module" if len(rows) == 1 else f"Load {len(rows)} modules"
        menu = QMenu(self._modules_table)
        menu.addAction(label, self._on_load_selected)
        menu.exec_(self._modules_table.viewport().mapToGlobal(pos))

    def _after_load_changed(self) -> None:
        self._modules_model.refresh_loaded()
        self._symbols_model.reload(self.data, self._modules, self._reloc_step)

    def _navigate_symbols_row(self, index) -> None:
        self._navigate_to(self._symbols_model.address_for_row(index.row()))

    def _modules_row_changed(self, current, _previous) -> None:
        addr = self._modules_model.address_for_row(current.row())
        if addr is not None:
            self._current_offset = addr
            UIContext.updateStatus()

    def _symbols_row_changed(self, current, _previous) -> None:
        addr = self._symbols_model.address_for_row(current.row())
        if addr is not None:
            self._current_offset = addr
            UIContext.updateStatus()

    def getData(self):
        return self.data

    def getCurrentOffset(self) -> int:
        return self._current_offset

    def getSelectionOffsets(self):
        return (self._current_offset, self._current_offset)

    def setCurrentOffset(self, offset) -> None:
        self._current_offset = offset
        UIContext.updateStatus()

    def getFont(self):
        return binaryninjaui.getMonospaceFont(self)

    def navigate(self, addr) -> bool:
        self._current_offset = addr
        return True


class SEPTriageViewType(ViewType):
    def __init__(self) -> None:
        super().__init__("SEPTriage", "SEP Firmware Triage")

    def getPriority(self, data, filename) -> int:
        if data.view_type == SEP_VIEW_NAME:
            return 1000
        return 0

    def create(self, data, view_frame):
        if data.view_type != SEP_VIEW_NAME:
            return None
        return SEPTriageView(view_frame, data)

    @staticmethod
    def register() -> None:
        ViewType.registerViewType(SEPTriageViewType())
