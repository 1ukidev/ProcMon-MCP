"""Static PE import and export extraction."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

NATIVE_API_PREFIXES = ("Nt", "Zw")

KERNEL_MODULES = frozenset(
    {
        "ntoskrnl.exe",
        "hal.dll",
        "fltmgr.sys",
        "ndis.sys",
        "fwpkclnt.sys",
        "wdmsec.sys",
        "cng.sys",
        "ksecdd.sys",
        "tm.sys",
    }
)

PE_EXTENSIONS_DEFAULT = {".exe", ".dll", ".sys"}


def classify_import(module_name: str, function_name: str) -> str:
    mod = (module_name or "").lower().strip()
    fn = function_name or ""
    if mod in KERNEL_MODULES:
        return "Kernel API"
    if mod == "ntdll.dll":
        if any(fn.startswith(prefix) for prefix in NATIVE_API_PREFIXES):
            return "Native API"
        if fn.startswith("Rtl") or fn.startswith("Ldr"):
            return "NTDLL Runtime/Internal API"
    if mod.endswith(".dll"):
        return "Win32/User-mode API"
    if mod.endswith(".sys"):
        return "Driver/Kernel Dependency"
    return "Unknown"


def _binary_type_from_path(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".exe":
        return "EXE"
    if suf == ".dll":
        return "DLL"
    if suf == ".sys":
        return "SYS"
    return suf.upper().lstrip(".") or "UNKNOWN"


def _safe_decode(data: bytes | None, fallback: str = "") -> str:
    if data is None:
        return fallback
    try:
        return data.decode("utf-8", errors="replace").rstrip("\x00")
    except Exception:
        return fallback


def analyze_pe(file_path: str) -> dict[str, Any]:
    path = Path(file_path).expanduser()
    if not path.is_file():
        return {"error": "not_found", "message": str(path)}

    imports_list: list[dict[str, Any]] = []
    exports_list: list[dict[str, Any]] = []

    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            try:
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    ]
                )
            except Exception:
                pass

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = _safe_decode(entry.dll, "").strip() or "UNKNOWN_DLL"
                    for imp in entry.imports:
                        if getattr(imp, "import_by_ord", False):
                            raw_name = ""
                            ordinal_val = imp.ordinal if imp.ordinal is not None else ""
                        else:
                            raw_name = _safe_decode(imp.name, "") if imp.name else ""
                            ordinal_val = ""
                        display_name = raw_name if raw_name else "(by ordinal)"
                        cat = classify_import(dll_name, raw_name)
                        imports_list.append(
                            {
                                "imported_module": dll_name,
                                "function_name": display_name,
                                "ordinal": "" if ordinal_val == "" else str(ordinal_val),
                                "category": cat,
                                "evidence_source": "Static PE import table",
                            }
                        )

            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                exp = pe.DIRECTORY_ENTRY_EXPORT
                for sym in exp.symbols:
                    name_raw = sym.name
                    if isinstance(name_raw, bytes):
                        name = _safe_decode(name_raw, "")
                    elif name_raw is None:
                        name = ""
                    else:
                        name = str(name_raw)
                    ord_ = sym.ordinal if sym.ordinal is not None else ""
                    exports_list.append(
                        {
                            "export_name": name if name else "(ordinal only)",
                            "ordinal": "" if ord_ == "" else str(ord_),
                            "evidence_source": "Static PE export table",
                        }
                    )
        finally:
            pe.close()
    except pefile.PEFormatError as e:
        return {"error": "pe_format", "message": str(e)}
    except OSError as e:
        return {"error": "os_error", "message": str(e)}

    cats = Counter(row["category"] for row in imports_list)
    summary = {
        "import_categories": dict(cats),
        "import_count": len(imports_list),
        "export_count": len(exports_list),
    }

    return {
        "binary_path": str(path.resolve()),
        "binary_name": path.name,
        "binary_type": _binary_type_from_path(path),
        "imports": imports_list,
        "exports": exports_list,
        "summary": summary,
    }


def find_pe_files(directory: str, extensions: list[str] | None = None) -> dict[str, Any]:
    root = Path(directory).expanduser()
    if not root.is_dir():
        return {"error": "not_a_directory", "message": str(root), "files": []}

    exts = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in (extensions or [])}
    if not exts:
        exts = set(PE_EXTENSIONS_DEFAULT)

    files: list[dict[str, Any]] = []
    warnings: list[str] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            suf = Path(name).suffix.lower()
            if suf not in exts:
                continue
            fp = Path(dirpath) / name
            try:
                st = fp.stat()
                kind = _binary_type_from_path(fp)
                files.append(
                    {
                        "path": str(fp.resolve()),
                        "name": name,
                        "size": st.st_size,
                        "type": kind,
                    }
                )
            except OSError as e:
                warnings.append(f"{fp}: {e}")

    return {"files": files, "warnings": warnings}
