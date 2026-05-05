"""Tests for PE analysis classification logic."""

from procmon_mcp.core.pe_analysis import (
    KERNEL_MODULES,
    classify_import,
)


def test_classify_kernel_api():
    assert classify_import("ntoskrnl.exe", "IoCreateDevice") == "Kernel API"


def test_classify_kernel_api_hal():
    assert classify_import("hal.dll", "HalGetBusData") == "Kernel API"


def test_classify_native_api_nt():
    assert classify_import("ntdll.dll", "NtCreateFile") == "Native API"


def test_classify_native_api_zw():
    assert classify_import("ntdll.dll", "ZwQuerySystemInformation") == "Native API"


def test_classify_ntdll_rtl():
    assert classify_import("ntdll.dll", "RtlInitUnicodeString") == "NTDLL Runtime/Internal API"


def test_classify_ntdll_ldr():
    assert classify_import("ntdll.dll", "LdrLoadDll") == "NTDLL Runtime/Internal API"


def test_classify_win32():
    assert classify_import("kernel32.dll", "CreateFileW") == "Win32/User-mode API"


def test_classify_driver():
    assert classify_import("somedriver.sys", "SomeFunc") == "Driver/Kernel Dependency"


def test_classify_unknown():
    assert classify_import("something", "func") == "Unknown"


def test_kernel_modules_contains_expected():
    for mod in ("ntoskrnl.exe", "hal.dll", "fltmgr.sys", "ndis.sys"):
        assert mod in KERNEL_MODULES
