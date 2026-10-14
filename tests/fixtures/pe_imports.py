#!/usr/bin/env python3
"""Writes pe_imports_x64.dll: a PE32+ DLL whose code calls through its import address table.

KERNEL32.dll's ExitProcess by name and its ordinal 7, and one export, start_here, at the entry.
The bytes are laid out here by hand so every field the tests assert is visible.
"""

import pathlib
import struct

BASE = 0x1_4000_0000
TEXT, IDATA, EDATA = 0x1000, 0x2000, 0x3000
RAW = {TEXT: 0x400, IDATA: 0x600, EDATA: 0x800}


def image():
    out = bytearray(0xA00)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x80)
    out[0x80:0x84] = b"PE\0\0"
    # COFF: x86-64, 3 sections, a PE32+ optional header, an executable DLL.
    struct.pack_into("<HHIIIHH", out, 0x84, 0x8664, 3, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        out,
        optional,
        0x20B, 14, 0, 0x200, 0x400, 0, TEXT, TEXT, BASE, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0, 0, 0x4000, 0x400, 0, 3, 0x160,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = optional + 112
    struct.pack_into("<II", out, directories + 0 * 8, EDATA, 0x60)
    struct.pack_into("<II", out, directories + 1 * 8, IDATA, 40)
    headers = directories + 16 * 8
    for index, (name, rva, flags) in enumerate(
        [(b".text", TEXT, 0x60000020), (b".idata", IDATA, 0xC0000040), (b".edata", EDATA, 0x40000040)]
    ):
        struct.pack_into(
            "<8sIIIIIIHHI", out, headers + index * 40, name, 0x200, rva, 0x200, RAW[rva], 0, 0, 0, 0, flags
        )

    def at(rva):
        section = max(start for start in RAW if start <= rva)
        return RAW[section] + rva - section

    # .text: call [rip + slot]; ret.
    slot = IDATA + 0x60
    struct.pack_into("<BBi", out, at(TEXT), 0xFF, 0x15, slot - (TEXT + 6))
    out[at(TEXT) + 6] = 0xC3
    # .idata: one descriptor and the null one, its lookup and address tables, the names.
    struct.pack_into("<IIIII", out, at(IDATA), IDATA + 0x40, 0, 0, IDATA + 0x80, slot)
    for table in (IDATA + 0x40, slot):
        struct.pack_into("<QQQ", out, at(table), IDATA + 0x90, (1 << 63) | 7, 0)
    out[at(IDATA + 0x80) : at(IDATA + 0x80) + 13] = b"KERNEL32.dll\0"
    struct.pack_into("<H12s", out, at(IDATA + 0x90), 0, b"ExitProcess\0")
    # .edata: one function, start_here, at the entry.
    struct.pack_into(
        "<IIHHIIIIIII", out, at(EDATA), 0, 0, 0, 0, EDATA + 0x50, 1, 1, 1, EDATA + 0x28, EDATA + 0x2C, EDATA + 0x30
    )
    struct.pack_into("<IIH", out, at(EDATA + 0x28), TEXT, EDATA + 0x40, 0)
    out[at(EDATA + 0x40) : at(EDATA + 0x40) + 11] = b"start_here\0"
    out[at(EDATA + 0x50) : at(EDATA + 0x50) + 12] = b"fixture.dll\0"
    return bytes(out)


if __name__ == "__main__":
    pathlib.Path(__file__).with_name("pe_imports_x64.dll").write_bytes(image())
