#!/usr/bin/env python3
"""Write the PE quirk fixtures: small PE32 images, each stating one thing as the Windows loader reads it.

pe_absolute.exe  a COFF symbol table with an absolute record (SectionNumber -1), whose Value is no address
"""

import pathlib
import struct

BASE = 0x400000


def pe32(sections, entry, symbols=(), base=BASE, section_alignment=0x1000, file_alignment=0x200, dll=False):
    """A PE32 image: `sections` as (name, rva, VirtualSize, PointerToRawData, SizeOfRawData, flags, bytes)."""
    end = max([0x200] + [raw + len(data) for _, _, _, raw, _, _, data in sections])
    table = end
    records = b"".join(struct.pack("<8sIhHBB", name, value, number, 0, 2, 0) for name, value, number in symbols)
    out = bytearray(end + len(records) + (4 if symbols else 0))
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    out[0x40:0x44] = b"PE\0\0"
    characteristics = 0x2102 if dll else 0x102
    struct.pack_into(
        "<HHIIIHH", out, 0x44, 0x14C, len(sections), 0, table if symbols else 0, len(symbols), 0xE0, characteristics
    )
    optional = 0x58
    image_size = max(rva + max(vsize, raw_size) for _, rva, vsize, _, raw_size, _, _ in sections)
    image_size = -(-image_size // section_alignment) * section_alignment
    struct.pack_into(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        out,
        optional,
        0x10B, 14, 0, 0, 0, 0, entry, 0x1000, 0, base, section_alignment, file_alignment,
        4, 0, 0, 0, 4, 0, 0, image_size, 0x200, 0, 2, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    headers = optional + 0xE0
    for index, (name, rva, vsize, raw, raw_size, flags, data) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", out, headers + index * 40, name, vsize, rva, raw_size, raw, 0, 0, 0, 0, flags)
        out[raw : raw + len(data)] = data
    out[table : table + len(records)] = records
    if symbols:
        struct.pack_into("<I", out, table + len(records), 4)  # an empty string table
    return bytes(out)


CODE = 0x60000020
RET = b"\xc3" + b"\x90" * 15


def absolute():
    return pe32(
        [(b".text", 0x1000, 0x10, 0x200, 0x200, CODE, RET)],
        entry=0x1000,
        symbols=[(b"_start", 0, 1), (b"__stack", 0x1000, -1)],
    )


if __name__ == "__main__":
    here = pathlib.Path(__file__).parent
    for name, build in [("pe_absolute.exe", absolute)]:
        (here / name).write_bytes(build())
        print("wrote", name)
