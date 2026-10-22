#!/usr/bin/env python3
"""Write the PE quirk fixtures: small PE32 images, each stating one thing as the Windows loader reads it.

pe_absolute.exe     a COFF symbol table with an absolute record (SectionNumber -1), whose Value is no address
pe_rounded.exe      PointerToRawData 0x205 (read from 0x200), raw data read up to FileAlignment, zeros past VirtualSize
pe_nullvirt.exe     VirtualSize 0, which means SizeOfRawData
pe_header_entry.exe an EXE whose AddressOfEntryPoint is 0: the loader starts it at its headers
pe_dll_noentry.dll  a DLL whose AddressOfEntryPoint is 0: it has no DllMain
pe_flat.exe         SectionAlignment 4 and no sections: the file is mapped as it lies, entry in the headers
pe_export_wrap.dll  a PE32 export at RVA 0xffffffff above base 0x1000000, which wraps to 0xffffff
pe_export_ordinals.dll  two ordinal-only exports, NumberOfNames 0 beside a stale AddressOfNames and no ordinal table
pe_delay_vc6.exe    a VC6 delay-load descriptor (dlattrRva clear), whose fields are addresses
"""

import pathlib
import struct

BASE = 0x400000


def pe32(
    sections,
    entry,
    symbols=(),
    base=BASE,
    section_alignment=0x1000,
    file_alignment=0x200,
    dll=False,
    directories=None,
    image_size=None,
    tail=(),
):
    """A PE32 image: `sections` as (name, rva, VirtualSize, PointerToRawData, SizeOfRawData, flags, bytes),
    `directories` as {index: (rva, size)}, `tail` as (file offset, bytes) written last."""
    end = max([0x200] + [raw + len(data) for _, _, _, raw, _, _, data in sections] + [o + len(b) for o, b in tail])
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
    if image_size is None:
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
    for index, (rva, size) in (directories or {}).items():
        struct.pack_into("<II", out, optional + 96 + 8 * index, rva, size)
    headers = optional + 0xE0
    for index, (name, rva, vsize, raw, raw_size, flags, data) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", out, headers + index * 40, name, vsize, rva, raw_size, raw, 0, 0, 0, 0, flags)
        out[raw : raw + len(data)] = data
    for offset, data in tail:
        out[offset : offset + len(data)] = data
    out[table : table + len(records)] = records
    if symbols:
        struct.pack_into("<I", out, table + len(records), 4)  # an empty string table
    return bytes(out)


CODE = 0x60000020
DATA = 0xC0000040
RET = b"\xc3" + b"\x90" * 15


def absolute():
    return pe32(
        [(b".text", 0x1000, 0x10, 0x200, 0x200, CODE, RET)],
        entry=0x1000,
        symbols=[(b"_start", 0, 1), (b"__stack", 0x1000, -1)],
    )


def rounded():
    # 0xaa at 0x200, where the loader reads; 0xbb at 0x205, where the header points; 0xcc at 0x300, past
    # the stated raw end (0x215) but inside the FileAlignment read; 0xdd at 0x390, past VirtualSize 0x180.
    return pe32(
        [(b".text", 0x1000, 0x180, 0x205, 0x10, CODE, b"")],
        entry=0x1000,
        tail=[(0x200, b"\xaa"), (0x205, b"\xbb"), (0x300, b"\xcc"), (0x390, b"\xdd"), (0x3FF, b"\0")],
    )


def nullvirt():
    return pe32([(b".text", 0x1000, 0, 0x200, 0x200, CODE, RET)], entry=0x1000)


def header_entry():
    return pe32([(b".text", 0x1000, 0x10, 0x200, 0x200, CODE, RET)], entry=0)


def dll_noentry():
    return pe32([(b".text", 0x1000, 0x10, 0x200, 0x200, CODE, RET)], entry=0, dll=True, base=0x1000000)


def flat():
    return pe32([], entry=0x180, section_alignment=4, file_alignment=4, image_size=0x200, tail=[(0x180, RET)])


def export_wrap():
    # An export directory at RVA 0x1000 publishing one function at RVA 0xffffffff, named `w`.
    edata = 0x1000
    directory = struct.pack(
        "<IIHHIIIIIII", 0, 0, 0, 0, edata + 0x40, 1, 1, 1, edata + 0x28, edata + 0x2C, edata + 0x30
    )
    body = bytearray(0x50)
    body[: len(directory)] = directory
    struct.pack_into("<IIH", body, 0x28, 0xFFFFFFFF, edata + 0x38, 0)
    body[0x38:0x3A] = b"w\0"
    body[0x40:0x46] = b"w.dll\0"
    return pe32(
        [(b".edata", edata, 0x50, 0x200, 0x200, DATA, bytes(body))],
        entry=0,
        dll=True,
        base=0x1000000,
        directories={0: (edata, 0x50)},
    )


def export_ordinals():
    # Two functions, NumberOfNames 0, a stale AddressOfNames and AddressOfNameOrdinals 0.
    edata = 0x1000
    directory = struct.pack(
        "<IIHHIIIIIII", 0, 0, 0, 0, edata + 0x40, 5, 2, 0, edata + 0x28, edata + 0x30, 0
    )
    body = bytearray(0x50)
    body[: len(directory)] = directory
    struct.pack_into("<II", body, 0x28, 0x2000, 0x2010)
    body[0x40:0x46] = b"o.dll\0"
    return pe32(
        [(b".edata", edata, 0x50, 0x200, 0x200, DATA, bytes(body))],
        entry=0,
        dll=True,
        directories={0: (edata, 0x50)},
    )


def delay_vc6():
    # One VC6 descriptor: every field an address. Its table at 0x1000, the IAT at 0x1080, the name
    # table at 0x1090, the hint/name at 0x10a0, the DLL's name at 0x10c0.
    data = 0x1000
    body = bytearray(0x100)
    struct.pack_into("<8I", body, 0, 0, BASE + data + 0xC0, 0, BASE + data + 0x80, BASE + data + 0x90, 0, 0, 0)
    struct.pack_into("<II", body, 0x80, BASE + data + 0xA0, 0)
    struct.pack_into("<II", body, 0x90, BASE + data + 0xA0, 0)
    body[0xA2:0xA8] = b"later\0"
    body[0xC0:0xC9] = b"late.dll\0"
    return pe32([(b".data", data, 0x100, 0x200, 0x200, DATA, bytes(body))], entry=0, directories={13: (data, 0x40)})


if __name__ == "__main__":
    here = pathlib.Path(__file__).parent
    for name, build in [
        ("pe_absolute.exe", absolute),
        ("pe_rounded.exe", rounded),
        ("pe_nullvirt.exe", nullvirt),
        ("pe_header_entry.exe", header_entry),
        ("pe_dll_noentry.dll", dll_noentry),
        ("pe_flat.exe", flat),
        ("pe_export_wrap.dll", export_wrap),
        ("pe_export_ordinals.dll", export_ordinals),
        ("pe_delay_vc6.exe", delay_vc6),
    ]:
        (here / name).write_bytes(build())
        print("wrote", name)
