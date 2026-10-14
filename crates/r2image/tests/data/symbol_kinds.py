#!/usr/bin/env python3
"""Write the symbol-kinds fixture: an ELF object whose symbols carry the types and bindings readelf names.

One `.data` section holds `unique`, `STB_GNU_UNIQUE`, which the GNU ABI (EI_OSABI 3) defines; one
`.tbss` holds `counter`, `STT_TLS`, whose value is an offset into the thread's block.
"""

import pathlib
import struct

DATA = bytes(8)

names = b"\0.data\0.tbss\0.symtab\0.strtab\0.shstrtab\0"
offset = {
    name: names.index(b"\0" + name.encode() + b"\0") + 1
    for name in (".data", ".tbss", ".symtab", ".strtab", ".shstrtab")
}

STB_GLOBAL, STB_GNU_UNIQUE = 1, 10
STT_OBJECT, STT_TLS = 1, 6
strtab = b"\0unique\0counter\0"
symbols = [
    (0, 0, 0, 0),  # the null symbol
    (strtab.index(b"\0unique\0") + 1, (STB_GNU_UNIQUE << 4) | STT_OBJECT, 1, 0),
    (strtab.index(b"\0counter\0") + 1, (STB_GLOBAL << 4) | STT_TLS, 2, 4),
]
symtab = b"".join(
    struct.pack("<IBBHQQ", name, info, 0, shndx, value, 4) for name, info, shndx, value in symbols
)

data_off = 0x40
symtab_off = data_off + len(DATA)
strtab_off = symtab_off + len(symtab)
shstrtab_off = strtab_off + len(strtab)
shoff = shstrtab_off + len(names)


def header(name, kind, flags, off, size, link, info, align, entsize):
    return struct.pack("<IIQQQQIIQQ", name, kind, flags, 0, off, size, link, info, align, entsize)


SHF_WRITE_ALLOC, SHF_TLS = 0x3, 0x400
sections = b"".join(
    [
        header(0, 0, 0, 0, 0, 0, 0, 0, 0),
        header(offset[".data"], 1, SHF_WRITE_ALLOC, data_off, len(DATA), 0, 0, 8, 0),
        header(offset[".tbss"], 8, SHF_WRITE_ALLOC | SHF_TLS, 0, 8, 0, 0, 8, 0),
        # Every symbol is global, so the first non-local is the first after the null one.
        header(offset[".symtab"], 2, 0, symtab_off, len(symtab), 4, 1, 8, 24),
        header(offset[".strtab"], 3, 0, strtab_off, len(strtab), 0, 0, 1, 0),
        header(offset[".shstrtab"], 3, 0, shstrtab_off, len(names), 0, 0, 1, 0),
    ]
)

ELFOSABI_GNU = 3
elf = bytearray(b"\x7fELF\x02\x01\x01" + bytes([ELFOSABI_GNU]) + b"\0" * 8)
elf += struct.pack("<HHIQQQIHHHHHH", 1, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 6, 5)
elf += b"\0" * (data_off - len(elf))
elf += DATA + symtab + strtab + names + sections

pathlib.Path(__file__).with_name("symbol_kinds.elf").write_bytes(bytes(elf))
print("wrote symbol_kinds.elf", len(elf), "bytes")
