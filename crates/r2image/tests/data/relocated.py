#!/usr/bin/env python3
"""Write the relocated-object fixture: an x86-64 ET_REL whose code, data and frames carry relocations.

Every field a static link fills is zero in the file, so a reader that decodes
the bytes as they are calls the next instruction and reads its own code. The
records say what each field is:

  .text  f:  call ext                  R_X86_64_PLT32 ext - 4         (an import)
             call g                    R_X86_64_PLT32 g - 4           (a local function)
             lea rdi, [rip + .data+8]  R_X86_64_PC32 .data + 4        (a section symbol)
             mov rax, [rip + ext@GOT]  R_X86_64_REX_GOTPCRELX ext - 4 (a table slot)
             mov eax, [rip + counter]  R_X86_64_PC32 counter - 4      (a .bss object)
             ret
         g:  ret
  .data      .quad g                   R_X86_64_64 g
  .symtab    `shared`, a common symbol of four bytes at an alignment of sixteen.
  .eh_frame  one CIE and three FDEs, whose pc_begin fields are R_X86_64_PC32
             against .text + 0 (f), .text + 0x1f (g) and the undefined ext.
"""

import pathlib
import struct

TEXT = bytes(
    [0xE8, 0, 0, 0, 0]  # call ext
    + [0xE8, 0, 0, 0, 0]  # call g
    + [0x48, 0x8D, 0x3D, 0, 0, 0, 0]  # lea rdi, [rip + disp32]
    + [0x48, 0x8B, 0x05, 0, 0, 0, 0]  # mov rax, [rip + disp32]
    + [0x8B, 0x05, 0, 0, 0, 0]  # mov eax, [rip + disp32]
    + [0xC3]  # ret
    + [0xC3]  # g: ret
)
assert len(TEXT) == 0x20
DATA = bytes(8) + struct.pack("<Q", 0x2A)

# CIE: version 1, "zR", code 1, data -8, return column 16, FDE pointers pcrel|sdata4;
# CFA = rsp + 8, return address at CFA - 8.
CIE = struct.pack("<II", 0x14, 0) + bytes(
    [1, ord("z"), ord("R"), 0, 1, 0x78, 0x10, 1, 0x1B, 0x0C, 7, 8, 0x90, 1, 0, 0]
)


def fde(at, length):
    """One FDE at offset `at` of the section: its CIE pointer, a zero pc_begin, its range, no augmentation."""
    return struct.pack("<IiiiB", 0x10, at + 4, 0, length, 0) + bytes(3)


EH = CIE + fde(0x18, 0x1F) + fde(0x2C, 1) + fde(0x40, 4) + bytes(4)
assert len(EH) == 0x58

# Symbols: locals first. Index 1 and 2 are the section symbols of .text and .data.
SHN = {".text": 1, ".data": 2, ".bss": 3, ".eh_frame": 4}
strtab = b"\0g\0counter\0f\0ext\0shared\0"


def name(text):
    return strtab.index(b"\0" + text + b"\0") + 1


LOCAL, GLOBAL = 0, 1
NOTYPE, OBJECT, FUNC, SECTION = 0, 1, 2, 3
symbols = [
    (0, 0, 0, 0, 0),
    (0, (LOCAL << 4) | SECTION, SHN[".text"], 0, 0),
    (0, (LOCAL << 4) | SECTION, SHN[".data"], 0, 0),
    (name(b"g"), (LOCAL << 4) | FUNC, SHN[".text"], 0x1F, 1),
    (name(b"counter"), (LOCAL << 4) | OBJECT, SHN[".bss"], 0, 8),
    (name(b"f"), (GLOBAL << 4) | FUNC, SHN[".text"], 0, 0x1F),
    (name(b"ext"), (GLOBAL << 4) | NOTYPE, 0, 0, 0),
    # A common symbol: its value is its alignment, and the static linker allocates it.
    (name(b"shared"), (GLOBAL << 4) | OBJECT, 0xFFF2, 16, 4),
]
FIRST_GLOBAL = 5
symtab = b"".join(
    struct.pack("<IBBHQQ", n, info, 0, shndx, value, size)
    for n, info, shndx, value, size in symbols
)

PC32, PLT32, ABS64, REX_GOTPCRELX = 2, 4, 1, 42


def rela(offset, symbol, kind, addend):
    return struct.pack("<QQq", offset, (symbol << 32) | kind, addend)


rela_text = b"".join(
    [
        rela(0x01, 6, PLT32, -4),
        rela(0x06, 3, PLT32, -4),
        rela(0x0D, 2, PC32, 4),
        rela(0x14, 6, REX_GOTPCRELX, -4),
        rela(0x1A, 4, PC32, -4),
    ]
)
rela_data = rela(0, 3, ABS64, 0)
rela_eh = b"".join([rela(0x20, 1, PC32, 0), rela(0x34, 1, PC32, 0x1F), rela(0x48, 6, PC32, 0)])

names = b"\0.text\0.data\0.bss\0.eh_frame\0.rela.text\0.rela.data\0.rela.eh_frame\0.symtab\0.strtab\0.shstrtab\0"


def sh_name(text):
    return names.index(b"\0" + text.encode() + b"\0") + 1


def align(value, to):
    return (value + to - 1) // to * to


layout = {}
at = 0x40
for key, blob, alignment in [
    (".text", TEXT, 16),
    (".data", DATA, 8),
    (".eh_frame", EH, 8),
    (".rela.text", rela_text, 8),
    (".rela.data", rela_data, 8),
    (".rela.eh_frame", rela_eh, 8),
    (".symtab", symtab, 8),
    (".strtab", strtab, 1),
    (".shstrtab", names, 1),
]:
    at = align(at, alignment)
    layout[key] = (at, blob)
    at += len(blob)
shoff = align(at, 8)


def header(key, kind, flags, link=0, info=0, alignment=1, entsize=0, size=None, offset=None):
    off, blob = layout.get(key, (offset, b""))
    return struct.pack(
        "<IIQQQQIIQQ",
        sh_name(key),
        kind,
        flags,
        0,
        off,
        len(blob) if size is None else size,
        link,
        info,
        alignment,
        entsize,
    )


SYMTAB_INDEX = 8
sections = [
    bytes(64),
    header(".text", 1, 0x6, alignment=16),  # 1
    header(".data", 1, 0x3, alignment=8),  # 2
    header(".bss", 8, 0x3, alignment=8, size=8, offset=layout[".rela.text"][0]),  # 3
    header(".eh_frame", 1, 0x2, alignment=8),  # 4
    header(".rela.text", 4, 0x40, SYMTAB_INDEX, 1, 8, 24),  # 5
    header(".rela.data", 4, 0x40, SYMTAB_INDEX, 2, 8, 24),  # 6
    header(".rela.eh_frame", 4, 0x40, SYMTAB_INDEX, 4, 8, 24),  # 7
    header(".symtab", 2, 0, 9, FIRST_GLOBAL, 8, 24),  # 8
    header(".strtab", 3, 0),  # 9
    header(".shstrtab", 3, 0),  # 10
]

elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + bytes(8))
elf += struct.pack("<HHIQQQIHHHHHH", 1, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), 10)
for key in layout:
    off, blob = layout[key]
    elf += bytes(off - len(elf))
    elf += blob
elf += bytes(shoff - len(elf))
elf += b"".join(sections)

out = pathlib.Path(__file__).with_name("relocated.elf")
out.write_bytes(bytes(elf))
print("wrote", out.name, len(elf), "bytes")
