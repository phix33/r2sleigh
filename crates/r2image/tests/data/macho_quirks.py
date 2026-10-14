#!/usr/bin/env python3
"""Write the Mach-O quirk fixtures: small images, each stating one thing as dyld or the linker reads it.

macho_indirect   an executable whose symbol table holds an N_INDR alias, whose n_value is a string index
"""

import pathlib
import struct

MH_EXECUTE = 2
TEXT = 0x100000000
CODE = b"\xc3" + b"\x90" * 15  # ret


def segment64(name, vmaddr, vmsize, fileoff, filesize, prot, sections):
    """An LC_SEGMENT_64 and its sections, each (sectname, addr, size, offset, flags)."""
    body = struct.pack(
        "<II16sQQQQiiII", 0x19, 72 + 80 * len(sections), name, vmaddr, vmsize, fileoff, filesize, prot, prot,
        len(sections), 0,
    )
    for sectname, addr, size, offset, flags in sections:
        body += struct.pack("<16s16sQQIIIIIIII", sectname, name, addr, size, offset, 0, 0, 0, flags, 0, 0, 0)
    return body


def macho64(filetype, commands, tail):
    """A 64-bit x86-64 Mach-O: its header, `commands`, then `tail` placed at its file offsets."""
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, filetype, len(commands), sum(map(len, commands)), 0, 0)
    out = bytearray(header + b"".join(commands))
    for offset, data in tail:
        out += bytes(max(0, offset - len(out)))
        out[offset : offset + len(data)] = data
    return bytes(out)


def indirect():
    strings = b"\0_start\0_alias\0_target\0"
    N_SECT, N_EXT, N_INDR = 0xE, 0x1, 0xA
    symbols = b"".join(
        [
            struct.pack("<IBBHQ", strings.index(b"_start"), N_SECT | N_EXT, 1, 0, TEXT + 0x1000),
            struct.pack("<IBBHQ", strings.index(b"_alias"), N_INDR | N_EXT, 0, 0, strings.index(b"_target")),
        ]
    )
    text = segment64(b"__TEXT", TEXT, 0x2000, 0, 0x1010, 5, [(b"__text", TEXT + 0x1000, len(CODE), 0x1000, 0x80000400)])
    symtab = struct.pack("<IIIIII", 0x2, 24, 0x1010, 2, 0x1030, len(strings))
    main = struct.pack("<IIQQ", 0x80000028, 24, 0x1000, 0)
    return macho64(MH_EXECUTE, [text, symtab, main], [(0x1000, CODE), (0x1010, symbols), (0x1030, strings)])


if __name__ == "__main__":
    here = pathlib.Path(__file__).parent
    for name, build in [("macho_indirect", indirect)]:
        (here / name).write_bytes(build())
        print("wrote", name)
