#!/usr/bin/env python3
"""Write the Mach-O quirk fixtures: small images, each stating one thing as dyld or the linker reads it.

macho_indirect   an executable whose symbol table holds an N_INDR alias, whose n_value is a string index
macho_object     an MH_OBJECT whose __text states addr 0 at file 0x100, and a symbol at its n_value 4
macho_thumb_main an ARMv7 executable whose LC_MAIN entryoff is a file offset, odd for Thumb, into __TEXT at 0x1000;
                 its _main is stated Thumb by n_desc, and its function start by the low bit
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


def obj():
    MH_OBJECT = 1
    strings = b"\0_f\0"
    symbol = struct.pack("<IBBHQ", 1, 0xE | 0x1, 1, 0, 4)
    segment = segment64(b"", 0, len(CODE), 0x100, len(CODE), 7, [(b"__text", 0, len(CODE), 0x100, 0x80000400)])
    symtab = struct.pack("<IIIIII", 0x2, 24, 0x110, 1, 0x120, len(strings))
    return macho64(MH_OBJECT, [segment, symtab], [(0x100, CODE), (0x110, symbol), (0x120, strings)])


def thumb_main():
    # __text runs over both readings of entryoff 0x1801: the address 0x2800 and, misread, 0x1800.
    code = bytearray(0x2000)
    code[0x1700:0x1704] = b"\x80\xb5\x6f\x46"  # push {r7, lr}; mov r7, sp, at 0x2800
    sections = struct.pack("<16s16sIIIIIIIII", b"__text", b"__TEXT", 0x1100, len(code), 0x100, 1, 0, 0, 0x80000400, 0, 0)
    text = struct.pack("<II16sIIIIiiII", 0x1, 56 + 68, b"__TEXT", 0x1000, 0x3000, 0, 0x2100, 5, 5, 1, 0) + sections
    main = struct.pack("<IIQQ", 0x80000028, 24, 0x1801, 0)
    # _main at 0x2800, Thumb by N_ARM_THUMB_DEF; a function start ld64 writes with the low bit, 0x1801 past __TEXT.
    strings = b"\0_main\0"
    symbols = struct.pack("<IBBHI", 1, 0xE | 0x1, 1, 0x0008, 0x2800)
    starts = bytes([0x81, 0x30, 0, 0])
    symtab = struct.pack("<IIIIII", 0x2, 24, 0x2100, 1, 0x2110, len(strings))
    function_starts = struct.pack("<IIII", 0x26, 16, 0x2120, len(starts))
    commands = [text, main, symtab, function_starts]
    header = struct.pack("<IiiIIII", 0xFEEDFACE, 12, 9, MH_EXECUTE, len(commands), sum(map(len, commands)), 0)
    out = bytearray(header + b"".join(commands))
    out += bytes(0x100 - len(out)) + code
    out += symbols + bytes(0x2110 - 0x2100 - len(symbols)) + strings
    out += bytes(0x2120 - len(out)) + starts
    return bytes(out)


if __name__ == "__main__":
    here = pathlib.Path(__file__).parent
    for name, build in [("macho_indirect", indirect), ("macho_object", obj), ("macho_thumb_main", thumb_main)]:
        (here / name).write_bytes(build())
        print("wrote", name)
