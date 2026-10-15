#!/usr/bin/env python3
"""Write the cold-fragment fixture: one function, the part of it GCC splits out, and a leaf.

GCC moves a function's unlikely tail into `.text.unlikely` as `f.cold` and
gives it an FDE of its own whose first row is the parent's state at the jump
(`.cfi_def_cfa_offset 16; .cfi_offset rbx, -16`), not the state a call leaves.
This is the smallest x86-64 executable whose `.eh_frame` says so: `f` jumps to
its fragment, the fragment's FDE starts mid-frame, and `g` is a plain leaf.
"""

import pathlib
import struct

TEXT_ADDR = 0x401000
F, COLD, G = TEXT_ADDR, TEXT_ADDR + 0x10, TEXT_ADDR + 0x20

text = bytearray(b"\xcc" * 0x30)
# f: push rbx; test edi, edi; je f.cold; pop rbx; ret
text[0x00:0x0B] = bytes([0x53, 0x85, 0xFF, 0x0F, 0x84, 0x07, 0, 0, 0, 0x5B, 0xC3])
# f.cold: ud2
text[0x10:0x12] = bytes([0x0F, 0x0B])
# g: ret
text[0x20:0x21] = bytes([0xC3])

EH_ADDR = 0x402000


def padded(body):
    """A CIE or FDE: its length, then `body` padded with DW_CFA_nop to a multiple of 8."""
    body = body + b"\0" * (-(len(body) + 4) % 8)
    return struct.pack("<I", len(body)) + body


# CIE: version 1, "zR", code 1, data -8, return address r16, pointers pcrel sdata4;
# def_cfa rsp+8, r16 at cfa-8: the state a call leaves.
cie = padded(
    struct.pack("<I", 0)
    + bytes([1])
    + b"zR\0"
    + bytes([1, 0x78, 0x10, 1, 0x1B])
    + bytes([0x0C, 0x07, 0x08, 0x90, 0x01])
)


def fde(offset, start, size, instructions):
    """An FDE at `offset` in the section, describing `start..start+size`."""
    pointer = offset + 4  # the CIE pointer counts back from its own field
    begin = EH_ADDR + offset + 8  # pc_begin is relative to its own field
    return padded(
        struct.pack("<Iii", pointer, start - begin, size) + bytes([0]) + instructions
    )


eh_frame = bytearray(cie)
# f: advance 1; cfa rsp+16; rbx at cfa-16; advance 9; cfa rsp+8.
eh_frame += fde(len(eh_frame), F, 0x0B, bytes([0x41, 0x0E, 0x10, 0x83, 0x02, 0x49, 0x0E, 0x08]))
# f.cold: entered with f's frame, before any advance.
eh_frame += fde(len(eh_frame), COLD, 0x02, bytes([0x0E, 0x10, 0x83, 0x02]))
# g: no instructions, so the CIE's state holds.
eh_frame += fde(len(eh_frame), G, 0x01, b"")
eh_frame += struct.pack("<I", 0)

names = b"\0.text\0.eh_frame\0.shstrtab\0"
name = {n: names.index(b"\0" + n.encode() + b"\0") + 1 for n in (".text", ".eh_frame", ".shstrtab")}

text_off = 0x1000
eh_off = 0x2000
shstrtab_off = eh_off + len(eh_frame)
shoff = (shstrtab_off + len(names) + 7) & ~7


def header(nm, kind, flags, addr, off, size, align):
    return struct.pack("<IIQQQQIIQQ", nm, kind, flags, addr, off, size, 0, 0, align, 0)


sections = b"".join(
    [
        header(0, 0, 0, 0, 0, 0, 0),
        header(name[".text"], 1, 0x6, TEXT_ADDR, text_off, len(text), 16),
        header(name[".eh_frame"], 1, 0x2, EH_ADDR, eh_off, len(eh_frame), 8),
        header(name[".shstrtab"], 3, 0, 0, shstrtab_off, len(names), 1),
    ]
)

# One PT_LOAD maps the file from offset 0 at 0x400000, so both sections are placed.
phoff = 0x40
segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, shstrtab_off, shstrtab_off, 0x1000)

elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8)
elf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, F, phoff, shoff, 0, 64, 56, 1, 64, 4, 3)
elf += segment
elf += b"\0" * (text_off - len(elf))
elf += text
elf += b"\0" * (eh_off - len(elf))
elf += eh_frame + names
elf += b"\0" * (shoff - len(elf))
elf += sections

pathlib.Path(__file__).with_name("cold_fragment.elf").write_bytes(bytes(elf))
print("wrote cold_fragment.elf", len(elf), "bytes")
