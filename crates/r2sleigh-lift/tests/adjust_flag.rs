//! x86's arithmetic sets AF to the carry or borrow out of bit 3 (Intel SDM Vol. 1, 3.4.3.1;
//! Vol. 2: ADD, ADC, SUB, SBB, CMP, INC, DEC, NEG, XADD, CMPXCHG), run through `r2il::eval`.
#![cfg(feature = "x86")]

mod x86_machine;

use x86_machine::{Machine, low};

/// Operands around each nibble and sign boundary.
const VALUES: [u128; 10] = [
    0,
    1,
    0x8,
    0xf,
    0x10,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fff0,
    0xffff_ffff,
    0x1234_5678,
];

/// Bit 4 of `a ^ b ^ result`: the carry into it, for an addition and a subtraction alike.
fn adjust(a: u128, b: u128, result: u128) -> u128 {
    ((a ^ b ^ result) >> 4) & 1
}

#[derive(Clone, Copy)]
enum Form {
    /// `a + b + carry` (ADD, ADC, INC, XADD).
    Add,
    /// `a - b - borrow` (SUB, SBB, CMP, DEC, NEG, CMPXCHG).
    Sub,
}

#[test]
fn arithmetic_sets_af_to_the_carry_out_of_bit_3() {
    let machine = Machine::x86_64();
    // (instruction, bytes, form, the register holding a, the one holding b, whether CF enters).
    let forms: [(&str, &[u8], Form, &str, &str, bool); 6] = [
        (
            "add eax, ecx",
            &[0x01, 0xc8],
            Form::Add,
            "EAX",
            "ECX",
            false,
        ),
        ("adc eax, ecx", &[0x11, 0xc8], Form::Add, "EAX", "ECX", true),
        (
            "sub eax, ecx",
            &[0x29, 0xc8],
            Form::Sub,
            "EAX",
            "ECX",
            false,
        ),
        ("sbb eax, ecx", &[0x19, 0xc8], Form::Sub, "EAX", "ECX", true),
        (
            "cmp eax, ecx",
            &[0x39, 0xc8],
            Form::Sub,
            "EAX",
            "ECX",
            false,
        ),
        (
            "xadd ecx, eax",
            &[0x0f, 0xc1, 0xc1],
            Form::Add,
            "ECX",
            "EAX",
            false,
        ),
    ];
    for (text, bytes, form, left, right, carries) in forms {
        for a in VALUES {
            for b in VALUES {
                for carry in [0, u128::from(carries)] {
                    let entry = [(left, a), (right, b), ("CF", carry)];
                    let state = &machine.run(bytes, &entry);
                    let result = match form {
                        Form::Add => a.wrapping_add(b).wrapping_add(carry),
                        Form::Sub => a.wrapping_sub(b).wrapping_sub(carry),
                    };
                    let expected = adjust(a, b, result);
                    let af = machine.read(state, "AF");
                    assert_eq!(af, expected, "{text}: {a:#x}, {b:#x}, CF {carry}");
                }
            }
        }
    }
}

#[test]
fn one_operand_and_memory_forms_set_af() {
    let machine = Machine::x86_64();
    let cell = low(4);
    for value in VALUES {
        // (instruction, bytes, a, b, form)
        let forms: [(&str, &[u8], u128, u128, Form); 6] = [
            ("inc eax", &[0xff, 0xc0], value, 1, Form::Add),
            ("dec eax", &[0xff, 0xc8], value, 1, Form::Sub),
            ("neg eax", &[0xf7, 0xd8], 0, value, Form::Sub),
            ("add [rsi], eax", &[0x01, 0x06], cell, value, Form::Add),
            ("inc dword [rsi]", &[0xff, 0x06], cell, 1, Form::Add),
            ("cmp eax, [rsi]", &[0x3b, 0x06], value, cell, Form::Sub),
        ];
        for (text, bytes, a, b, form) in forms {
            let state = &machine.run(bytes, &[("RAX", value)]);
            let result = match form {
                Form::Add => a.wrapping_add(b),
                Form::Sub => a.wrapping_sub(b),
            };
            let af = machine.read(state, "AF");
            assert_eq!(af, adjust(a, b, result), "{text}: {value:#x}");
        }
    }
    // cmpxchg ecx, edx compares EAX with ECX, as `cmp eax, ecx` does.
    for (a, b) in [(0x10, 0x1), (0x1f, 0xf), (0x8, 0x9)] {
        let entry = [("RAX", a), ("RCX", b), ("RDX", 0)];
        let state = &machine.run(&[0x0f, 0xb1, 0xd1], &entry);
        let af = machine.read(state, "AF");
        assert_eq!(
            af,
            adjust(a, b, a.wrapping_sub(b)),
            "cmpxchg: {a:#x}, {b:#x}"
        );
    }
}

/// Worked cases from the definition, "set if an arithmetic operation generates a carry or a
/// borrow out of bit 3 of the result" (Intel SDM Vol. 1, 3.4.3.1), each stated as a literal.
#[test]
fn af_is_the_carry_or_borrow_out_of_bit_3_as_the_sdm_states_it() {
    let machine = Machine::x86_64();
    // (instruction, bytes, EAX, ECX, CF in, AF out)
    let cases: [(&str, &[u8], u128, u128, u128, u128); 8] = [
        ("add eax, ecx", &[0x01, 0xc8], 0x0f, 0x01, 0, 1),
        ("add eax, ecx", &[0x01, 0xc8], 0x0e, 0x01, 0, 0),
        ("add eax, ecx", &[0x01, 0xc8], 0x08, 0x08, 0, 1),
        ("adc eax, ecx", &[0x11, 0xc8], 0x0e, 0x01, 1, 1),
        ("sub eax, ecx", &[0x29, 0xc8], 0x10, 0x01, 0, 1),
        ("sub eax, ecx", &[0x29, 0xc8], 0x1f, 0x0f, 0, 0),
        ("sbb eax, ecx", &[0x19, 0xc8], 0x1f, 0x0f, 1, 1),
        ("cmp eax, ecx", &[0x39, 0xc8], 0x100, 0x01, 0, 1),
    ];
    for (text, bytes, eax, ecx, carry, af) in cases {
        let state = &machine.run(bytes, &[("EAX", eax), ("ECX", ecx), ("CF", carry)]);
        let stated = machine.read(state, "AF");
        assert_eq!(stated, af, "{text}: {eax:#x}, {ecx:#x}, CF {carry}");
    }
    // INC of 0x0f carries out of bit 3; DEC of 0x10 borrows; NEG of a nonzero low nibble borrows.
    for (text, bytes, eax, af) in [
        ("inc eax", &[0xff, 0xc0][..], 0x0f, 1),
        ("dec eax", &[0xff, 0xc8], 0x10, 1),
        ("neg eax", &[0xf7, 0xd8], 0x01, 1),
        ("neg eax", &[0xf7, 0xd8], 0x10, 0),
    ] {
        let state = &machine.run(bytes, &[("EAX", eax)]);
        assert_eq!(machine.read(state, "AF"), af, "{text}: {eax:#x}");
    }
}
