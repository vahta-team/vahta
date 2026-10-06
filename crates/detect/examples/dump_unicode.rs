//! One line per Unicode scalar value, for `benchmarks/diff_unicode.py`.
//!
//! `<hex> <space><word><digit> <class> <fold hex>` — every Unicode predicate
//! the detector answers with Python's semantics rather than Rust's.

use std::io::{BufWriter, Write};
use vahta_detect::{
    CharClass, char_class, fold_ci, is_digit_python, is_python_space, is_word_python,
};

fn main() {
    let out = std::io::stdout();
    let mut w = BufWriter::new(out.lock());
    for c in (0u32..0x11_0000).filter_map(char::from_u32) {
        let class = match char_class(c) {
            CharClass::Upper => 'U',
            CharClass::Lower => 'L',
            CharClass::Digit => 'D',
            _ => 'O',
        };
        writeln!(
            w,
            "{:x} {}{}{} {} {:x}",
            c as u32,
            is_python_space(c) as u8,
            is_word_python(c) as u8,
            is_digit_python(c) as u8,
            class,
            fold_ci(c) as u32
        )
        .unwrap();
    }
}
