// The MIT License (MIT)
//
// Copyright (c) 2016 Saghm Rossi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::char;

/// Takes in a string with backslash escapes written out with literal backslash characters and
/// converts it to a string with the proper escaped characters.
pub fn unescape(s: &str) -> Option<String> {
    let mut queue = s.chars();
    let mut s = String::new();

    while let Some(c) = queue.next() {
        if c != '\\' {
            s.push(c);
            continue;
        }

        match queue.next() {
            Some('b') => s.push('\u{0008}'),
            Some('f') => s.push('\u{000C}'),
            Some('n') => s.push('\n'),
            Some('r') => s.push('\r'),
            Some('t') => s.push('\t'),
            Some('\'') => s.push('\''),
            Some('\"') => s.push('\"'),
            Some('\\') => s.push('\\'),
            Some('u') => s.push(unescape_unicode(&mut queue)?),
            Some('x') => s.push(unescape_byte(&mut queue)?),
            Some(c) if c.is_digit(8) => s.push(unescape_octal(c, &mut queue)?),
            _ => return None,
        };
    }

    Some(s)
}
/// Unescape `s` until an unescaped quote (single or double) is encountered.
/// Also returns how many bytes were read.
pub fn unescape_until_quote(s: &str) -> Option<(String, usize)> {
    let mut queue = s.chars();
    let mut s = String::new();
    let mut bytes = 0;

    while let Some(c) = queue.next() {
        if c == '"' || c == '\'' {
            return Some((s, bytes));
        }
        bytes += c.len_utf8();
        if c != '\\' {
            s.push(c);
            continue;
        }

        let c = queue.next()?;
        bytes += c.len_utf8();
        match c {
            'b' => s.push('\x08'),
            'f' => s.push('\x0C'),
            'n' => s.push('\n'),
            'r' => s.push('\r'),
            't' => s.push('\t'),
            '\'' => s.push('\''),
            '\"' => s.push('\"'),
            '\\' => s.push('\\'),
            'u' => s.push(unescape_unicode(&mut queue)?),
            'x' => s.push(unescape_byte(&mut queue)?),
            c if c.is_digit(8) => s.push(unescape_octal(c, &mut queue)?),
            _ => return None,
        };
    }

    Some((s, bytes))
}

fn unescape_unicode(queue: &mut impl Iterator<Item = char>) -> Option<char> {
    let mut s = String::with_capacity(4);

    for _ in 0..4 {
        s.push(queue.next()?);
    }

    let u = u32::from_str_radix(&s, 16).ok()?;
    char::from_u32(u)
}

fn unescape_byte(queue: &mut impl Iterator<Item = char>) -> Option<char> {
    let mut s = String::with_capacity(2);

    for _ in 0..2 {
        s.push(queue.next()?);
    }

    let u = u32::from_str_radix(&s, 16).ok()?;
    char::from_u32(u)
}

fn unescape_octal(c: char, queue: &mut impl Iterator<Item = char>) -> Option<char> {
    if c != '0' && c != '1' && c != '2' && c != '3' {
        unescape_octal_no_leading(c, queue)
    } else {
        unescape_octal_leading(c, queue)
    }
}

fn unescape_octal_leading(c: char, queue: &mut impl Iterator<Item = char>) -> Option<char> {
    let mut s = String::new();
    s.push(c);
    s.push(queue.next()?);
    s.push(queue.next()?);

    let u = u32::from_str_radix(&s, 8).ok()?;
    char::from_u32(u)
}

fn unescape_octal_no_leading(c: char, queue: &mut impl Iterator<Item = char>) -> Option<char> {
    let mut s = String::new();
    s.push(c);
    s.push(queue.next()?);

    let u = u32::from_str_radix(&s, 8).ok()?;
    char::from_u32(u)
}
