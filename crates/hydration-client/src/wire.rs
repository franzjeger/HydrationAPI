//! The watch line is a single line of `key=value` tokens, so a value may never
//! contain whitespace, `=`, or a newline. Paths are the one value that can
//! contain all three, so they are escaped before they go on the line and
//! unescaped on the way back out.
//!
//! The escape is a flat one: `\` becomes `\\`, a space becomes `\s`, `=`
//! becomes `\e`, and a newline becomes `\n` (a real newline would otherwise
//! split the line into two). It is deliberately not percent-encoding — the
//! alphabet is the set of characters a path is actually likely to hold, and a
//! reader that does not know the scheme simply sees an opaque value and
//! ignores the key, which is the contract for every unrecognised key on the
//! line.

/// Encode one path for the watch line.
pub fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\s"),
            '=' => out.push_str("\\e"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

/// Decode one path token from the watch line. A token with no escape is
/// returned unchanged, so a reader that predates the scheme still round-trips
/// the values it knows.
pub fn decode_path(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('s') => out.push(' '),
                Some('e') => out.push('='),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                // A lone trailing backslash, or one before a character we do
                // not escape: keep both rather than invent a meaning.
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_path_round_trips_unchanged() {
        let p = "Documents/report final.docx";
        assert_eq!(decode_path(&encode_path(p)), p);
    }

    #[test]
    fn the_tricky_characters_round_trip() {
        let p = "a\\b c=d\ne\r";
        assert_eq!(decode_path(&encode_path(p)), p);
    }

    #[test]
    fn an_encoded_path_needs_no_whitespace_or_equals() {
        let p = "a b=c d";
        let enc = encode_path(p);
        assert!(!enc.contains(' '));
        assert!(!enc.contains('='));
        assert!(!enc.contains('\n'));
    }

    #[test]
    fn a_trailing_backslash_is_kept_verbatim() {
        assert_eq!(decode_path("a\\"), "a\\");
    }
}
