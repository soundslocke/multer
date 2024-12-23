use http::header::{self, HeaderMap};
use std::borrow::Cow;
use std::str;

#[derive(Debug)]
pub(crate) struct ContentDisposition {
    pub(crate) field_name: Option<String>,
    pub(crate) file_name: Option<String>,
}

impl ContentDisposition {
    pub fn parse(headers: &HeaderMap) -> ContentDisposition {
        let content_disposition = headers.get(header::CONTENT_DISPOSITION).map(|val| val.as_bytes());

        let field_name = content_disposition
            .and_then(|val| ContentDispositionAttr::Name.extract_from(val))
            .map(|attr| attr.into_owned());

        let file_name = content_disposition
            .and_then(|val| ContentDispositionAttr::FileName.extract_from(val))
            .map(|attr| attr.into_owned());

        ContentDisposition { field_name, file_name }
    }
}

#[derive(PartialEq)]
pub(crate) enum ContentDispositionAttr {
    Name,
    FileName,
}

#[derive(Debug)]
struct ParsedField<'a> {
    value: &'a [u8],
    is_extended: bool,
    is_escaped: bool,
}

/// Convert a field value with escaped quotes
fn convert_escaped(bytes: &[u8]) -> Option<Cow<'_, str>> {
    let s = str::from_utf8(bytes).ok()?;
    Some(s.replace(r#"\""#, "\"").into())
}

/// Decode a field value according to RFC 5987
fn decode_field(value: &[u8]) -> Option<Cow<'_, str>> {
    // First try to decode the percent encoding
    let decoded = percent_decode(value)?;

    // Convert to string
    // We'll treat all extended values as utf-8
    match decoded {
        Cow::Borrowed(bytes) => str::from_utf8(bytes).ok().map(Cow::Borrowed),
        Cow::Owned(bytes) => String::from_utf8(bytes).ok().map(Cow::Owned),
    }
}

/// Decode percent-encoded bytes
fn percent_decode(input: &[u8]) -> Option<Cow<'_, [u8]>> {
    if !input.contains(&b'%') {
        return Some(Cow::Borrowed(input));
    }

    let mut decoded = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hex = str::from_utf8(&input[i + 1..i + 3]).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            decoded.push(byte);
            i += 3;
        } else {
            decoded.push(input[i]);
            i += 1;
        }
    }

    Some(Cow::Owned(decoded))
}

fn trim_ascii_ws_start(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or_else(|| &bytes[bytes.len()..], |i| &bytes[i..])
}

fn trim_ascii_ws_then(bytes: &[u8], char: u8) -> Option<&[u8]> {
    match trim_ascii_ws_start(bytes) {
        [first, rest @ ..] if *first == char => Some(rest),
        _ => None,
    }
}

/// Functions for parsing Content-Disposition header fields
mod parser {
    use super::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    pub(crate) struct ExtendedValue<'a> {
        charset: &'a str,
        language_tag: Option<&'a str>,
        value: &'a [u8],
    }

    /// Case-insensitive prefix matching
    pub(crate) fn matches_prefix(bytes: &[u8], prefix: &[u8]) -> bool {
        bytes.len() >= prefix.len()
            && bytes
                .iter()
                .take(prefix.len())
                .zip(prefix.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    }

    pub(crate) fn find_next_field<'a>(header: &'a [u8], prefix: &[u8]) -> Option<(ParsedField<'a>, &'a [u8])> {
        let mut header = trim_ascii_ws_start(header);

        while !header.is_empty() {
            if header[0] != b';' {
                let next_semi = memchr::memchr(b';', header)?;
                header = &header[next_semi..];
            }

            header = trim_ascii_ws_start(&header[1..]);

            if matches_prefix(header, prefix) {
                if let Some((field, rest)) = parse_field(header, prefix) {
                    return Some((field, rest));
                }
            }

            if let Some(next_semi) = memchr::memchr(b';', header) {
                header = &header[next_semi..];
            } else {
                break;
            }
        }

        None
    }

    fn parse_field<'a>(header: &'a [u8], prefix: &[u8]) -> Option<(ParsedField<'a>, &'a [u8])> {
        let suffix = &header[prefix.len()..];
        let rest = trim_ascii_ws_start(suffix);

        let (rest, is_extended) = if !rest.is_empty() && rest[0] == b'*' {
            (trim_ascii_ws_start(&rest[1..]), true)
        } else {
            (rest, false)
        };

        if !rest.is_empty() && rest[0] != b'=' {
            return None;
        }

        let rest = trim_ascii_ws_then(rest, b'=')?;

        if is_extended {
            // Parse extended value format: charset'language'percent-encoded-value
            let value = parse_extended_value(rest)?;
            Some((
                ParsedField {
                    value: value.value,
                    is_extended: true,
                    is_escaped: false, // Extended values don't use quote escaping
                },
                suffix,
            ))
        } else {
            let (value, is_escaped) = parse_value(rest)?;
            Some((
                ParsedField {
                    value,
                    is_extended: false,
                    is_escaped,
                },
                suffix,
            ))
        }
    }

    fn parse_extended_value(input: &[u8]) -> Option<ExtendedValue<'_>> {
        let input = trim_ascii_ws_start(input);

        // Find the first single quote
        let charset_end = memchr::memchr(b'\'', input)?;
        let charset = str::from_utf8(&input[..charset_end]).ok()?;

        // Find the second single quote
        let after_charset = &input[charset_end + 1..];
        let lang_end = memchr::memchr(b'\'', after_charset)?;
        let language_tag = match str::from_utf8(&after_charset[..lang_end]).ok()? {
            "" => None,
            lang => Some(lang),
        };

        // The value goes until the next semicolon or end of input
        let value_start = charset_end + 1 + lang_end + 1;
        let remaining = &input[value_start..];
        let value_end = memchr::memchr(b';', remaining).unwrap_or(remaining.len());
        let value = &remaining[..value_end];

        // Trim any trailing whitespace from the value
        let value = match memchr::memchr(b' ', value) {
            Some(pos) => &value[..pos],
            None => value,
        };

        Some(ExtendedValue {
            charset,
            language_tag,
            value,
        })
    }

    fn parse_value(input: &[u8]) -> Option<(&[u8], bool)> {
        if let Some(rest) = trim_ascii_ws_then(input, b'"') {
            let (mut k, mut escaped) = (memchr::memchr(b'"', rest)?, false);
            while k > 0 && rest[k - 1] == b'\\' {
                escaped = true;
                k = k + 1 + memchr::memchr(b'"', &rest[(k + 1)..])?;
            }
            Some((&rest[..k], escaped))
        } else {
            let rest = trim_ascii_ws_start(input);
            let j = memchr::memchr2(b';', b' ', rest).unwrap_or(rest.len());
            Some((&rest[..j], false))
        }
    }
}

impl ContentDispositionAttr {
    pub fn extract_from<'h>(&self, header: &'h [u8]) -> Option<Cow<'h, str>> {
        let prefix = match self {
            ContentDispositionAttr::Name => &b"name"[..],
            ContentDispositionAttr::FileName => &b"filename"[..],
        };

        let mut regular_result: Option<ParsedField<'_>> = None;
        let mut current_header = header;

        while let Some((field, rest)) = parser::find_next_field(current_header, prefix) {
            if field.is_extended {
                return decode_field(field.value);
            } else if regular_result.is_none() {
                regular_result = Some(field);
            }
            current_header = rest;
        }

        regular_result.and_then(|field| {
            if field.is_escaped {
                convert_escaped(field.value)
            } else {
                str::from_utf8(field.value).ok().map(Cow::Borrowed)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_only() {
        let val = br#"form-data; name="my_field""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert!(filename.is_none());

        let val = br#"form-data; name=my_field  "#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert!(filename.is_none());

        let val = br#"form-data; name  =  my_field  "#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert!(filename.is_none());

        let val = br#"form-data; name  =  "#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "");
        assert!(filename.is_none());

        let val = br#"form-data; name*=utf-8''my_field%20with%20space"#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field with space");
        assert!(filename.is_none());
    }

    #[test]
    fn test_extraction() {
        let val = br#"form-data; name="my_field"; filename="file abc.txt""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert_eq!(filename.unwrap(), "file abc.txt");

        let val = "form-data; name=\"你好\"; filename=\"file abc.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "你好");
        assert_eq!(filename.unwrap(), "file abc.txt");

        let val = "form-data; name=\"কখগ\"; filename=\"你好.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "কখগ");
        assert_eq!(filename.unwrap(), "你好.txt");
    }

    #[test]
    fn test_extraction_extended() {
        let val = br#"form-data; name*=utf-8''my_field%20with%20space; filename="file abc.txt""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field with space");
        assert_eq!(filename.unwrap(), "file abc.txt");

        let val = "form-data; name=\"my_field\"; filename=\"你好.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert_eq!(filename.unwrap(), "你好.txt");

        // RFC 7578 Section 4.2 says `filename*=` syntax is invalid.
        // Clients might still set it, though.
        // See https://datatracker.ietf.org/doc/html/rfc7578#section-4.2
        let val = "form-data; name=my_field; filename=\"你好.txt\"; filename*=utf-8''你好.txt".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert_eq!(filename.unwrap(), "你好.txt");

        let val = "form-data; name=my_field; filename*=utf-8''你好.txt; filename=\"你好.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert_eq!(filename.unwrap(), "你好.txt");
    }

    #[test]
    fn test_file_name_only() {
        // These are technically malformed, as RFC 7578 says the `name`
        // parameter _must_ be included. But okay.
        let val = br#"form-data; filename="file-name.txt""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(filename.unwrap(), "file-name.txt");
        assert!(name.is_none());

        let val = "form-data; filename=\"কখগ-你好.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(filename.unwrap(), "কখগ-你好.txt");
        assert!(name.is_none());
    }

    #[test]
    fn test_misordered_fields() {
        let val = br#"form-data; filename=file-name.txt; name=file"#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(filename.unwrap(), "file-name.txt");
        assert_eq!(name.unwrap(), "file");

        let val = br#"form-data; filename="file-name.txt"; name="file""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(filename.unwrap(), "file-name.txt");
        assert_eq!(name.unwrap(), "file");

        let val = "form-data; filename=\"你好.txt\"; name=\"কখগ\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "কখগ");
        assert_eq!(filename.unwrap(), "你好.txt");
    }

    #[test]
    fn test_name_mixed_case() {
        let val = br#"form-data; Name=file; FileName=file-name.txt"#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "file");
        assert_eq!(filename.unwrap(), "file-name.txt");

        let val = br#"form-data; NAME="file"; FILENAME="file-name.txt""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "file");
        assert_eq!(filename.unwrap(), "file-name.txt");

        let val = "form-data; Name=\"কখগ\"; FileName=\"你好.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "কখগ");
        assert_eq!(filename.unwrap(), "你好.txt");

        let val = "form-data; Name*=UTF-8''কখগ; FileNAME*=utf-8''你好.txt; FILEName=\"file-name.txt\"".as_bytes();
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "কখগ");
        assert_eq!(filename.unwrap(), "你好.txt");
    }

    #[test]
    fn test_name_unquoted() {
        let val = br#"form-data; name=my_field"#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert!(filename.is_none());

        let val = br#"form-data; name=my_field; filename=file-name.txt"#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        assert_eq!(filename.unwrap(), "file-name.txt");
    }

    #[test]
    fn test_name_quoted() {
        let val = br#"form-data; name="my;f;ield""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "my;f;ield");
        assert!(filename.is_none());

        let val = br#"form-data; name=my_field; filename = "file;name.txt""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        assert_eq!(name.unwrap(), "my_field");
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(filename.unwrap(), "file;name.txt");

        let val = br#"form-data; name=; filename=filename.txt"#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), "");
        assert_eq!(filename.unwrap(), "filename.txt");

        let val = br#"form-data; name=";"; filename=";""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        let filename = ContentDispositionAttr::FileName.extract_from(val);
        assert_eq!(name.unwrap(), ";");
        assert_eq!(filename.unwrap(), ";");
    }

    #[test]
    fn test_name_escaped_quote() {
        let val = br#"form-data; name="my\"field\"name""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        assert_eq!(name.unwrap(), r#"my"field"name"#);

        let val = br#"form-data; name="myfield\"name""#;
        let name = ContentDispositionAttr::Name.extract_from(val);
        assert_eq!(name.unwrap(), r#"myfield"name"#);
    }
}
