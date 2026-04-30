use std::borrow::Cow;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub enum JsonMode<'a> {
    Json,
    Jsonp { args: &'a [u8] },
}

pub fn render_html(
    dir_path: &Path,
    uri: &[u8],
    exact_size: bool,
    localtime: bool,
) -> std::io::Result<Vec<u8>> {
    let entries = read_sorted_entries(dir_path)?;

    let uri_text = String::from_utf8_lossy(uri);
    let uri_escaped = escape_html(&uri_text);

    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(b"<html>\r\n<head><title>Index of ");
    out.extend_from_slice(uri_escaped.as_bytes());
    out.extend_from_slice(b"</title></head>\r\n<body>\r\n<h1>Index of ");
    out.extend_from_slice(uri_escaped.as_bytes());
    out.extend_from_slice(b"</h1><hr><pre>");

    if uri != b"/" {
        write_entry_line(&mut out, b"../", "../", true, 0, 0, true, localtime);
    }

    for entry in entries {
        let raw_name = entry.file_name.as_os_str().as_bytes();
        let mut href = percent_encode(raw_name);
        let mut display = String::from_utf8_lossy(raw_name).into_owned();
        if entry.is_dir {
            href.push(b'/');
            display.push('/');
        }

        write_entry_line(
            &mut out,
            &href,
            &display,
            entry.is_dir,
            entry.size,
            entry.mtime,
            exact_size,
            localtime,
        );
    }

    out.extend_from_slice(b"</pre><hr></body>\r\n</html>\r\n");
    Ok(out)
}

pub fn render_xml(dir_path: &Path) -> std::io::Result<Vec<u8>> {
    let entries = read_sorted_entries(dir_path)?;
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(br#"<?xml version="1.0"?>"#);
    out.extend_from_slice(b"\n<list>");
    for entry in entries {
        let raw_name = entry.file_name.as_os_str().as_bytes();
        let name = String::from_utf8_lossy(raw_name);
        let name_escaped = escape_html(&name);
        let mtime = format_xml_timestamp(entry.mtime);
        if entry.is_dir {
            out.extend_from_slice(br#"<directory mtime=""#);
            out.extend_from_slice(mtime.as_bytes());
            out.extend_from_slice(br#"">"#);
            out.extend_from_slice(name_escaped.as_bytes());
            out.extend_from_slice(b"</directory>");
        } else {
            out.extend_from_slice(br#"<file mtime=""#);
            out.extend_from_slice(mtime.as_bytes());
            out.extend_from_slice(br#"" size=""#);
            out.extend_from_slice(entry.size.to_string().as_bytes());
            out.extend_from_slice(br#"">"#);
            out.extend_from_slice(name_escaped.as_bytes());
            out.extend_from_slice(b"</file>");
        }
    }
    out.extend_from_slice(b"</list>\n");
    Ok(out)
}

pub fn render_json(dir_path: &Path, mode: JsonMode<'_>) -> std::io::Result<Vec<u8>> {
    let entries = read_sorted_entries(dir_path)?;
    let mut array = Vec::with_capacity(2048);
    array.extend_from_slice(b"[");
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            array.extend_from_slice(b",");
        }
        let raw_name = entry.file_name.as_os_str().as_bytes();
        let name = String::from_utf8_lossy(raw_name);
        let mut name_json = Vec::with_capacity(name.len() + 8);
        write_json_string(&mut name_json, &name);
        let mtime = format_httpdate(entry.mtime);
        let mut mtime_json = Vec::with_capacity(mtime.len() + 8);
        write_json_string(&mut mtime_json, &mtime);

        array.extend_from_slice(b"{\"name\":");
        array.extend_from_slice(&name_json);
        array.extend_from_slice(b",\"type\":\"");
        if entry.is_dir {
            array.extend_from_slice(b"directory");
        } else {
            array.extend_from_slice(b"file");
        }
        array.extend_from_slice(b"\",\"mtime\":");
        array.extend_from_slice(&mtime_json);
        if !entry.is_dir {
            array.extend_from_slice(b",\"size\":");
            array.extend_from_slice(entry.size.to_string().as_bytes());
        }
        array.extend_from_slice(b"}");
    }
    array.extend_from_slice(b"]");

    match mode {
        JsonMode::Json => Ok(array),
        JsonMode::Jsonp { args } => {
            let callback = query_arg(args, b"callback").and_then(percent_decode);
            if let Some(cb) = callback
                && !cb.is_empty()
            {
                let mut out = Vec::with_capacity(cb.len() + array.len() + 8);
                out.extend_from_slice(&cb);
                out.extend_from_slice(b"(");
                out.extend_from_slice(&array);
                out.extend_from_slice(b");");
                return Ok(out);
            }
            Ok(array)
        }
    }
}

struct Entry {
    file_name: OsString,
    is_dir: bool,
    size: u64,
    mtime: u64,
}

fn read_sorted_entries(dir_path: &Path) -> std::io::Result<Vec<Entry>> {
    let mut entries: Vec<Entry> = Vec::new();
    for item in std::fs::read_dir(dir_path)? {
        let item = match item {
            Ok(v) => v,
            Err(_) => continue,
        };
        let file_name = item.file_name();
        // `fs::metadata` follows symlinks (vs. `DirEntry::metadata`,
        // which does not). nginx's autoindex follows symlinks too —
        // `ngx_http_autoindex_module.c` calls `ngx_de_info` which is
        // `stat(2)`, not `lstat(2)`.
        let metadata = match std::fs::metadata(item.path()) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let is_dir = metadata.is_dir();
        let size = metadata.len();
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        entries.push(Entry {
            file_name,
            is_dir,
            size,
            mtime,
        });
    }

    entries.sort_by(|a, b| {
        a.file_name
            .as_os_str()
            .as_bytes()
            .cmp(b.file_name.as_os_str().as_bytes())
    });
    Ok(entries)
}

fn write_entry_line(
    out: &mut Vec<u8>,
    href: &[u8],
    display: &str,
    is_dir: bool,
    size: u64,
    mtime: u64,
    exact_size: bool,
    localtime: bool,
) {
    out.extend_from_slice(b"<a href=\"");
    out.extend_from_slice(href);
    out.extend_from_slice(b"\">");

    let (shown, width) = truncate_name(display, 50);
    let shown_escaped = escape_html(&shown);
    out.extend_from_slice(shown_escaped.as_bytes());
    out.extend_from_slice(b"</a>");

    for _ in width..50 {
        out.push(b' ');
    }
    out.push(b' ');

    let ts = format_timestamp(mtime, localtime);
    out.extend_from_slice(ts.as_bytes());

    out.push(b' ');
    let size_text = if is_dir {
        Cow::Borrowed("-")
    } else {
        Cow::Owned(format_size(size, exact_size))
    };

    for _ in size_text.len()..19 {
        out.push(b' ');
    }
    out.extend_from_slice(size_text.as_bytes());
    out.extend_from_slice(b"\r\n");
}

fn truncate_name(name: &str, limit: usize) -> (String, usize) {
    let count = name.chars().count();
    if count <= limit {
        return (name.to_string(), count);
    }

    let keep = limit.saturating_sub(3);
    let mut out = String::new();
    for ch in name.chars().take(keep) {
        out.push(ch);
    }
    out.push('.');
    out.push('.');
    out.push('>');
    (out, limit)
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

fn percent_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex((b >> 4) & 0x0f));
            out.push(hex(b & 0x0f));
        }
    }
    out
}

fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

fn hex(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'A' + (n - 10),
    }
}

fn format_size(size: u64, exact: bool) -> String {
    if exact {
        return size.to_string();
    }

    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if size < KB {
        size.to_string()
    } else if size < MB {
        format!("{}K", size.saturating_add(KB - 1) / KB)
    } else if size < GB {
        format!("{}M", size.saturating_add(MB - 1) / MB)
    } else {
        format!("{}G", size.saturating_add(GB - 1) / GB)
    }
}

fn format_timestamp(secs: u64, localtime: bool) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = if secs > libc::time_t::MAX as u64 {
        libc::time_t::MAX
    } else {
        secs as libc::time_t
    };

    let tm_ptr = unsafe {
        if localtime {
            libc::localtime_r(&t, &mut tm)
        } else {
            libc::gmtime_r(&t, &mut tm)
        }
    };

    if tm_ptr.is_null() {
        return "01-Jan-1970 00:00".to_string();
    }

    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let mon = if (0..12).contains(&tm.tm_mon) {
        MONTHS[tm.tm_mon as usize]
    } else {
        "Jan"
    };

    format!(
        "{:02}-{}-{:04} {:02}:{:02}",
        tm.tm_mday,
        mon,
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min
    )
}

fn format_xml_timestamp(secs: u64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = if secs > libc::time_t::MAX as u64 {
        libc::time_t::MAX
    } else {
        secs as libc::time_t
    };
    let tm_ptr = unsafe { libc::gmtime_r(&t, &mut tm) };
    if tm_ptr.is_null() {
        return "1970-01-01T00:00:00Z".to_string();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

fn format_httpdate(secs: u64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = if secs > libc::time_t::MAX as u64 {
        libc::time_t::MAX
    } else {
        secs as libc::time_t
    };
    let tm_ptr = unsafe { libc::gmtime_r(&t, &mut tm) };
    if tm_ptr.is_null() {
        return "Thu, 01 Jan 1970 00:00:00 GMT".to_string();
    }
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let wday = if (0..7).contains(&tm.tm_wday) {
        WDAYS[tm.tm_wday as usize]
    } else {
        "Thu"
    };
    let mon = if (0..12).contains(&tm.tm_mon) {
        MONTHS[tm.tm_mon as usize]
    } else {
        "Jan"
    };
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        wday,
        tm.tm_mday,
        mon,
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

fn write_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if c <= '\u{1F}' => {
                let mut buf = [0u8; 6];
                let code = c as u32;
                buf[0] = b'\\';
                buf[1] = b'u';
                buf[2] = hex(((code >> 12) & 0x0f) as u8);
                buf[3] = hex(((code >> 8) & 0x0f) as u8);
                buf[4] = hex(((code >> 4) & 0x0f) as u8);
                buf[5] = hex((code & 0x0f) as u8);
                out.extend_from_slice(&buf);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn query_arg<'a>(args: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    for pair in args.split(|&b| b == b'&') {
        let (k, v) = match pair.iter().position(|&b| b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        if k == key {
            return Some(v);
        }
    }
    None
}

fn percent_decode(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len() {
                return None;
            }
            let hi = hex_nibble(raw[i + 1])?;
            let lo = hex_nibble(raw[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_escapes_reserved_bytes() {
        assert_eq!(percent_encode(b"abc:de?f%"), b"abc%3Ade%3Ff%25");
    }

    #[test]
    fn truncate_marks_long_names_with_dot_dot_gt() {
        let (shown, width) =
            truncate_name("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50);
        assert_eq!(width, 50);
        assert!(shown.ends_with("..>"));
    }

    #[test]
    fn format_size_rounds_units_when_exact_is_off() {
        assert_eq!(format_size(1_100, false), "2K");
        assert_eq!(format_size(1_048_577, false), "2M");
    }
}
