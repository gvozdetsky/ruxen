use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub fn render_html(
    dir_path: &Path,
    uri: &[u8],
    exact_size: bool,
    localtime: bool,
) -> std::io::Result<Vec<u8>> {
    let entries = read_sorted_entries(dir_path)?;
    // nginx adds its cached UTC offset (`tp->gmtoff`) to every entry with
    // `autoindex_localtime on`: one lookup per listing, not per entry
    // (`localtime_r` and `gmtime_r` take glibc's process-wide timezone
    // lock, which serialized the workers, #250).
    let offset = if localtime { local_utc_offset() } else { 0 };

    // ngx_http_autoindex_html sizes its buffer up front; so does this,
    // with room for the longest line nginx writes per entry.
    let names: usize = entries.iter().map(|e| e.file_name.len()).sum();
    let mut out = Vec::with_capacity(256 + 6 * uri.len() + entries.len() * 150 + 9 * names);
    out.extend_from_slice(b"<html>\r\n<head><title>Index of ");
    escape_html_into(&mut out, uri);
    out.extend_from_slice(b"</title></head>\r\n<body>\r\n<h1>Index of ");
    escape_html_into(&mut out, uri);
    out.extend_from_slice(b"</h1><hr><pre><a href=\"../\">../</a>\r\n");
    for entry in &entries {
        write_entry_line(&mut out, entry, exact_size, offset);
    }
    out.extend_from_slice(b"</pre><hr></body>\r\n</html>\r\n");
    Ok(out)
}

/// The current offset of local time from UTC, in seconds.
fn local_utc_offset() -> i64 {
    // SAFETY: `time(NULL)` and `localtime_r` with out-pointers to locals.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            0
        } else {
            tm.tm_gmtoff
        }
    }
}

pub fn render_xml(dir_path: &Path) -> std::io::Result<Vec<u8>> {
    let entries = read_sorted_entries(dir_path)?;
    // ngx_http_autoindex_xml: one entry per line, the name as it is on
    // disk, HTML-escaped.
    let mut out = Vec::with_capacity(64 + entries.len() * 96);
    out.extend_from_slice(b"<?xml version=\"1.0\"?>\r\n<list>\r\n");
    for entry in &entries {
        let kind = entry.kind();
        out.push(b'<');
        out.extend_from_slice(kind);
        out.extend_from_slice(b" mtime=\"");
        out.extend_from_slice(format_xml_timestamp(entry.mtime).as_bytes());
        if entry.is_file {
            out.extend_from_slice(b"\" size=\"");
            out.extend_from_slice(entry.size.to_string().as_bytes());
        }
        out.extend_from_slice(b"\">");
        escape_html_into(&mut out, entry.file_name.as_os_str().as_bytes());
        out.extend_from_slice(b"</");
        out.extend_from_slice(kind);
        out.extend_from_slice(b">\r\n");
    }
    out.extend_from_slice(b"</list>\r\n");
    Ok(out)
}

/// ngx_http_autoindex_json: one entry per line; a non-empty `callback`
/// makes it JSONP.
pub fn render_json(dir_path: &Path, callback: &[u8]) -> std::io::Result<Vec<u8>> {
    let entries = read_sorted_entries(dir_path)?;
    let mut out = Vec::with_capacity(32 + callback.len() + entries.len() * 112);
    if !callback.is_empty() {
        out.extend_from_slice(b"/* callback */\r\n");
        out.extend_from_slice(callback);
        out.push(b'(');
    }
    out.push(b'[');
    for entry in &entries {
        out.extend_from_slice(b"\r\n{ \"name\":\"");
        escape_json_into(&mut out, entry.file_name.as_os_str().as_bytes());
        out.extend_from_slice(b"\", \"type\":\"");
        out.extend_from_slice(entry.kind());
        out.extend_from_slice(b"\", \"mtime\":\"");
        out.extend_from_slice(format_httpdate(entry.mtime).as_bytes());
        if entry.is_file {
            out.extend_from_slice(b"\", \"size\":");
            out.extend_from_slice(entry.size.to_string().as_bytes());
        } else {
            out.push(b'"');
        }
        out.extend_from_slice(b" },");
    }
    if !entries.is_empty() {
        out.pop();
    }
    out.extend_from_slice(b"\r\n]");
    if !callback.is_empty() {
        out.extend_from_slice(b");");
    }
    Ok(out)
}

/// The `callback` argument as sent (empty if absent); `Err` for a name
/// nginx answers 400 to (ngx_http_autoindex_jsonp_callback).
pub fn jsonp_callback(args: &[u8]) -> Result<&[u8], ()> {
    let Some(cb) = query_arg(args, b"callback") else {
        return Ok(&[]);
    };
    if cb.len() > 128
        || !cb
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
    {
        return Err(());
    }
    Ok(cb)
}

struct Entry {
    file_name: OsString,
    is_dir: bool,
    /// A regular file; neither this nor `is_dir` is nginx's "other".
    is_file: bool,
    size: u64,
    mtime: u64,
}

impl Entry {
    fn kind(&self) -> &'static [u8] {
        if self.is_dir {
            b"directory"
        } else if self.is_file {
            b"file"
        } else {
            b"other"
        }
    }
}

fn read_sorted_entries(dir_path: &Path) -> std::io::Result<Vec<Entry>> {
    let mut entries: Vec<Entry> = Vec::new();
    for item in std::fs::read_dir(dir_path)? {
        let item = match item {
            Ok(v) => v,
            Err(_) => continue,
        };
        let file_name = item.file_name();
        // nginx leaves out every name that starts with a dot (`.htpasswd`,
        // `.git`, `.env`, and `.`/`..`): ngx_http_autoindex_handler skips
        // `ngx_de_name(&dir)[0] == '.'`.
        if file_name.as_os_str().as_bytes().first() == Some(&b'.') {
            continue;
        }
        // `fs::metadata` follows symlinks (vs. `DirEntry::metadata`,
        // which does not). nginx's autoindex follows symlinks too —
        // `ngx_http_autoindex_module.c` calls `ngx_de_info` which is
        // `stat(2)`, not `lstat(2)`.
        // A dangling or looping link is listed as itself (ngx_de_link_info
        // after ENOENT / ELOOP).
        let metadata = match std::fs::metadata(item.path()) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ELOOP) =>
            {
                match std::fs::symlink_metadata(item.path()) {
                    Ok(v) => v,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };

        let is_dir = metadata.is_dir();
        let is_file = metadata.is_file();
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
            is_file,
            size,
            mtime,
        });
    }

    // ngx_http_autoindex_cmp_entries: directories first, then by name.
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then_with(|| {
            a.file_name
                .as_os_str()
                .as_bytes()
                .cmp(b.file_name.as_os_str().as_bytes())
        })
    });
    Ok(entries)
}

/// Width of the name column (`NGX_HTTP_AUTOINDEX_NAME_LEN`).
const NAME_LEN: usize = 50;

/// One line of nginx's HTML listing, written in place. Names are measured
/// in bytes, as nginx does without `charset utf-8`.
fn write_entry_line(out: &mut Vec<u8>, entry: &Entry, exact_size: bool, offset: i64) {
    let name = entry.file_name.as_os_str().as_bytes();
    out.extend_from_slice(b"<a href=\"");
    percent_encode_into(out, name);
    if entry.is_dir {
        out.push(b'/');
    }
    out.extend_from_slice(b"\">");
    let mut len = name.len();
    if len > NAME_LEN {
        escape_html_into(out, &name[..NAME_LEN - 3]);
        out.extend_from_slice(b"..&gt;</a>");
    } else {
        escape_html_into(out, name);
        if entry.is_dir && NAME_LEN > len {
            out.push(b'/');
            len += 1;
        }
        out.extend_from_slice(b"</a>");
        out.resize(out.len() + (NAME_LEN - len), b' ');
    }
    out.push(b' ');
    write_listing_time(out, entry.mtime as i64 + offset);
    out.push(b' ');
    match (exact_size, entry.is_dir) {
        (true, true) => out.extend_from_slice(b"                  -"),
        (true, false) => write_right(out, entry.size, None, 19),
        (false, true) => out.extend_from_slice(b"      -"),
        (false, false) => {
            const K: u64 = 1024;
            const M: u64 = 1024 * K;
            const G: u64 = 1024 * M;
            let size = entry.size;
            // Rounded to the nearest unit, as nginx does.
            let (n, scale) = if size > G - 1 {
                (size / G + u64::from(size % G > G / 2 - 1), Some(b'G'))
            } else if size > M - 1 {
                (size / M + u64::from(size % M > M / 2 - 1), Some(b'M'))
            } else if size > 9999 {
                (size / K + u64::from(size % K > 511), Some(b'K'))
            } else {
                (size, None)
            };
            if scale.is_none() {
                out.push(b' ');
            }
            write_right(out, n, scale, 6);
        }
    }
    out.extend_from_slice(b"\r\n");
}

/// `n` right-aligned in `width` columns, then `suffix` (nginx's `%6i%c`).
fn write_right(out: &mut Vec<u8>, n: u64, suffix: Option<u8>, width: usize) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let text = &digits[i..];
    out.resize(out.len() + width.saturating_sub(text.len()), b' ');
    out.extend_from_slice(text);
    if let Some(c) = suffix {
        out.push(c);
    }
}

const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// (year, month 0..=11, day, hour, minute, second) of a time in seconds
/// since the epoch, before 1970 clamped to it.
fn split_time(secs: i64) -> (u32, usize, u8, u8, u8, u8) {
    let secs = secs.max(0) as u64;
    let (year, mon, day) = crate::file::civil_from_days(secs / 86_400);
    let hms = secs % 86_400;
    (
        year,
        mon,
        day,
        (hms / 3600) as u8,
        ((hms % 3600) / 60) as u8,
        (hms % 60) as u8,
    )
}

fn two(out: &mut Vec<u8>, n: u8) {
    out.push(b'0' + n / 10);
    out.push(b'0' + n % 10);
}

/// `05-Mar-2024 07:08` (nginx's `%02d-%s-%d %02d:%02d`).
fn write_listing_time(out: &mut Vec<u8>, secs: i64) {
    let (year, mon, day, hour, min, _) = split_time(secs);
    two(out, day);
    out.push(b'-');
    out.extend_from_slice(MONTHS[mon]);
    out.push(b'-');
    write_right(out, u64::from(year), None, 0);
    out.push(b' ');
    two(out, hour);
    out.push(b':');
    two(out, min);
}

/// `2024-03-05T07:08:09Z` for the XML listing.
fn format_xml_timestamp(secs: u64) -> String {
    let (year, mon, day, hour, min, sec) = split_time(secs.min(i64::MAX as u64) as i64);
    format!(
        "{year:04}-{:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z",
        mon + 1
    )
}

/// The JSON listing's IMF-fixdate.
fn format_httpdate(secs: u64) -> String {
    String::from_utf8_lossy(&crate::file::format_http_date(secs)).into_owned()
}

fn escape_html_into(out: &mut Vec<u8>, input: &[u8]) {
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            _ => out.push(b),
        }
    }
}

fn percent_encode_into(out: &mut Vec<u8>, input: &[u8]) {
    for &b in input {
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex((b >> 4) & 0x0f));
            out.push(hex(b & 0x0f));
        }
    }
}

#[cfg(test)]
fn percent_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    percent_encode_into(&mut out, input);
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

/// ngx_escape_json: `"` and `\\` escaped, control bytes as `\\n`-style or
/// `\\u00XX`, any other byte as it is.
fn escape_json_into(out: &mut Vec<u8>, input: &[u8]) {
    for &b in input {
        match b {
            b'"' | b'\\' => out.extend_from_slice(&[b'\\', b]),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0..=0x1f => {
                out.extend_from_slice(&[b'\\', b'u', b'0', b'0', b'0' + (b >> 4), hex(b & 0x0f)])
            }
            _ => out.push(b),
        }
    }
}

fn query_arg<'a>(args: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    for pair in args.split(|&b| b == b'&') {
        let (k, v) = match pair.iter().position(|&b| b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        // ngx_http_arg: the name matches whatever its case.
        if k.eq_ignore_ascii_case(key) {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_escapes_reserved_bytes() {
        assert_eq!(percent_encode(b"abc:de?f%"), b"abc%3Ade%3Ff%25");
    }

    fn line(name: &str, is_dir: bool, size: u64, exact: bool) -> String {
        let entry = Entry {
            file_name: OsString::from(name),
            is_dir,
            is_file: !is_dir,
            size,
            mtime: 1_709_622_489, // 2024-03-05 07:08:09 UTC
        };
        let mut out = Vec::new();
        write_entry_line(&mut out, &entry, exact, 0);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn lines_match_nginx() {
        assert_eq!(
            line("a&b<c>.html", false, 0, true),
            "<a href=\"a%26b%3Cc%3E.html\">a&amp;b&lt;c&gt;.html</a>                                        \
             05-Mar-2024 07:08                   0\r\n"
        );
        assert_eq!(
            line("dir", true, 4096, true),
            "<a href=\"dir/\">dir/</a>                                               \
             05-Mar-2024 07:08                   -\r\n"
        );
        let long = "very_long_name_that_goes_past_the_fifty_character_column.txt";
        assert_eq!(
            line(long, false, 3_000_000, false),
            format!(
                "<a href=\"{long}\">{}..&gt;</a> 05-Mar-2024 07:08      3M\r\n",
                &long[..47]
            )
        );
    }

    #[test]
    fn sizes_round_like_nginx_when_not_exact() {
        let size = |n| {
            let l = line("f", false, n, false);
            l[l.len() - 9..l.len() - 2].to_string()
        };
        assert_eq!(size(1_500), "   1500");
        assert_eq!(size(9_999), "   9999");
        assert_eq!(size(10_000), "    10K");
        assert_eq!(size(15_000), "    15K");
        assert_eq!(size(1_048_576), "     1M");
        assert_eq!(size(3_000_000), "     3M");
    }

    /// Byte for byte what nginx 1.30 sends for the same directory (#802):
    /// names as on disk, escaped as ngx_escape_json / ngx_escape_html,
    /// a dangling link as "other".
    #[test]
    fn json_and_xml_are_laid_out_like_nginx() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("ruxen-autoindex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join(std::ffi::OsStr::from_bytes(b"a\"\\\x01<\xe9")),
            b"12345",
        )
        .unwrap();
        std::os::unix::fs::symlink("/nonexistent", dir.join("b")).unwrap();
        let t = std::fs::FileTimes::new()
            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000));
        for name in [&b"sub"[..], b"a\"\\\x01<\xe9"] {
            std::fs::File::open(dir.join(std::ffi::OsStr::from_bytes(name)))
                .unwrap()
                .set_times(t)
                .unwrap();
        }
        let link_mtime = format_httpdate(
            std::fs::symlink_metadata(dir.join("b"))
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let date = "Tue, 14 Nov 2023 22:13:20 GMT";
        let entries = format!(
            "[\r\n{{ \"name\":\"sub\", \"type\":\"directory\", \"mtime\":\"{date}\" }},\r\n\
             {{ \"name\":\"a\\\"\\\\\\u0001<\u{e9}\", \"type\":\"file\", \"mtime\":\"{date}\", \"size\":5 }},\r\n\
             {{ \"name\":\"b\", \"type\":\"other\", \"mtime\":\"{link_mtime}\" }}\r\n]"
        )
        .replace('\u{e9}', "\u{fffd}");
        let lossy = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
        let json = render_json(&dir, b"").unwrap();
        assert!(json.contains(&0xe9), "the raw name");
        assert_eq!(lossy(json), entries);
        assert_eq!(
            lossy(render_json(&dir, b"cb").unwrap()),
            format!("/* callback */\r\ncb({entries});")
        );
        let xml = lossy(render_xml(&dir).unwrap());
        assert!(
            xml.starts_with(
                "<?xml version=\"1.0\"?>\r\n<list>\r\n\
                 <directory mtime=\"2023-11-14T22:13:20Z\">sub</directory>\r\n\
                 <file mtime=\"2023-11-14T22:13:20Z\" size=\"5\">a&quot;\\\u{1}&lt;\u{fffd}</file>\r\n\
                 <other mtime=\""
            ),
            "{xml}"
        );
        assert!(xml.ends_with("\">b</other>\r\n</list>\r\n"), "{xml}");
        let _ = std::fs::remove_dir_all(&dir);
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(render_json(&empty, b"").unwrap(), b"[\r\n]");
        assert_eq!(
            render_xml(&empty).unwrap(),
            b"<?xml version=\"1.0\"?>\r\n<list>\r\n</list>\r\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
