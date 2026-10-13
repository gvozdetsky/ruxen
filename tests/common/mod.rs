// Shared scaffolding for integration tests. Keep new helpers in their own
// submodule (e.g. `tls.rs`) rather than dumping into `mod.rs` so unrelated
// tests don't compile cert-gen / openssl machinery.
//
// Cargo treats `tests/common/mod.rs` (not `tests/common.rs`) as a non-binary
// helper, so test files that don't `mod common;` won't link these symbols.

#![allow(dead_code)] // not every integration test consumes every helper

pub mod ports;
pub mod tls;

/// An errno as ruxen (and nginx) print it, `98: Address already in use`,
/// in this libc's words: musl says `Address in use`.
pub fn errno_text(code: i32) -> String {
    let text = std::io::Error::from_raw_os_error(code).to_string();
    let reason = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    format!("{code}: {reason}")
}
