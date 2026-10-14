// Shared scaffolding for integration tests. Keep new helpers in their own
// submodule (e.g. `tls.rs`) rather than dumping into `mod.rs` so unrelated
// tests don't compile cert-gen / openssl machinery.
//
// Cargo treats `tests/common/mod.rs` (not `tests/common.rs`) as a non-binary
// helper, so test files that don't `mod common;` won't link these symbols.

#![allow(dead_code)] // not every integration test consumes every helper

pub mod ports;
pub mod tls;

/// Owns a ruxen process and stops it when the test ends, also when an
/// assertion panics: an orphaned ruxen otherwise keeps its ports and CPU
/// after the run. Wrap the child before waiting for it to be ready.
/// Derefs to the `Child`, for signals and `try_wait`.
pub struct KillOnDrop(pub std::process::Child);

impl std::ops::Deref for KillOnDrop {
    type Target = std::process::Child;
    fn deref(&self) -> &std::process::Child {
        &self.0
    }
}

impl std::ops::DerefMut for KillOnDrop {
    fn deref_mut(&mut self) -> &mut std::process::Child {
        &mut self.0
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// An errno as ruxen (and nginx) print it, `98: Address already in use`,
/// in this libc's words: musl says `Address in use`.
pub fn errno_text(code: i32) -> String {
    let text = std::io::Error::from_raw_os_error(code).to_string();
    let reason = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    format!("{code}: {reason}")
}
