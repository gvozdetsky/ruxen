// Shared scaffolding for integration tests. Keep new helpers in their own
// submodule (e.g. `tls.rs`) rather than dumping into `mod.rs` so unrelated
// tests don't compile cert-gen / openssl machinery.
//
// Cargo treats `tests/common/mod.rs` (not `tests/common.rs`) as a non-binary
// helper, so test files that don't `mod common;` won't link these symbols.

#![allow(dead_code)] // not every integration test consumes every helper

pub mod tls;
