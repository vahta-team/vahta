// Included by both `build.rs` (to refuse such a name in an `env_keep`) and the
// crate (`is_redirecting_env`, for the run window), so the two cannot drift.

/// Prefixes (upper case) of variables that can point a program at another
/// place or make it load other code.
const REDIRECTING_ENV: &[&str] = &[
    "NPM_CONFIG",
    "CARGO_REGISTR",
    "TWINE_",
    "PIP_",
    "UV_",
    "GIT_",
    "RUSTFLAGS",
    "NODE_OPTIONS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "LD_",
    "DYLD_",
    "VAHTA_",
];
