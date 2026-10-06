//! What exists only in a test build (the `test-surface` feature): overrides of
//! timing and version, and, from the next step on, the scripted prompt surface.
//!
//! The shipped `vahta` has none of it. [`ENABLED`] says which build this is, so
//! the command line can tell a person that a test build is running without
//! itself carrying any `cfg`. CI fails if `vahta-cli` ever sees the feature.

use crate::server::Options;

/// Whether this is a test build.
pub const ENABLED: bool = cfg!(feature = "test-surface");

/// Apply the test overrides to the daemon's options: the version it reports
/// (`VAHTA_TEST_DAEMON_VERSION`, to stand in for an old daemon) and how long
/// it idles before it exits (`VAHTA_TEST_IDLE_SECONDS`). Does nothing in a
/// shipped build.
pub fn apply_overrides(options: &mut Options) {
    #[cfg(feature = "test-surface")]
    {
        if let Some(v) = std::env::var_os("VAHTA_TEST_DAEMON_VERSION") {
            options.version = v.to_string_lossy().into_owned();
        }
        if let Some(secs) = std::env::var("VAHTA_TEST_IDLE_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            options.idle = std::time::Duration::from_secs(secs);
        }
    }
    #[cfg(not(feature = "test-surface"))]
    let _ = options;
}
