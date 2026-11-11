//! Where Vahta keeps its data and configuration by default: the one place
//! every crate asks, so they cannot disagree.
//!
//! On Linux and macOS these are the platform's own directories (`dirs`). On
//! Windows they are `%USERPROFILE%\.local\share\vahta` and
//! `%USERPROFILE%\.config\vahta`, not `%APPDATA%`: Claude Desktop and Codex are
//! MSIX packages, and for every process descended from one, writes to
//! `%APPDATA%` are redirected into the package's own `LocalCache`. A process
//! inside the package and one outside it (a terminal, the watchdog) would then
//! see two different `%APPDATA%\vahta`, and uninstalling the app would delete
//! the data. The redirection covers AppData only, not the rest of the profile.
//!
//! The home directory must not hold a directory called `.vahta`: a project's
//! vault is found by walking up from the working directory looking for one.

use std::path::{Path, PathBuf};

/// The data directory (store, journal), without any `VAHTA_DATA_DIR` override.
pub fn default_data_dir() -> Option<PathBuf> {
    data_dir_in(dirs::home_dir().as_deref(), cfg!(windows))
}

/// The configuration directory, without any `VAHTA_CONFIG_DIR` override.
pub fn default_config_dir() -> Option<PathBuf> {
    config_dir_in(dirs::home_dir().as_deref(), cfg!(windows))
}

fn data_dir_in(home: Option<&Path>, windows: bool) -> Option<PathBuf> {
    if windows {
        home.map(|h| h.join(".local").join("share").join("vahta"))
    } else {
        dirs::data_dir().map(|d| d.join("vahta"))
    }
}

fn config_dir_in(home: Option<&Path>, windows: bool) -> Option<PathBuf> {
    if windows {
        home.map(|h| h.join(".config").join("vahta"))
    } else {
        dirs::config_dir().map(|d| d.join("vahta"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_keeps_both_outside_appdata_and_not_in_a_dot_vahta() {
        let home = Path::new("home");
        let data = data_dir_in(Some(home), true).unwrap();
        let config = config_dir_in(Some(home), true).unwrap();
        assert_eq!(data, home.join(".local").join("share").join("vahta"));
        assert_eq!(config, home.join(".config").join("vahta"));
        for p in [&data, &config] {
            assert!(!p.components().any(|c| c.as_os_str() == ".vahta"));
        }
        assert_eq!(data_dir_in(None, true), None);
        assert_eq!(config_dir_in(None, true), None);
    }

    #[test]
    fn elsewhere_the_platform_directories_are_used() {
        let home = Path::new("home");
        assert_eq!(
            data_dir_in(Some(home), false),
            dirs::data_dir().map(|d| d.join("vahta"))
        );
        assert_eq!(
            config_dir_in(Some(home), false),
            dirs::config_dir().map(|d| d.join("vahta"))
        );
    }
}
