//! Where a project's vault lives: `<root>/.vahta/vault.vht`.
//!
//! The root is the nearest directory, from the one you are in upward, that
//! holds a `.vahta/` directory. `.vahta/` carries a `.gitignore` containing
//! `*`, so the vault, its lock and its backups are never committed whatever the
//! project's own ignore rules say. `vahta.toml` sits at the root, outside
//! `.vahta/`, because it is the committed part.

use std::fs;
use std::path::{Path, PathBuf};

use crate::Error;

pub const DIR_NAME: &str = ".vahta";
pub const VAULT_NAME: &str = "vault.vht";
pub const MANIFEST_NAME: &str = "vahta.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub root: PathBuf,
}

impl Project {
    /// The project containing `start`, if any `.vahta/` directory is on the
    /// way up from it.
    pub fn find(start: &Path) -> Option<Project> {
        start
            .ancestors()
            .find(|dir| dir.join(DIR_NAME).is_dir())
            .map(|root| Project {
                root: root.to_path_buf(),
            })
    }

    /// The project containing `start` for a command that must also work where
    /// the vault does not (CI): the nearest directory with either a `.vahta/`
    /// directory or a `vahta.toml`.
    pub fn find_contract(start: &Path) -> Option<Project> {
        start
            .ancestors()
            .find(|dir| dir.join(DIR_NAME).is_dir() || dir.join(MANIFEST_NAME).is_file())
            .map(|root| Project {
                root: root.to_path_buf(),
            })
    }

    pub fn dir(&self) -> PathBuf {
        self.root.join(DIR_NAME)
    }

    pub fn vault_path(&self) -> PathBuf {
        self.dir().join(VAULT_NAME)
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_NAME)
    }

    /// Create `.vahta/` and its `.gitignore` under `root`. Safe to repeat.
    pub fn init(root: &Path) -> Result<Project, Error> {
        let project = Project {
            root: root.to_path_buf(),
        };
        let dir = project.dir();
        let io = |op, path: &Path| {
            let path = path.to_path_buf();
            move |source| Error::Io { op, path, source }
        };
        fs::create_dir_all(&dir).map_err(io("create", &dir))?;
        let ignore = dir.join(".gitignore");
        if !ignore.exists() {
            fs::write(&ignore, "*\n").map_err(io("write", &ignore))?;
        }
        Ok(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_nearest_project_upward() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("a");
        let deep = root.join("b").join("c");
        fs::create_dir_all(&deep).unwrap();
        assert_eq!(Project::find(&deep), None);
        Project::init(&root).unwrap();
        assert_eq!(Project::find(&deep).unwrap().root, root);
        assert_eq!(
            fs::read_to_string(root.join(".vahta/.gitignore")).unwrap(),
            "*\n"
        );
        // A nearer project wins.
        Project::init(&root.join("b")).unwrap();
        assert_eq!(Project::find(&deep).unwrap().root, root.join("b"));
    }

    #[test]
    fn init_twice_keeps_a_changed_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        Project::init(tmp.path()).unwrap();
        let p = tmp.path().join(".vahta/.gitignore");
        fs::write(&p, "*\n!keep\n").unwrap();
        Project::init(tmp.path()).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "*\n!keep\n");
    }
}
