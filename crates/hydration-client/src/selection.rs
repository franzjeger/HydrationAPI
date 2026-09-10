//! Per-device folder exclusions stored as metadata on the sync root. No file
//! contents are read or written, and changing selection never removes files.
use crate::store::{get_xattr, set_xattr};
use std::io;
use std::path::{Component, Path};
pub const XATTR: &str = "user.hydration.selection";
const APPLIED: &str = "user.hydration.selection_applied";

pub fn validate(paths: &[String]) -> io::Result<Vec<String>> {
    if paths.len() > 200 {
        return Err(io::Error::other("Choose at most 200 excluded folders"));
    }
    let mut paths = paths.to_vec();
    for p in &paths {
        if p.is_empty()
            || p.len() > 2048
            || p.contains(['\0', '\n', '\r'])
            || p.starts_with('/')
            || p.split('/').any(|s| s.is_empty() || s == "." || s == "..")
            || Path::new(p)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(io::Error::other(
                "Choose a folder relative to the OneDrive root",
            ));
        }
    }
    paths.sort();
    paths.dedup();
    let all = paths.clone();
    paths.retain(|p| {
        !all.iter()
            .any(|parent| p != parent && Path::new(p).starts_with(parent))
    });
    if serde_json::to_vec(&paths)?.len() > 16000 {
        return Err(io::Error::other("Folder selection is too large"));
    }
    Ok(paths)
}
pub fn read(root: &Path) -> io::Result<Vec<String>> {
    match get_xattr(root, XATTR)? {
        None => Ok(Vec::new()),
        Some(bytes) => {
            if bytes.len() > 16000 {
                return Err(io::Error::other("Invalid folder selection"));
            }
            validate(&serde_json::from_slice::<Vec<String>>(&bytes)?)
        }
    }
}
pub fn write(root: &Path, paths: &[String]) -> io::Result<()> {
    set_xattr(root, XATTR, &serde_json::to_vec(&validate(paths)?)?)
}
pub fn applied(root: &Path) -> io::Result<Vec<String>> {
    match get_xattr(root, APPLIED)? {
        None => Ok(Vec::new()),
        Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
    }
}
pub fn mark_applied(root: &Path, paths: &[String]) -> io::Result<()> {
    let bytes = serde_json::to_vec(paths)?;
    if get_xattr(root, APPLIED)?.as_deref() == Some(bytes.as_slice()) {
        return Ok(());
    }
    set_xattr(root, APPLIED, &bytes)
}
pub fn contains(paths: &[String], relative: &Path) -> bool {
    paths.iter().any(|p| relative.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusion_is_exact_root_relative_and_persists_without_touching_content() {
        let root = test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            "folder-selection",
        );
        write(&root, &["Docs".into(), "Docs/nested".into(), "a #b".into()]).unwrap();
        let paths = read(&root).unwrap();
        assert_eq!(paths, vec!["Docs", "a #b"]);
        assert!(contains(&paths, Path::new("Docs/file")));
        assert!(!contains(&paths, Path::new("Other/Docs/file")));
        assert!(!contains(&paths, Path::new("Docs2/file")));
        for bad in [
            "",
            "../out",
            "/out",
            "Docs/../out",
            "Docs//child",
            "Docs/",
            "Docs\nchild",
        ] {
            assert!(write(&root, &[bad.into()]).is_err());
        }
        mark_applied(&root, &paths).unwrap();
        assert_eq!(applied(&root).unwrap(), paths);
        write(&root, &[]).unwrap();
        assert_ne!(
            read(&root).unwrap(),
            applied(&root).unwrap(),
            "re-inclusion requires a fresh listing"
        );
    }
}
