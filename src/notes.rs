//! Filesystem operations for the note tree, with path containment.
//!
//! Every caller-supplied path is treated as relative to `FSGATE_ROOT` and is
//! rejected if it is absolute or contains a `..` component. Where the target
//! already exists we additionally canonicalize and re-check containment, which
//! closes symlink-escape holes for reads and patches. There is deliberately no
//! delete or overwrite operation (see README threat model).

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::auth::random_token;

/// A single full-text search hit.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchHit {
    pub path: String,
    pub line: usize,
    pub text: String,
}

/// A note tree rooted at a canonicalized absolute directory.
#[derive(Debug, Clone)]
pub struct Notes {
    root: PathBuf,
}

impl Notes {
    pub fn new(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot canonicalize root {}", root.display()))?;
        Ok(Self { root })
    }

    /// Lexical containment: reject absolute paths and any `..` component, then
    /// join under root. This alone guarantees the joined path is textually
    /// inside root; canonicalization (below) additionally defeats symlinks.
    fn resolve(&self, rel: &str) -> Result<PathBuf> {
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            bail!("path must not be empty");
        }
        let candidate = Path::new(rel);
        for component in candidate.components() {
            match component {
                Component::ParentDir => bail!("path traversal ('..') is not allowed"),
                Component::Prefix(_) | Component::RootDir => {
                    bail!("absolute paths are not allowed")
                }
                _ => {}
            }
        }
        Ok(self.root.join(candidate))
    }

    /// Resolves an existing file and verifies its canonical path is within root.
    fn resolve_existing(&self, rel: &str) -> Result<PathBuf> {
        let path = self.resolve(rel)?;
        let canonical = path
            .canonicalize()
            .with_context(|| format!("{rel}: no such file"))?;
        if !canonical.starts_with(&self.root) {
            bail!("{rel}: resolves outside the served root");
        }
        if !canonical.is_file() {
            bail!("{rel}: not a regular file");
        }
        Ok(canonical)
    }

    pub fn read(&self, rel: &str) -> Result<String> {
        let path = self.resolve_existing(rel)?;
        fs::read_to_string(&path).with_context(|| format!("cannot read {rel}"))
    }

    /// Creates a new file, failing if it already exists. Parent directories are
    /// created as needed. Uses `create_new` for an atomic exclusive create.
    pub fn create(&self, rel: &str, content: &str) -> Result<()> {
        use std::io::Write;

        let path = self.resolve(rel)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create parent dirs for {rel}"))?;
            // Re-check containment now that the parent exists (defeats symlinks).
            let canonical_parent = parent
                .canonicalize()
                .with_context(|| format!("cannot canonicalize parent of {rel}"))?;
            if !canonical_parent.starts_with(&self.root) {
                bail!("{rel}: resolves outside the served root");
            }
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("{rel}: already exists or cannot be created"))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("cannot write {rel}"))?;
        Ok(())
    }

    /// Replaces exactly one occurrence of `old` with `new`. Fails if `old` is
    /// absent or ambiguous (appears more than once) — a blind full-file
    /// overwrite is never performed. The write is atomic (temp file + rename).
    pub fn patch(&self, rel: &str, old: &str, new: &str) -> Result<()> {
        if old.is_empty() {
            bail!("old_str must not be empty");
        }
        let path = self.resolve_existing(rel)?;
        let content = fs::read_to_string(&path).with_context(|| format!("cannot read {rel}"))?;

        let occurrences = content.matches(old).count();
        match occurrences {
            0 => bail!("{rel}: old_str not found"),
            1 => {}
            n => bail!("{rel}: old_str is ambiguous ({n} occurrences); include more context"),
        }

        let updated = content.replacen(old, new, 1);
        self.atomic_write(&path, &updated)
    }

    /// Lists regular files under an optional relative prefix, returning paths
    /// relative to root. Hidden entries (dotfiles/dotdirs) are skipped.
    pub fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let start = match prefix {
            Some(p) if !p.trim().is_empty() => self.resolve(p)?,
            _ => self.root.clone(),
        };
        let mut out = Vec::new();
        if start.is_file() {
            if let Ok(rel) = start.strip_prefix(&self.root) {
                out.push(rel.to_string_lossy().into_owned());
            }
            return Ok(out);
        }
        self.walk(&start, &mut |file| {
            if let Ok(rel) = file.strip_prefix(&self.root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        })?;
        out.sort();
        Ok(out)
    }

    /// Case-insensitive full-text search across the tree, capped at `limit` hits.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        if query.trim().is_empty() {
            bail!("query must not be empty");
        }
        let needle = query.to_lowercase();
        let mut hits = Vec::new();
        self.walk(&self.root, &mut |file| {
            if hits.len() >= limit {
                return;
            }
            // Skip files we cannot read as UTF-8 (binaries, etc.).
            let Ok(content) = fs::read_to_string(file) else {
                return;
            };
            let rel = file
                .strip_prefix(&self.root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            for (i, line) in content.lines().enumerate() {
                if hits.len() >= limit {
                    break;
                }
                if line.to_lowercase().contains(&needle) {
                    hits.push(SearchHit {
                        path: rel.clone(),
                        line: i + 1,
                        text: line.trim().to_string(),
                    });
                }
            }
        })?;
        Ok(hits)
    }

    /// Depth-first walk yielding regular files, skipping hidden entries.
    fn walk(&self, dir: &Path, visit: &mut impl FnMut(&Path)) -> Result<()> {
        let entries =
            fs::read_dir(dir).with_context(|| format!("cannot read dir {}", dir.display()))?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.walk(&path, visit)?;
            } else if file_type.is_file() {
                visit(&path);
            }
        }
        Ok(())
    }

    /// Atomic write: temp file in the same directory, then rename over target.
    fn atomic_write(&self, path: &Path, content: &str) -> Result<()> {
        let dir = path.parent().unwrap_or(&self.root);
        let tmp = dir.join(format!(".fsgate-tmp-{}", random_token()));
        fs::write(&tmp, content)
            .with_context(|| format!("cannot write temp for {}", path.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("cannot finalize {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_notes() -> (Notes, PathBuf) {
        let base = std::env::temp_dir().join(format!("fsgate-test-{}", random_token()));
        fs::create_dir_all(&base).unwrap();
        (Notes::new(&base).unwrap(), base)
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        let (notes, _dir) = temp_notes();
        assert!(notes.read("../etc/passwd").is_err());
        assert!(notes.create("../evil.md", "x").is_err());
    }

    #[test]
    fn rejects_absolute_paths() {
        let (notes, _dir) = temp_notes();
        assert!(notes.read("/etc/passwd").is_err());
    }

    #[test]
    fn create_read_roundtrip_and_no_overwrite() {
        let (notes, _dir) = temp_notes();
        notes.create("sub/a.md", "hello").unwrap();
        assert_eq!(notes.read("sub/a.md").unwrap(), "hello");
        // create must fail on an existing file.
        assert!(notes.create("sub/a.md", "again").is_err());
    }

    #[test]
    fn patch_requires_unambiguous_match() {
        let (notes, _dir) = temp_notes();
        notes.create("n.md", "one two one").unwrap();
        // Ambiguous: "one" appears twice.
        assert!(notes.patch("n.md", "one", "X").is_err());
        // Unique replacement.
        notes.patch("n.md", "two", "2").unwrap();
        assert_eq!(notes.read("n.md").unwrap(), "one 2 one");
        // Missing old_str.
        assert!(notes.patch("n.md", "absent", "X").is_err());
    }

    #[test]
    fn search_and_list_find_created_files() {
        let (notes, _dir) = temp_notes();
        notes.create("a.md", "alpha keyword here").unwrap();
        notes.create("b/c.md", "beta").unwrap();

        let hits = notes.search("KEYWORD", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "a.md");

        let mut listed = notes.list(None).unwrap();
        listed.sort();
        assert_eq!(listed, vec!["a.md".to_string(), "b/c.md".to_string()]);
    }
}
