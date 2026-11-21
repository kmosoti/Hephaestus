//! Enforce full 40-hex commit SHA pinning on all GitHub Actions workflows.

use std::fmt;
use std::path::Path;

/// A workflow `uses:` reference not pinned to an immutable reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnpinnedAction {
    pub(crate) file: String,
    pub(crate) line: usize,
    pub(crate) uses: String,
}

impl fmt::Display for UnpinnedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[workflow-action-unpinned] {}:{}: `{}` is not pinned to a 40-char commit SHA",
            self.file, self.line, self.uses
        )
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Checks whether a `uses:` target is pinned to a full SHA, local path, or container digest.
pub(crate) fn is_pinned(uses: &str) -> bool {
    if uses.starts_with("./") {
        return true;
    }
    if let Some(image) = uses.strip_prefix("docker://") {
        return image
            .split_once("@sha256:")
            .is_some_and(|(_, digest)| is_lower_hex(digest, 64));
    }
    uses.split_once('@')
        .is_some_and(|(action, reference)| action.contains('/') && is_lower_hex(reference, 40))
}

fn extract_uses(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim_start().trim_start_matches("- ").trim_start();
            let raw = trimmed.strip_prefix("uses:")?;
            let before_comment = raw.split(" #").next().unwrap_or(raw);
            let value = before_comment
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            Some((idx + 1, value.to_owned()))
        })
        .collect()
}

/// Checks every `.yml` / `.yaml` workflow file in `dir`.
pub(crate) fn check(dir: &Path) -> Result<Vec<UnpinnedAction>, String> {
    if !dir.is_dir() {
        return Err(format!("workflows directory missing: {}", dir.display()));
    }
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no workflow YAML files found in {}", dir.display()));
    }

    let mut unpinned = Vec::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let name = file
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        for (line, uses) in extract_uses(&text) {
            if !is_pinned(&uses) {
                unpinned.push(UnpinnedAction {
                    file: name.clone(),
                    line,
                    uses,
                });
            }
        }
    }
    Ok(unpinned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "11d5960a326750d5838078e36cf38b85af677262";

    #[test]
    fn rejects_mutable_tags_and_accepts_full_shas() {
        assert!(is_pinned(&format!("actions/checkout@{SHA}")));
        assert!(is_pinned("./.github/actions/local"));
        assert!(is_pinned(&format!(
            "docker://ghcr.io/example/img@sha256:{}",
            "a".repeat(64)
        )));
        for bad in [
            "actions/checkout@v4",
            "dtolnay/rust-toolchain@master",
            "actions/checkout@11d5960",
            &format!("actions/checkout@{}", SHA.to_uppercase()),
            "docker://alpine:3.20",
        ] {
            assert!(!is_pinned(bad), "expected unpinned for `{bad}`");
        }
    }

    #[test]
    fn check_reports_unpinned_lines() {
        let dir = std::env::temp_dir().join(format!("hep-pins-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("ci.yml"),
            format!("steps:\n  - uses: actions/checkout@{SHA} # v4\n  - uses: actions/cache@v4\n"),
        )
        .unwrap();
        let bad = check(&dir).unwrap();
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].line, 3);
        assert_eq!(bad[0].uses, "actions/cache@v4");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
