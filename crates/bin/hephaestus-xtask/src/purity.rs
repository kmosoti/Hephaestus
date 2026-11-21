//! Enforce `crates/core/PURITY.toml` across all crates under `crates/core/`.

use crate::layers::cargo_metadata_platform;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

const POLICY_PATH: &str = "crates/core/PURITY.toml";

#[derive(Debug, Deserialize)]
struct PolicyFile {
    policy: PolicyRules,
    #[serde(default)]
    crates: BTreeMap<String, toml::Value>,
    #[serde(default)]
    allow: BTreeMap<String, AllowRule>,
    #[serde(default)]
    deny: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PolicyRules {
    no_std: bool,
    build_scripts: bool,
    #[serde(default)]
    required_lints: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AllowRule {
    #[serde(default)]
    default_features: bool,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    transitive: Vec<String>,
}

fn denied_lookup(deny: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (class, crates) in deny {
        for name in crates {
            map.insert(name.clone(), class.clone());
        }
    }
    map
}

fn check_policy_consistency(policy: &PolicyFile, denied: &BTreeMap<String, String>) -> Vec<String> {
    let mut errs = Vec::new();
    for (crate_name, rule) in &policy.allow {
        if let Some(class) = denied.get(crate_name) {
            errs.push(format!(
                "IMPURE [purity-policy-allows-denied-class]: allow `{crate_name}` is in denied class `{class}`"
            ));
        }
        for tr in &rule.transitive {
            if let Some(class) = denied.get(tr) {
                errs.push(format!(
                    "IMPURE [purity-policy-allows-denied-class]: transitive `{tr}` under `{crate_name}` is in denied class `{class}`"
                ));
            }
        }
    }
    errs
}

fn check_crate_source_and_manifest(
    crate_dir: &Path,
    crate_name: &str,
    rules: &PolicyRules,
    has_custom_build: bool,
) -> Vec<String> {
    let mut errs = Vec::new();
    if !rules.build_scripts && has_custom_build {
        errs.push(format!(
            "IMPURE [core-build-script]: `{crate_name}` has a custom build script"
        ));
    }

    let manifest_path = crate_dir.join("Cargo.toml");
    if let Ok(raw) = std::fs::read_to_string(&manifest_path)
        && let Ok(val) = toml::from_str::<toml::Value>(&raw)
    {
        let ws_lints = val
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        if !ws_lints {
            errs.push(format!(
                "IMPURE [core-lints-not-workspace]: `{crate_name}` Cargo.toml must set `[lints] workspace = true`"
            ));
        }
    }

    let lib_path = crate_dir.join("src/lib.rs");
    match std::fs::read_to_string(&lib_path) {
        Ok(src) => {
            if rules.no_std && !src.contains("#![no_std]") {
                errs.push(format!(
                    "IMPURE [core-no-std-missing]: `{crate_name}` src/lib.rs missing `#![no_std]`"
                ));
            }
            for lint in &rules.required_lints {
                if !src.contains(lint.as_str()) {
                    errs.push(format!(
                        "IMPURE [core-required-lint-missing]: `{crate_name}` src/lib.rs must deny `{lint}`"
                    ));
                }
            }
        }
        Err(err) => errs.push(format!("IMPURE [core-lib-unreadable]: {crate_name}: {err}")),
    }
    errs
}

/// Enforces `crates/core/PURITY.toml` on every workspace crate under `crates/core/`.
pub(crate) fn check_workspace(root: &Path) -> Result<usize, String> {
    let policy_path = root.join(POLICY_PATH);
    let raw_policy = std::fs::read_to_string(&policy_path).map_err(|e| {
        format!(
            "IMPURE [purity-policy-missing]: {}: {e}",
            policy_path.display()
        )
    })?;
    let policy: PolicyFile = toml::from_str(&raw_policy)
        .map_err(|e| format!("IMPURE [purity-policy-malformed]: {e}"))?;

    let denied = denied_lookup(&policy.deny);
    let mut violations = check_policy_consistency(&policy, &denied);

    let meta = cargo_metadata_platform(root, false, Some("x86_64-unknown-linux-gnu"))?;
    let packages = meta["packages"]
        .as_array()
        .ok_or("cargo metadata missing packages")?;
    let members: BTreeSet<String> = meta["workspace_members"]
        .as_array()
        .ok_or("cargo metadata missing workspace_members")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();

    let mut id_to_pkg: BTreeMap<String, &Value> = BTreeMap::new();
    let mut core_pkgs: Vec<&Value> = Vec::new();
    for pkg in packages {
        let Some(id) = pkg["id"].as_str() else {
            continue;
        };
        id_to_pkg.insert(id.to_owned(), pkg);
        if !members.contains(id) {
            continue;
        }
        let manifest = Path::new(pkg["manifest_path"].as_str().unwrap_or_default());
        if let Ok(rel) = manifest.strip_prefix(root)
            && rel.starts_with("crates/core")
        {
            core_pkgs.push(pkg);
        }
    }

    let mut seen_core = BTreeSet::new();
    for pkg in &core_pkgs {
        let name = pkg["name"].as_str().unwrap_or_default().to_owned();
        seen_core.insert(name.clone());
        if !policy.crates.contains_key(&name) {
            violations.push(format!(
                "IMPURE [core-crate-unlisted]: `{name}` is missing from {POLICY_PATH} [crates]"
            ));
        }

        let manifest = Path::new(pkg["manifest_path"].as_str().unwrap_or_default());
        let crate_dir = manifest.parent().unwrap_or(root);
        let has_build = pkg["targets"].as_array().into_iter().flatten().any(|t| {
            t["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k.as_str() == Some("custom-build"))
        });
        violations.extend(check_crate_source_and_manifest(
            crate_dir,
            &name,
            &policy.policy,
            has_build,
        ));

        for dep in pkg["dependencies"].as_array().into_iter().flatten() {
            let kind = dep["kind"].as_str();
            if kind == Some("dev") {
                continue;
            }
            let dep_name = dep["name"].as_str().unwrap_or_default();
            if let Some(class) = denied.get(dep_name) {
                violations.push(format!(
                    "IMPURE [core-dependency-denied-class]: `{name}` -> `{dep_name}` (class `{class}`)"
                ));
                continue;
            }
            if let Some(rule) = policy.allow.get(dep_name) {
                let uses_default = dep["uses_default_features"].as_bool().unwrap_or(true);
                if !rule.default_features && uses_default {
                    violations.push(format!(
                        "IMPURE [core-dependency-features]: `{name}` -> `{dep_name}` must disable default-features"
                    ));
                }
                for f in dep["features"].as_array().into_iter().flatten() {
                    if let Some(fs) = f.as_str()
                        && !rule.features.iter().any(|allowed| allowed == fs)
                    {
                        violations.push(format!(
                            "IMPURE [core-dependency-features]: `{name}` -> `{dep_name}` enables unlisted feature `{fs}`"
                        ));
                    }
                }
            } else {
                violations.push(format!(
                    "IMPURE [core-dependency-not-allowlisted]: `{name}` -> `{dep_name}`"
                ));
            }
        }
    }

    for listed in policy.crates.keys() {
        if !seen_core.contains(listed) {
            violations.push(format!(
                "IMPURE [purity-policy-names-unknown-crate]: `{listed}` not under crates/core/"
            ));
        }
    }

    let mut resolve_adj: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for node in meta["resolve"]["nodes"].as_array().into_iter().flatten() {
        let Some(id) = node["id"].as_str() else {
            continue;
        };
        let mut edges = Vec::new();
        for d in node["deps"].as_array().into_iter().flatten() {
            let Some(dpkg) = d["pkg"].as_str() else {
                continue;
            };
            let normal_dep = d["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k["kind"].is_null());
            if normal_dep {
                let dname = id_to_pkg
                    .get(dpkg)
                    .and_then(|p| p["name"].as_str())
                    .unwrap_or_default()
                    .to_owned();
                edges.push((dpkg.to_owned(), dname));
            }
        }
        resolve_adj.insert(id.to_owned(), edges);
    }

    let all_allowed_transitive: BTreeSet<String> = policy
        .allow
        .iter()
        .flat_map(|(k, r)| std::iter::once(k.clone()).chain(r.transitive.iter().cloned()))
        .collect();

    for pkg in &core_pkgs {
        let root_id = pkg["id"].as_str().unwrap_or_default();
        let root_name = pkg["name"].as_str().unwrap_or_default();
        let mut q = VecDeque::from([root_id.to_owned()]);
        let mut visited = BTreeSet::from([root_id.to_owned()]);
        while let Some(cur) = q.pop_front() {
            for (next_id, next_name) in resolve_adj.get(&cur).into_iter().flatten() {
                if let Some(class) = denied.get(next_name) {
                    violations.push(format!(
                        "IMPURE [core-transitive-dependency-denied-class]: `{root_name}` reaches `{next_name}` (class `{class}`)"
                    ));
                } else if !seen_core.contains(next_name)
                    && !all_allowed_transitive.contains(next_name)
                {
                    violations.push(format!(
                        "IMPURE [core-transitive-dependency-not-allowlisted]: `{root_name}` reaches `{next_name}`"
                    ));
                }
                if visited.insert(next_id.clone()) {
                    q.push_back(next_id.clone());
                }
            }
        }
    }

    violations.sort();
    violations.dedup();
    if !violations.is_empty() {
        return Err(violations.join("\n"));
    }
    Ok(core_pkgs.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_policy_allowing_denied_crate() {
        let policy: PolicyFile = toml::from_str(
            r#"
[policy]
no_std = true
build_scripts = false

[allow.tokio]
default_features = false

[deny]
async-runtime = ["tokio"]
"#,
        )
        .unwrap();
        let denied = denied_lookup(&policy.deny);
        let errs = check_policy_consistency(&policy, &denied);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("purity-policy-allows-denied-class"));
    }
}
