//! Enforce the hexagonal layer dependency rule via `cargo metadata`.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Layer {
    Core,
    Ports,
    App,
    Adapters,
    Bin,
}

impl Layer {
    fn from_dir_component(name: &str) -> Option<Self> {
        match name {
            "core" => Some(Self::Core),
            "ports" => Some(Self::Ports),
            "app" => Some(Self::App),
            "adapters" => Some(Self::Adapters),
            "bin" => Some(Self::Bin),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Ports => "ports",
            Self::App => "app",
            Self::Adapters => "adapters",
            Self::Bin => "bin",
        }
    }
}

pub(crate) fn cargo_metadata(root: &Path, no_deps: bool) -> Result<Value, String> {
    cargo_metadata_platform(root, no_deps, None)
}

pub(crate) fn cargo_metadata_platform(
    root: &Path,
    no_deps: bool,
    platform: Option<&str>,
) -> Result<Value, String> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .args(["metadata", "--format-version", "1", "--locked"]);
    if no_deps {
        cmd.arg("--no-deps");
    }
    if let Some(triple) = platform {
        cmd.args(["--filter-platform", triple]);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("invalid cargo metadata JSON: {e}"))
}

fn classify_package(root: &Path, manifest_path: &Path) -> Result<Layer, String> {
    let rel = manifest_path
        .strip_prefix(root)
        .map_err(|_| format!("workspace member outside root: {}", manifest_path.display()))?;
    let mut comps = rel.components().filter_map(|c| c.as_os_str().to_str());
    let first = comps.next();
    let second = comps.next();
    if first != Some("crates") {
        return Err(format!(
            "workspace crate `{}` must live under `crates/<layer>/<pkg>`",
            rel.display()
        ));
    }
    second
        .and_then(Layer::from_dir_component)
        .ok_or_else(|| format!("unknown hexagonal layer for `{}`", rel.display()))
}

#[derive(Debug, Clone)]
struct PkgInfo {
    name: String,
    layer: Layer,
    declared_deps: Vec<String>,
}

fn is_edge_allowed(src: &PkgInfo, _dep_name: &str, dep_layer: Layer) -> Option<&'static str> {
    if dep_layer == Layer::Bin {
        return Some("FORBIDDEN [depends-on-bin]: no crate may depend on a `bin/` crate");
    }
    match src.layer {
        Layer::Core => {
            if src.name == "hephaestus-core" {
                Some("FORBIDDEN [root-core-has-workspace-dep]: hephaestus-core depends on no workspace crate")
            } else if dep_layer != Layer::Core {
                Some("FORBIDDEN [core-depends-outside-core]: core crates depend only on core")
            } else {
                None
            }
        }
        Layer::Ports => (dep_layer != Layer::Core)
            .then_some("FORBIDDEN [port-depends-outside-core]: ports depend only on core"),
        Layer::App => (!matches!(dep_layer, Layer::Core | Layer::Ports))
            .then_some("FORBIDDEN [app-depends-outside-core-and-ports]: app depends only on core and ports"),
        Layer::Adapters => (!matches!(dep_layer, Layer::Core | Layer::Ports))
            .then_some("FORBIDDEN [adapter-depends-outside-core-and-ports]: adapters depend only on core and ports"),
        Layer::Bin => None,
    }
}

fn check_graph(
    pkgs_by_name: &BTreeMap<String, PkgInfo>,
    resolved_edges: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for pkg in pkgs_by_name.values() {
        for dep in &pkg.declared_deps {
            if let Some(dep_pkg) = pkgs_by_name.get(dep)
                && let Some(msg) = is_edge_allowed(pkg, &dep_pkg.name, dep_pkg.layer)
            {
                violations.push(format!(
                    "{msg} (declared: {} [{}] -> {} [{}])",
                    pkg.name,
                    pkg.layer.as_str(),
                    dep_pkg.name,
                    dep_pkg.layer.as_str()
                ));
            }
        }
        if let Some(deps) = resolved_edges.get(&pkg.name) {
            for dep in deps {
                if let Some(dep_pkg) = pkgs_by_name.get(dep)
                    && let Some(msg) = is_edge_allowed(pkg, &dep_pkg.name, dep_pkg.layer)
                {
                    violations.push(format!(
                        "{msg} (resolved: {} [{}] -> {} [{}])",
                        pkg.name,
                        pkg.layer.as_str(),
                        dep_pkg.name,
                        dep_pkg.layer.as_str()
                    ));
                }
            }
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

/// Validates declared and resolved dependency graphs for all workspace crates.
pub(crate) fn check_workspace(root: &Path) -> Result<usize, String> {
    let meta = cargo_metadata(root, false)?;
    let packages = meta["packages"]
        .as_array()
        .ok_or("cargo metadata missing packages array")?;
    let members: BTreeSet<String> = meta["workspace_members"]
        .as_array()
        .ok_or("cargo metadata missing workspace_members")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();

    let mut id_to_name = BTreeMap::new();
    let mut pkgs_by_name = BTreeMap::new();
    for pkg in packages {
        let Some(id) = pkg["id"].as_str() else {
            continue;
        };
        let Some(name) = pkg["name"].as_str() else {
            continue;
        };
        id_to_name.insert(id.to_owned(), name.to_owned());
        if !members.contains(id) {
            continue;
        }
        let manifest = Path::new(
            pkg["manifest_path"]
                .as_str()
                .ok_or("package missing manifest_path")?,
        );
        let layer = classify_package(root, manifest)?;
        let declared_deps = pkg["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d["name"].as_str().map(str::to_owned))
            .collect();
        pkgs_by_name.insert(
            name.to_owned(),
            PkgInfo {
                name: name.to_owned(),
                layer,
                declared_deps,
            },
        );
    }

    let mut resolved_edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Some(nodes) = meta["resolve"]["nodes"].as_array() {
        for node in nodes {
            let Some(id) = node["id"].as_str() else {
                continue;
            };
            let Some(src_name) = id_to_name.get(id) else {
                continue;
            };
            if !pkgs_by_name.contains_key(src_name) {
                continue;
            }
            let entry = resolved_edges.entry(src_name.clone()).or_default();
            if let Some(deps) = node["deps"].as_array() {
                for d in deps {
                    if let Some(pkg_id) = d["pkg"].as_str()
                        && let Some(dep_name) = id_to_name.get(pkg_id)
                    {
                        entry.insert(dep_name.clone());
                    }
                }
            }
        }
    }

    let violations = check_graph(&pkgs_by_name, &resolved_edges);
    if !violations.is_empty() {
        return Err(violations.join("\n"));
    }
    Ok(pkgs_by_name.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_inward_edges_and_rejects_adapter_in_core_or_ports() {
        let mut pkgs = BTreeMap::new();
        pkgs.insert(
            "hephaestus-core".into(),
            PkgInfo {
                name: "hephaestus-core".into(),
                layer: Layer::Core,
                declared_deps: vec![],
            },
        );
        pkgs.insert(
            "hephaestus-store".into(),
            PkgInfo {
                name: "hephaestus-store".into(),
                layer: Layer::Ports,
                declared_deps: vec!["hephaestus-core".into()],
            },
        );
        pkgs.insert(
            "hephaestus-store-sqlite".into(),
            PkgInfo {
                name: "hephaestus-store-sqlite".into(),
                layer: Layer::Adapters,
                declared_deps: vec!["hephaestus-core".into(), "hephaestus-store".into()],
            },
        );
        assert!(check_graph(&pkgs, &BTreeMap::new()).is_empty());

        pkgs.get_mut("hephaestus-store")
            .unwrap()
            .declared_deps
            .push("hephaestus-store-sqlite".into());
        let bad = check_graph(&pkgs, &BTreeMap::new());
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("port-depends-outside-core"));
    }
}
