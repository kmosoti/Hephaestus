#![forbid(unsafe_code)]
//! Hephaestus repository tooling invoked via `cargo xtask <command>`.

mod layers;
mod package;
mod pins;
mod purity;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .ok_or_else(|| "unable to locate workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn usage() -> &'static str {
    "Usage: cargo xtask <command> [options]

Commands:
  check-layers                     Enforce hexagonal crate dependency rules
  check-core-purity                Enforce crates/core/PURITY.toml no_std & dependency rules
  check-workflow-pins              Enforce 40-hex commit SHA pins in .github/workflows/
  package-deb [--out DIR] [--binary PATH] [--version VER]
                                   Build/package Debian .deb, .tar.zst, and SHA256SUMS"
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        println!("{}", usage());
        return Ok(());
    };

    let root = workspace_root()?;
    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        "check-layers" => {
            let checked = layers::check_workspace(&root)?;
            println!("check-layers: OK ({checked} workspace crates verified)");
            Ok(())
        }
        "check-core-purity" => {
            let checked = purity::check_workspace(&root)?;
            println!("check-core-purity: OK ({checked} core crates verified)");
            Ok(())
        }
        "check-workflow-pins" => {
            let dir = root.join(".github/workflows");
            let unpinned = pins::check(&dir)?;
            if !unpinned.is_empty() {
                for item in &unpinned {
                    eprintln!("{item}");
                }
                return Err(format!(
                    "{} unpinned workflow action(s) in {}",
                    unpinned.len(),
                    dir.display()
                ));
            }
            println!("check-workflow-pins: OK");
            Ok(())
        }
        "package-deb" => {
            let mut out = root.join("dist");
            let mut binary: Option<PathBuf> = None;
            let mut version: Option<String> = None;
            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--out" => {
                        let val = args.next().ok_or("--out requires a directory path")?;
                        out = PathBuf::from(val);
                    }
                    "--binary" => {
                        let val = args.next().ok_or("--binary requires a file path")?;
                        binary = Some(PathBuf::from(val));
                    }
                    "--version" => {
                        let val = args.next().ok_or("--version requires a semver string")?;
                        version = Some(val);
                    }
                    other => return Err(format!("unknown package-deb flag `{other}`")),
                }
            }
            let summary = package::run_package(&root, &out, binary.as_deref(), version.as_deref())?;
            println!(
                "package-deb: OK (deb={}, tar_zst={}, sha256sums={})",
                summary.deb_path.display(),
                summary.tar_zst_path.display(),
                summary.sums_path.display()
            );
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`\n\n{}", usage())),
    }
}
