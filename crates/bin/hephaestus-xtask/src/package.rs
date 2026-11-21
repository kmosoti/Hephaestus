//! Build/assemble Debian `.deb`, `.tar.zst`, and `SHA256SUMS` artifacts.

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const SERVICE_UNIT: &str = "[Unit]
Description=Hephaestus Authoritative Jujutsu Storage and QUIC Server
Documentation=https://github.com/kmosoti/Hephaestus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory=hephaestus
ExecStart=/usr/bin/hephaestus-server --http-bind [::1]:8081 --quic-bind [::1]:8443 --data-dir /var/lib/hephaestus
Restart=on-failure
RestartSec=3s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
";

const POSTINST: &str = "#!/bin/sh
set -e
if [ \"$1\" = configure ]; then
    install -d -m 0750 /var/lib/hephaestus
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
    fi
fi
";

const PRERM: &str = "#!/bin/sh
set -e
if [ \"$1\" = remove ] && [ -d /run/systemd/system ]; then
    systemctl stop hephaestus-server.service || true
fi
";

const POSTRM: &str = "#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ \"$1\" = purge ]; then
    rm -rf /var/lib/hephaestus
fi
";

/// Output paths created by [`run_package`].
#[derive(Debug, Clone)]
pub(crate) struct PackageSummary {
    pub(crate) deb_path: PathBuf,
    pub(crate) tar_zst_path: PathBuf,
    pub(crate) sums_path: PathBuf,
}

pub(crate) fn debian_version(cargo: &str) -> String {
    match cargo.split_once('-') {
        Some((release, pre)) => format!("{release}~{pre}"),
        None => cargo.to_string(),
    }
}

fn control_text(deb_version: &str, installed_kib: u64) -> String {
    format!(
        "Package: hephaestus-server
Version: {deb_version}
Architecture: amd64
Maintainer: Hephaestus Contributors <47609243+kmosoti@users.noreply.github.com>
Installed-Size: {installed_kib}
Depends: libc6, systemd
Section: vcs
Priority: optional
Homepage: https://github.com/kmosoti/Hephaestus
Description: Authoritative Jujutsu storage and QUIC replication daemon
 Hephaestus provides an Ed25519 mTLS-pinned QUIC transport, GRNB0002 Zstd
 CAS bundling over object_store/Google Drive, SQLite WAL idempotency with
 Zstd LTX snapshots, a hash-chained Decision Log, and orthogonal Observation Logs.
"
    )
}

fn workspace_version(root: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("read Cargo.toml: {e}"))?;
    let val: toml::Value = toml::from_str(&raw).map_err(|e| format!("parse Cargo.toml: {e}"))?;
    val.get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "missing [workspace.package].version in Cargo.toml".to_owned())
}

fn build_server_binary(root: &Path) -> Result<PathBuf, String> {
    let out = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--locked",
            "--message-format=json",
            "-p",
            "hephaestus-server",
            "--bin",
            "hephaestus-server",
        ])
        .output()
        .map_err(|e| format!("failed to run cargo build: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo build hephaestus-server failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|m| {
            m["reason"] == "compiler-artifact" && m["target"]["name"] == "hephaestus-server"
        })
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .ok_or_else(|| "cargo build produced no hephaestus-server executable".to_owned())
}

fn append_tar_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
    mode: u32,
) -> Result<(), String> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder
        .append_data(&mut header, path, data)
        .map_err(|e| format!("tar append `{path}`: {e}"))
}

fn build_control_tar_gz(deb_ver: &str, installed_kib: u64) -> Result<Vec<u8>, String> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tb = tar::Builder::new(enc);
    append_tar_bytes(
        &mut tb,
        "./control",
        control_text(deb_ver, installed_kib).as_bytes(),
        0o644,
    )?;
    append_tar_bytes(&mut tb, "./postinst", POSTINST.as_bytes(), 0o755)?;
    append_tar_bytes(&mut tb, "./prerm", PRERM.as_bytes(), 0o755)?;
    append_tar_bytes(&mut tb, "./postrm", POSTRM.as_bytes(), 0o755)?;
    let enc = tb
        .into_inner()
        .map_err(|e| format!("control tar finish: {e}"))?;
    enc.finish()
        .map_err(|e| format!("control gzip finish: {e}"))
}

fn build_data_tar_gz(bin_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tb = tar::Builder::new(enc);
    append_tar_bytes(&mut tb, "./usr/bin/hephaestus-server", bin_bytes, 0o755)?;
    append_tar_bytes(
        &mut tb,
        "./lib/systemd/system/hephaestus-server.service",
        SERVICE_UNIT.as_bytes(),
        0o644,
    )?;
    let enc = tb
        .into_inner()
        .map_err(|e| format!("data tar finish: {e}"))?;
    enc.finish().map_err(|e| format!("data gzip finish: {e}"))
}

fn write_ar_member(out: &mut Vec<u8>, name: &str, data: &[u8]) -> Result<(), String> {
    if name.len() > 16 {
        return Err(format!("ar member name too long: {name}"));
    }
    let header = format!(
        "{name:<16}{mtime:<12}{uid:<6}{gid:<6}{mode:<8}{size:<10}`\n",
        mtime = 0,
        uid = 0,
        gid = 0,
        mode = 100644,
        size = data.len()
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
    Ok(())
}

fn build_ar_deb(deb_path: &Path, deb_ver: &str, bin_bytes: &[u8]) -> Result<(), String> {
    let installed_kib = ((bin_bytes.len() + SERVICE_UNIT.len()) as u64).div_ceil(1024);
    let control_gz = build_control_tar_gz(deb_ver, installed_kib)?;
    let data_gz = build_data_tar_gz(bin_bytes)?;

    let mut ar = Vec::with_capacity(8 + 64 + control_gz.len() + data_gz.len() + 256);
    ar.extend_from_slice(b"!<arch>\n");
    write_ar_member(&mut ar, "debian-binary", b"2.0\n")?;
    write_ar_member(&mut ar, "control.tar.gz", &control_gz)?;
    write_ar_member(&mut ar, "data.tar.gz", &data_gz)?;
    std::fs::write(deb_path, &ar).map_err(|e| format!("write {}: {e}", deb_path.display()))
}

fn build_tar_zst(tar_zst_path: &Path, bin_bytes: &[u8]) -> Result<(), String> {
    let enc = zstd::stream::Encoder::new(Vec::new(), 3).map_err(|e| format!("zstd init: {e}"))?;
    let mut tb = tar::Builder::new(enc);
    append_tar_bytes(&mut tb, "bin/hephaestus-server", bin_bytes, 0o755)?;
    append_tar_bytes(
        &mut tb,
        "systemd/hephaestus-server.service",
        SERVICE_UNIT.as_bytes(),
        0o644,
    )?;
    let enc = tb.into_inner().map_err(|e| format!("tar finish: {e}"))?;
    let compressed = enc.finish().map_err(|e| format!("zstd finish: {e}"))?;
    std::fs::write(tar_zst_path, &compressed)
        .map_err(|e| format!("write {}: {e}", tar_zst_path.display()))
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Packages `hephaestus-server` (or a caller-provided binary) into `.deb`, `.tar.zst`, and `SHA256SUMS`.
pub(crate) fn run_package(
    root: &Path,
    out_dir: &Path,
    binary_override: Option<&Path>,
    version_override: Option<&str>,
) -> Result<PackageSummary, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let version = match version_override {
        Some(v) => v.to_owned(),
        None => workspace_version(root)?,
    };
    let deb_ver = debian_version(&version);
    let bin_path = match binary_override {
        Some(p) => p.to_path_buf(),
        None => build_server_binary(root)?,
    };
    let bin_bytes =
        std::fs::read(&bin_path).map_err(|e| format!("read {}: {e}", bin_path.display()))?;

    let deb_name = format!("hephaestus-server_{version}_amd64.deb");
    let tar_name = format!("hephaestus-server-{version}-x86_64-linux.tar.zst");
    let deb_path = out_dir.join(&deb_name);
    let tar_zst_path = out_dir.join(&tar_name);
    let sums_path = out_dir.join("SHA256SUMS");

    build_ar_deb(&deb_path, &deb_ver, &bin_bytes)?;
    build_tar_zst(&tar_zst_path, &bin_bytes)?;

    let deb_sum = sha256_hex(&deb_path)?;
    let tar_sum = sha256_hex(&tar_zst_path)?;
    let sums = format!("{deb_sum}  {deb_name}\n{tar_sum}  {tar_name}\n");
    std::fs::write(&sums_path, sums).map_err(|e| format!("write {}: {e}", sums_path.display()))?;

    Ok(PackageSummary {
        deb_path,
        tar_zst_path,
        sums_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_valid_ar_deb_and_tar_zst_from_synthetic_binary() {
        let dir = std::env::temp_dir().join(format!("hep-pkg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fake_bin = dir.join("hephaestus-server");
        std::fs::write(&fake_bin, b"#!/bin/sh\necho ok\n").unwrap();

        let out_dir = dir.join("out");
        let summary = run_package(&dir, &out_dir, Some(&fake_bin), Some("0.1.0-alpha.1")).unwrap();
        let deb_bytes = std::fs::read(&summary.deb_path).unwrap();
        assert!(deb_bytes.starts_with(b"!<arch>\n"));
        assert!(deb_bytes.windows(13).any(|w| w == b"debian-binary"));
        assert!(deb_bytes.windows(14).any(|w| w == b"control.tar.gz"));
        assert!(deb_bytes.windows(11).any(|w| w == b"data.tar.gz"));

        let tar_zst = std::fs::read(&summary.tar_zst_path).unwrap();
        let decoded = zstd::stream::decode_all(tar_zst.as_slice()).unwrap();
        let mut archive = tar::Archive::new(decoded.as_slice());
        let entries: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["bin/hephaestus-server", "systemd/hephaestus-server.service"]
        );

        let sums = std::fs::read_to_string(&summary.sums_path).unwrap();
        assert!(sums.contains("hephaestus-server_0.1.0-alpha.1_amd64.deb"));
        assert!(sums.contains("hephaestus-server-0.1.0-alpha.1-x86_64-linux.tar.zst"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
