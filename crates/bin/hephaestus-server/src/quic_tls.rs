//! Ed25519 persisted/ephemeral identity and constant-time SPKI SHA-256 mTLS pinning for `quinn 0.11`.

use crate::quic_spki::ct_contains_pin;
pub use crate::quic_spki::{ct_eq_32, extract_spki_der, spki_sha256_pin};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, OtherError,
    SignatureScheme,
};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// ALPN protocol identifier negotiated by Hephaestus QUIC endpoints.
pub const ALPN_HEPHAESTUS_QUIC: &[u8] = b"hephaestus-quic/1";

/// Ephemeral or persisted Ed25519 X.509 identity with SPKI SHA-256 pin.
#[derive(Clone)]
pub struct QuicTlsIdentity {
    /// DER-encoded X.509 v3 certificate.
    pub cert_der: Vec<u8>,
    /// PKCS#8 DER-encoded Ed25519 private key.
    pub pkcs8_key_der: Vec<u8>,
    /// SPKI SHA-256 fingerprint derived from the Ed25519 public key.
    pub fingerprint: [u8; 32],
    /// Lowercase hex encoding of [`Self::fingerprint`].
    pub fingerprint_hex: String,
    key_pem: String,
}

impl QuicTlsIdentity {
    /// Generates a new Ed25519 X.509 v3 self-signed certificate for `common_name`.
    pub fn generate(common_name: &str) -> Result<Self, String> {
        let key_pair =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|e| format!("ed25519 keygen: {e}"))?;
        Self::from_key_pair(key_pair, common_name)
    }

    /// Reconstructs an identity with stable SPKI SHA-256 pin from a PKCS#8 Ed25519 PEM string.
    pub fn from_key_pem(pem: &str, common_name: &str) -> Result<Self, String> {
        let key_pair =
            KeyPair::from_pem(pem).map_err(|e| format!("parse Ed25519 PKCS#8 PEM: {e}"))?;
        Self::from_key_pair(key_pair, common_name)
    }

    /// Loads an Ed25519 key PEM from `path`, or generates and persists a new `0600` key file.
    pub fn load_or_generate(path: &Path, common_name: &str) -> Result<Self, String> {
        if path.exists() {
            let pem = std::fs::read_to_string(path)
                .map_err(|e| format!("read tls key {}: {e}", path.display()))?;
            return Self::from_key_pem(&pem, common_name);
        }
        let id = Self::generate(common_name)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create tls key dir {}: {e}", parent.display()))?;
        }
        std::fs::write(path, id.key_pem.as_bytes())
            .map_err(|e| format!("write tls key {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(id)
    }

    fn from_key_pair(key_pair: KeyPair, common_name: &str) -> Result<Self, String> {
        let params = CertificateParams::new(vec![
            common_name.to_owned(),
            "localhost".to_owned(),
            "::1".to_owned(),
        ])
        .map_err(|e| format!("cert params: {e}"))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("self_signed: {e}"))?;
        let cert_der = cert.der().to_vec();
        let pkcs8_key_der = key_pair.serialize_der();
        let key_pem = key_pair.serialize_pem();
        let fingerprint = spki_sha256_pin(&cert_der).map_err(str::to_owned)?;
        let fingerprint_hex = hex::encode(fingerprint);
        Ok(Self {
            cert_der,
            pkcs8_key_der,
            fingerprint,
            fingerprint_hex,
            key_pem,
        })
    }

    fn cert_and_key(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (
            vec![CertificateDer::from(self.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8_key_der.clone())),
        )
    }
}

#[derive(Debug)]
struct PinMismatchError(&'static str);

impl fmt::Display for PinMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for PinMismatchError {}

fn tuned_transport_config() -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    cfg.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("30s fits")));
    cfg.keep_alive_interval(Some(Duration::from_secs(10)));
    cfg.max_concurrent_bidi_streams(128u32.into());
    cfg.max_concurrent_uni_streams(32u32.into());
    cfg.stream_receive_window((8 * 1024 * 1024u32).into());
    cfg.receive_window((32 * 1024 * 1024u32).into());
    cfg.send_window(32 * 1024 * 1024);
    Arc::new(cfg)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected_fp: [u8; 32],
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = spki_sha256_pin(end_entity.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        if !ct_eq_32(&actual, &self.expected_fp) {
            return Err(TlsError::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(PinMismatchError(
                    "server SPKI SHA-256 fingerprint mismatch",
                ))),
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::InvalidCertificate(CertificateError::BadEncoding))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

#[derive(Debug)]
struct PinnedClientVerifier {
    allowed_fps: Vec<[u8; 32]>,
    empty_hints: Vec<DistinguishedName>,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.empty_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let actual = spki_sha256_pin(end_entity.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        if !ct_contains_pin(&self.allowed_fps, &actual) {
            return Err(TlsError::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(PinMismatchError(
                    "client SPKI SHA-256 fingerprint not in mTLS allowlist",
                ))),
            )));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::InvalidCertificate(CertificateError::BadEncoding))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Builds an Ed25519 mTLS-pinned [`quinn::ServerConfig`] requiring constant-time SPKI pins.
pub fn build_quinn_server_config(
    server_id: &QuicTlsIdentity,
    allowed_client_fps: Vec<[u8; 32]>,
) -> Result<quinn::ServerConfig, String> {
    if allowed_client_fps.is_empty() {
        return Err("mTLS allowlist must contain at least one client SPKI fingerprint".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier = Arc::new(PinnedClientVerifier {
        allowed_fps: allowed_client_fps,
        empty_hints: Vec::new(),
    });
    let (certs, key) = server_id.cert_and_key();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![ALPN_HEPHAESTUS_QUIC.to_vec()];
    let quic_crypto = QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    cfg.transport_config(tuned_transport_config());
    Ok(cfg)
}

/// Builds an Ed25519 mTLS-pinned [`quinn::ClientConfig`] verifying the server SPKI pin.
pub fn build_quinn_client_config(
    client_id: &QuicTlsIdentity,
    expected_server_fp: [u8; 32],
) -> Result<quinn::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_verifier = Arc::new(PinnedServerVerifier {
        expected_fp: expected_server_fp,
    });
    let (certs, key) = client_id.cert_and_key();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![ALPN_HEPHAESTUS_QUIC.to_vec()];
    let quic_crypto = QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    cfg.transport_config(tuned_transport_config());
    Ok(cfg)
}
