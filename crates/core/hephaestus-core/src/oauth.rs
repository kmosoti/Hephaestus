//! Pure Sans-I/O OAuth 2.0 PKCE (`S256`) and token refresh state machine for `drive.file`.

use crate::time::MonoTime;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use core::fmt;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Least-privilege OAuth scope granting access solely to files created by this app.
pub const DRIVE_FILE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";
/// Google OAuth 2.0 authorization endpoint.
pub const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// Google OAuth 2.0 token exchange and refresh endpoint.
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const EXPIRY_MARGIN_MS: u64 = 60_000;

/// Errors emitted by [`DriveOAuthFsm`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DriveOAuthError {
    /// Client identifier was blank.
    #[error("Drive OAuth client_id must not be empty")]
    EmptyClientId,

    /// Requested OAuth scope violated least-privilege `drive.file` confinement.
    #[error("forbidden Drive OAuth scope `{0}`: strictly `{DRIVE_FILE_SCOPE}` is allowed")]
    ForbiddenScope(String),

    /// Callback `state` did not match the active PKCE session.
    #[error("OAuth state mismatch in loopback callback")]
    StateMismatch,

    /// Callback missed a non-empty authorization code.
    #[error("OAuth callback missing authorization code")]
    MissingAuthCode,

    /// Attempted refresh without a stored refresh token.
    #[error("no refresh token available to renew expired Drive session")]
    MissingRefreshToken,
}

/// Redaction-safe string wrapper preventing credential disclosure in `Debug`/`Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a sensitive token string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Exposes the raw token strictly for outbound `Authorization` headers or form bodies.
    #[must_use]
    pub fn expose_for_http_header(&self) -> &str {
        &self.0
    }

    /// Returns the token byte length without exposing its contents.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<redacted {} bytes>)", self.0.len())
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

/// Pure PKCE `S256` verifier/challenge pair derived from caller-supplied entropy.
#[derive(Clone, PartialEq, Eq)]
pub struct PkcePair {
    verifier: SecretString,
    /// Base64URL-encoded SHA-256 challenge sent in the consent URL.
    pub challenge: String,
    /// Anti-CSRF state nonce.
    pub state: String,
}

impl PkcePair {
    /// Derives an `S256` PKCE pair deterministically from caller entropy.
    #[must_use]
    pub fn from_entropy(verifier_entropy: [u8; 32], state_entropy: [u8; 16]) -> Self {
        let verifier_raw = URL_SAFE_NO_PAD.encode(verifier_entropy);
        let digest = Sha256::digest(verifier_raw.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        let state = URL_SAFE_NO_PAD.encode(state_entropy);
        Self {
            verifier: SecretString::new(verifier_raw),
            challenge,
            state,
        }
    }

    /// Returns the redaction-safe PKCE verifier.
    #[must_use]
    pub fn verifier(&self) -> &SecretString {
        &self.verifier
    }
}

impl fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkcePair")
            .field("verifier", &self.verifier)
            .field("challenge", &self.challenge)
            .field("state", &self.state)
            .finish()
    }
}

/// Active OAuth access/refresh lease bound to monotonic expiry time.
#[derive(Debug, Clone)]
pub struct TokenLease {
    /// Short-lived bearer access token.
    pub access_token: SecretString,
    /// Optional long-lived refresh token.
    pub refresh_token: Option<SecretString>,
    /// Monotonic expiry deadline.
    pub expires_at: MonoTime,
}

/// Outbound `application/x-www-form-urlencoded` request produced by [`DriveOAuthFsm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFormRequest {
    /// Token endpoint URL.
    pub endpoint: &'static str,
    /// Key-value form fields for HTTP POST.
    pub form_fields: Vec<(&'static str, String)>,
}

/// Pure Sans-I/O OAuth 2.0 PKCE + refresh state machine confined to `drive.file`.
#[derive(Debug, Clone)]
pub struct DriveOAuthFsm {
    client_id: String,
    redirect_uri: String,
    pending_pkce: Option<PkcePair>,
    lease: Option<TokenLease>,
}

impl DriveOAuthFsm {
    /// Constructs a new FSM after verifying `client_id` and `drive.file` scope confinement.
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        requested_scope: &str,
    ) -> Result<Self, DriveOAuthError> {
        let client_id = client_id.into().trim().to_owned();
        if client_id.is_empty() {
            return Err(DriveOAuthError::EmptyClientId);
        }
        if requested_scope != DRIVE_FILE_SCOPE {
            return Err(DriveOAuthError::ForbiddenScope(requested_scope.to_owned()));
        }
        Ok(Self {
            client_id,
            redirect_uri: redirect_uri.into(),
            pending_pkce: None,
            lease: None,
        })
    }

    /// Transitions into awaiting-callback state and returns the authorization consent URL.
    pub fn begin_consent(&mut self, pkce: PkcePair) -> String {
        let pairs = [
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", DRIVE_FILE_SCOPE),
            ("code_challenge", pkce.challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", pkce.state.as_str()),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ];
        let mut url = String::from(GOOGLE_AUTH_ENDPOINT);
        url.push('?');
        for (idx, (k, v)) in pairs.iter().enumerate() {
            if idx > 0 {
                url.push('&');
            }
            push_percent_encoded(&mut url, k);
            url.push('=');
            push_percent_encoded(&mut url, v);
        }
        self.pending_pkce = Some(pkce);
        url
    }

    /// Validates the loopback callback and yields a token exchange form request.
    pub fn handle_callback(
        &mut self,
        returned_state: &str,
        code: &str,
    ) -> Result<TokenFormRequest, DriveOAuthError> {
        let pkce = self
            .pending_pkce
            .as_ref()
            .ok_or(DriveOAuthError::StateMismatch)?;
        if pkce.state != returned_state {
            return Err(DriveOAuthError::StateMismatch);
        }
        if code.trim().is_empty() {
            return Err(DriveOAuthError::MissingAuthCode);
        }
        let verifier = pkce.verifier.expose_for_http_header().to_owned();
        self.pending_pkce = None;
        Ok(TokenFormRequest {
            endpoint: GOOGLE_TOKEN_ENDPOINT,
            form_fields: vec![
                ("client_id", self.client_id.clone()),
                ("code", code.trim().to_owned()),
                ("code_verifier", verifier),
                ("grant_type", "authorization_code".into()),
                ("redirect_uri", self.redirect_uri.clone()),
            ],
        })
    }

    /// Records newly issued tokens, retaining an existing refresh token if none is returned.
    pub fn apply_token_response(
        &mut self,
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        expires_in_secs: u64,
        now: MonoTime,
    ) {
        let prev_refresh = self.lease.as_ref().and_then(|l| l.refresh_token.clone());
        self.lease = Some(TokenLease {
            access_token,
            refresh_token: refresh_token.or(prev_refresh),
            expires_at: now.add_ms(expires_in_secs.saturating_mul(1000)),
        });
    }

    /// Returns the active access token if it remains valid beyond the safety margin.
    #[must_use]
    pub fn valid_access_token(&self, now: MonoTime) -> Option<&SecretString> {
        let lease = self.lease.as_ref()?;
        if now.add_ms(EXPIRY_MARGIN_MS) < lease.expires_at {
            Some(&lease.access_token)
        } else {
            None
        }
    }

    /// Builds a refresh-token exchange form request when a refresh token is held.
    pub fn build_refresh_request(&self) -> Result<TokenFormRequest, DriveOAuthError> {
        let refresh = self
            .lease
            .as_ref()
            .and_then(|l| l.refresh_token.as_ref())
            .ok_or(DriveOAuthError::MissingRefreshToken)?;
        Ok(TokenFormRequest {
            endpoint: GOOGLE_TOKEN_ENDPOINT,
            form_fields: vec![
                ("client_id", self.client_id.clone()),
                ("grant_type", "refresh_token".into()),
                ("refresh_token", refresh.expose_for_http_header().to_owned()),
            ],
        })
    }
}

fn push_percent_encoded(out: &mut String, input: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in input.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
}
