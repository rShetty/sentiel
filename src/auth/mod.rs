//! Bearer-token authentication primitives.
//!
//! Two independent tokens are supported, sourced from the environment:
//!
//! - `SENTIEL_ADMIN_TOKEN`: full read/admin access to every `/api` route.
//! - `SENTIEL_INGEST_TOKEN`: restricted to `POST /api/events` (event producers).
//!
//! Token comparison is constant-time so request handling time does not leak
//! secret contents via timing side channels.

use serde::{Deserialize, Serialize};

/// Capability required to access a protected route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Event ingestion (`POST /api/events`).
    Ingest,
    /// Reads and administrative operations.
    Admin,
}

/// Role resolved from a successfully authenticated bearer token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Ingest,
}

impl Role {
    /// Whether this role may access a route guarded by `scope`.
    pub fn permits(self, scope: Scope) -> bool {
        match self {
            Role::Admin => true,
            Role::Ingest => scope == Scope::Ingest,
        }
    }
}

/// Authentication settings sourced from the environment.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub admin_token: Option<String>,
    pub ingest_token: Option<String>,
    pub insecure_dev: bool,
}

impl AuthConfig {
    /// Read token configuration from the environment.
    ///
    /// - `SENTIEL_ADMIN_TOKEN`: grants admin access to all `/api` routes.
    /// - `SENTIEL_INGEST_TOKEN`: grants ingest-only access to `POST /api/events`.
    /// - `SENTIEL_INSECURE_DEV=1`: explicit operator opt-out from mandatory tokens.
    pub fn from_env() -> Self {
        let var = |key: &str| {
            std::env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        AuthConfig {
            admin_token: var("SENTIEL_ADMIN_TOKEN"),
            ingest_token: var("SENTIEL_INGEST_TOKEN"),
            insecure_dev: var("SENTIEL_INSECURE_DEV").as_deref() == Some("1"),
        }
    }

    /// Startup guard: refuse token-less starts in release builds unless the
    /// operator explicitly opted out with `SENTIEL_INSECURE_DEV=1`.
    pub fn ensure_startable(&self, release_build: bool) -> Result<(), String> {
        if self.admin_token.is_some() || self.ingest_token.is_some() {
            return Ok(());
        }
        if self.insecure_dev {
            tracing::warn!(
                "SENTIEL_INSECURE_DEV=1: starting WITHOUT authentication; never expose this instance beyond loopback"
            );
            return Ok(());
        }
        if release_build {
            Err(
                "refusing to start: set SENTIEL_ADMIN_TOKEN and/or SENTIEL_INGEST_TOKEN, \
                 or explicitly opt out with SENTIEL_INSECURE_DEV=1"
                    .to_string(),
            )
        } else {
            tracing::warn!(
                "no SENTIEL_ADMIN_TOKEN/SENTIEL_INGEST_TOKEN configured: API is UNAUTHENTICATED \
                 (tolerated only because this is a debug build)"
            );
            Ok(())
        }
    }

    /// Resolve a presented bearer token to its [`Role`] using constant-time
    /// comparisons against the configured secrets.
    pub fn authenticate(&self, presented: &str) -> Option<Role> {
        let bytes = presented.as_bytes();
        if let Some(admin) = self.admin_token.as_deref() {
            if constant_time_eq(bytes, admin.as_bytes()) {
                return Some(Role::Admin);
            }
        }
        if let Some(ingest) = self.ingest_token.as_deref() {
            if constant_time_eq(bytes, ingest.as_bytes()) {
                return Some(Role::Ingest);
            }
        }
        None
    }
}

/// Constant-time byte-slice equality.
///
/// Iterates over the longer slice and XOR-folds every compared byte pair so
/// running time depends only on token-length bounds, never on where (or
/// whether) the secrets first diverge. Length differences are folded into the
/// accumulator instead of short-circuiting.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u32;
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        // Reads past the end of the shorter slice contribute zero bytes, which
        // can never cancel out a genuine mismatch.
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= (left ^ right) as u32;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_slices() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn authenticate_resolves_roles() {
        let config = AuthConfig {
            admin_token: Some("admin-secret".to_string()),
            ingest_token: Some("ingest-secret".to_string()),
            insecure_dev: false,
        };

        assert_eq!(config.authenticate("admin-secret"), Some(Role::Admin));
        assert_eq!(config.authenticate("ingest-secret"), Some(Role::Ingest));
        assert_eq!(config.authenticate("nope"), None);
        assert_eq!(config.authenticate(""), None);
    }

    #[test]
    fn role_permissions() {
        assert!(Role::Admin.permits(Scope::Admin));
        assert!(Role::Admin.permits(Scope::Ingest));
        assert!(Role::Ingest.permits(Scope::Ingest));
        assert!(!Role::Ingest.permits(Scope::Admin));
    }

    #[test]
    fn start_guard_refuses_release_without_tokens() {
        let config = AuthConfig::default();
        assert!(config.ensure_startable(true).is_err());
        // Debug builds are tolerated with a warning so local development works.
        assert!(config.ensure_startable(false).is_ok());
    }

    #[test]
    fn start_guard_allows_tokens_or_explicit_opt_out() {
        let with_token = AuthConfig {
            admin_token: Some("t".to_string()),
            ..AuthConfig::default()
        };
        assert!(with_token.ensure_startable(true).is_ok());

        let opted_out = AuthConfig {
            insecure_dev: true,
            ..AuthConfig::default()
        };
        assert!(opted_out.ensure_startable(true).is_ok());
    }
}
