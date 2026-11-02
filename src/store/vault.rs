// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! HashiVault / OpenBao KV v2 over HTTP: the `SecretStore` behind
//! `ConnectionStore` in the default (upstream) configuration.
//!
//! Login (AppRole or workload JWT), token renewal, TLS client setup and the
//! KV v2 requests moved here from `vault.rs` unchanged. Paths are relative
//! to the KV mount, so `mybastion/shared/prod/web01` is read from
//! `/v1/<mount>/data/mybastion/shared/prod/web01`.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{Doc, SecretStore, StoreError};
use crate::config::VaultConfig;

pub struct VaultStore {
    http: reqwest::Client,
    addr: String,
    mount: String,
    namespace: Option<String>,
    token: Arc<RwLock<String>>,
    role_id: String,
    secret_id: String,
    jwt_auth: Option<crate::config::VaultJwtAuth>,
}

/// The workload identity JWT for a login: read from `path`, or printed by
/// `token_command`. Errors never include the token or the command's output,
/// which could carry it.
async fn fetch_workload_jwt(cfg: &crate::config::VaultJwtAuth) -> Result<String, StoreError> {
    let raw = if let Some(path) = cfg.path.as_deref().filter(|p| !p.trim().is_empty()) {
        tokio::fs::read_to_string(path).await.map_err(|e| {
            StoreError::Auth(format!("cannot read workload identity token: {}", e.kind()))
        })?
    } else if let Some([program, args @ ..]) = cfg.token_command.as_deref() {
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let timeout = std::time::Duration::from_secs(cfg.token_command_timeout_secs.max(1));
        let out = match tokio::time::timeout(timeout, cmd.output()).await {
            Err(_) => {
                return Err(StoreError::Auth(format!(
                    "jwt_auth.token_command did not finish within {}s",
                    timeout.as_secs()
                )))
            }
            Ok(Err(e)) => {
                return Err(StoreError::Auth(format!(
                    "jwt_auth.token_command could not run: {}",
                    e.kind()
                )))
            }
            Ok(Ok(out)) => out,
        };
        if !out.status.success() {
            return Err(StoreError::Auth(format!(
                "jwt_auth.token_command failed ({})",
                out.status
            )));
        }
        String::from_utf8(out.stdout)
            .map_err(|_| StoreError::Auth("jwt_auth.token_command printed non-UTF-8".into()))?
    } else {
        return Err(StoreError::Auth(
            "jwt_auth needs path or token_command".into(),
        ));
    };
    let jwt = raw.trim();
    if jwt.is_empty() {
        return Err(StoreError::Auth("workload identity token is empty".into()));
    }
    Ok(jwt.to_string())
}

impl VaultStore {
    /// Create a new Vault client and perform initial login.
    pub async fn new(config: &VaultConfig, secret_id: &str) -> Result<Self, StoreError> {
        if let Some(ref jwt_auth) = config.jwt_auth {
            jwt_auth.validate().map_err(StoreError::Auth)?;
        } else if config.role_id.trim().is_empty() {
            return Err(StoreError::Auth(
                "AppRole role_id is required when jwt_auth is not configured".into(),
            ));
        }
        if config.tls_skip_verify {
            tracing::warn!(
                "Vault TLS certificate verification is DISABLED (tls_skip_verify = true)"
            );
        }
        let http = build_vault_http_client(config)?;

        let client = Self {
            http,
            addr: config.addr.trim_end_matches('/').to_string(),
            mount: config.mount.clone(),
            namespace: config.namespace.clone(),
            token: Arc::new(RwLock::new(String::new())),
            role_id: config.role_id.clone(),
            secret_id: secret_id.to_string(),
            jwt_auth: config.jwt_auth.clone(),
        };

        // Perform initial login
        let (token, _ttl) = client.login().await?;
        *client.token.write().await = token;

        Ok(client)
    }

    /// Log in and return (token, ttl_seconds). With `jwt_auth` the JWT is
    /// fetched again every time, so a rotated token (kubelet, Nomad,
    /// spiffe-helper, a metadata service) is always the one sent.
    async fn login(&self) -> Result<(String, u64), StoreError> {
        let (url, body) = if let Some(ref jwt_auth) = self.jwt_auth {
            let jwt = fetch_workload_jwt(jwt_auth).await?;
            (
                format!("{}/v1/auth/{}/login", self.addr, jwt_auth.mount),
                serde_json::json!({ "role": jwt_auth.role, "jwt": jwt }),
            )
        } else {
            (
                format!("{}/v1/auth/approle/login", self.addr),
                serde_json::json!({ "role_id": self.role_id, "secret_id": self.secret_id }),
            )
        };

        let mut req = self.http.post(&url).json(&body);
        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            if self.jwt_auth.is_some() {
                // An auth backend/proxy could reflect the submitted JWT. Never
                // include its response body in errors that reach the logs.
                return Err(StoreError::Auth(format!(
                    "JWT login failed — HTTP {} from {}",
                    status.as_u16(),
                    url,
                )));
            }
            let text = resp.text().await.unwrap_or_default();
            // Truncate response body — HTML error pages from reverse proxies are useless noise
            let body_preview = if text.len() > 200 {
                format!(
                    "{}... (truncated, {} bytes total)",
                    &text[..200],
                    text.len()
                )
            } else {
                text
            };
            return Err(StoreError::Auth(format!(
                "Vault login failed — HTTP {} from {} — response: {}",
                status.as_u16(),
                url,
                body_preview
            )));
        }

        let json: serde_json::Value = resp.json().await?;
        let token = json["auth"]["client_token"]
            .as_str()
            .ok_or_else(|| StoreError::Auth("no client_token in login response".into()))?
            .to_string();
        let ttl = json["auth"]["lease_duration"].as_u64().unwrap_or(3600);

        Ok((token, ttl))
    }

    /// Spawn a background task that renews the token at 50% of TTL.
    pub fn spawn_renewal_task(self: &Arc<Self>) {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            // Initial TTL — re-login to get it
            let mut ttl = match client.login().await {
                Ok((_, ttl)) => ttl,
                Err(_) => 3600,
            };

            loop {
                let sleep_secs = std::cmp::max(ttl / 2, 30);
                tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;

                // Try to renew the existing token first
                let renewed = client.renew_token().await;
                match renewed {
                    Ok(new_ttl) => {
                        tracing::debug!("Vault token renewed, TTL: {}s", new_ttl);
                        ttl = new_ttl;
                    }
                    Err(_) => {
                        // Renewal failed — try full re-login
                        tracing::warn!("Vault token renewal failed, attempting re-login");
                        match client.login().await {
                            Ok((new_token, new_ttl)) => {
                                *client.token.write().await = new_token;
                                ttl = new_ttl;
                                tracing::info!("Vault re-login successful, TTL: {}s", new_ttl);
                            }
                            Err(e) => {
                                tracing::error!("Vault re-login failed: {}", e);
                                ttl = 60; // retry quickly
                            }
                        }
                    }
                }
            }
        });
    }

    /// Renew the current token. Returns new TTL.
    async fn renew_token(&self) -> Result<u64, StoreError> {
        let url = format!("{}/v1/auth/token/renew-self", self.addr);
        let token = self.token.read().await.clone();

        let mut req = self.http.post(&url).header("X-Vault-Token", &token);
        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(StoreError::Auth("token renewal failed".into()));
        }

        let json: serde_json::Value = resp.json().await?;
        Ok(json["auth"]["lease_duration"].as_u64().unwrap_or(3600))
    }

    /// Make an authenticated request to Vault. Retries once on 403 with re-login.
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response, StoreError> {
        let url = format!("{}{}", self.addr, path);

        let do_request = |token: String| {
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header("X-Vault-Token", &token);
            if let Some(ref ns) = self.namespace {
                req = req.header("X-Vault-Namespace", ns.as_str());
            }
            if let Some(b) = body {
                req = req.json(b);
            }
            req.send()
        };

        let token = self.token.read().await.clone();
        let resp = do_request(token).await?;

        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            // Re-login and retry once
            tracing::debug!("Vault 403, attempting re-login and retry");
            match self.login().await {
                Ok((new_token, _)) => {
                    *self.token.write().await = new_token.clone();
                    let resp = do_request(new_token).await?;
                    Ok(resp)
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(resp)
        }
    }

    fn data_path(&self, path: &str) -> String {
        format!("/v1/{}/data/{}", self.mount, path)
    }

    fn metadata_path(&self, path: &str) -> String {
        format!("/v1/{}/metadata/{}", self.mount, path)
    }

    /// Perform a LIST operation on a Vault path. Returns the keys array.
    async fn kv_list(&self, path: &str) -> Result<Vec<String>, StoreError> {
        // Vault LIST is a GET with ?list=true (also works with HTTP method LIST,
        // but ?list=true is more portable across HTTP clients).
        let url = format!("{}{}?list=true", self.addr, path);
        let token = self.token.read().await.clone();

        let mut req = self.http.get(&url).header("X-Vault-Token", &token);
        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let resp = req.send().await?;

        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                let keys = json["data"]["keys"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(keys)
            }
            404 => Err(StoreError::NotFound),
            403 => Err(StoreError::Forbidden),
            s => Err(rejected(s, resp).await),
        }
    }
}

/// The error for a status the operation did not expect, carrying the
/// response body for the caller to report or not.
async fn rejected(status: u16, resp: reqwest::Response) -> StoreError {
    StoreError::Rejected {
        status,
        body: resp.text().await.unwrap_or_default(),
    }
}

#[async_trait]
impl SecretStore for VaultStore {
    async fn get(&self, path: &str) -> Result<Option<Doc>, StoreError> {
        let resp = self
            .request(reqwest::Method::GET, &self.data_path(path), None)
            .await?;
        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value = resp.json().await?;
                Ok(Some(Doc {
                    version: json["data"]["metadata"]["version"].as_u64().unwrap_or(0),
                    data: json["data"]["data"].clone(),
                }))
            }
            404 => Ok(None),
            403 => Err(StoreError::Forbidden),
            s => Err(rejected(s, resp).await),
        }
    }

    async fn put(
        &self,
        path: &str,
        data: &serde_json::Value,
        cas: Option<u64>,
    ) -> Result<u64, StoreError> {
        let body = match cas {
            Some(cas) => serde_json::json!({ "options": { "cas": cas }, "data": data }),
            None => serde_json::json!({ "data": data }),
        };
        let resp = self
            .request(reqwest::Method::POST, &self.data_path(path), Some(&body))
            .await?;
        match resp.status().as_u16() {
            200 | 204 => {
                // KV v2 answers a write with the new version's metadata; a
                // body that doesn't parse still means the write happened.
                let meta: Option<serde_json::Value> = resp.json().await.ok();
                Ok(meta
                    .and_then(|m| m["data"]["version"].as_u64())
                    .unwrap_or(0))
            }
            403 => Err(StoreError::Forbidden),
            s => {
                let body = resp.text().await.unwrap_or_default();
                if cas.is_some() && s == 400 && body.contains("check-and-set") {
                    return Err(StoreError::CasConflict);
                }
                Err(StoreError::Rejected { status: s, body })
            }
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        self.kv_list(&format!("{}/", self.metadata_path(prefix)))
            .await
    }

    async fn delete(&self, path: &str) -> Result<(), StoreError> {
        // The metadata endpoint removes every version, not just the latest.
        let resp = self
            .request(reqwest::Method::DELETE, &self.metadata_path(path), None)
            .await?;
        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            404 => Err(StoreError::NotFound),
            403 => Err(StoreError::Forbidden),
            s => Err(rejected(s, resp).await),
        }
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<(), StoreError> {
        // KV v2 has no subtree delete: walk it and delete each document.
        let mut dirs = vec![prefix.to_string()];
        while let Some(dir) = dirs.pop() {
            let names = match self.list(&dir).await {
                Ok(names) => names,
                Err(StoreError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            for name in names {
                let path = format!("{}/{}", dir, name.trim_end_matches('/'));
                if name.ends_with('/') {
                    dirs.push(path);
                } else {
                    match self.delete(&path).await {
                        Ok(()) | Err(StoreError::NotFound) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Ok(())
    }

    fn spawn_maintenance(self: Arc<Self>) {
        self.spawn_renewal_task();
    }
}

/// Build a reqwest HTTP client from a VaultConfig (extracted for testability).
fn build_vault_http_client(config: &VaultConfig) -> Result<reqwest::Client, StoreError> {
    let needs_custom_tls =
        config.client_cert.is_some() || config.ca_cert.is_some() || config.tls_skip_verify;

    if !needs_custom_tls {
        // Simple path: no custom TLS config needed
        return reqwest::Client::builder()
            .build()
            .map_err(|e| StoreError::Auth(format!("failed to create HTTP client: {}", e)));
    }

    // Ensure ring crypto provider is available (needed when building rustls ClientConfig
    // directly rather than through reqwest's builder).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build a rustls ClientConfig directly — this bypasses reqwest::Identity::from_pem()
    // which can fail with the rustls backend for valid PKCS#8 keys from OpenBao/Vault PKI.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Custom CA certificate for private/self-signed CAs
    if let Some(ref ca_path) = config.ca_cert {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|e| StoreError::Auth(format!("failed to read CA cert {}: {}", ca_path, e)))?;
        let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Auth(format!("failed to parse CA cert {}: {}", ca_path, e)))?;
        if ca_certs.is_empty() {
            return Err(StoreError::Auth(format!(
                "no certificates found in CA file {}",
                ca_path
            )));
        }
        for cert in &ca_certs {
            root_store.add(cert.clone()).map_err(|e| {
                StoreError::Auth(format!("failed to add CA cert to root store: {}", e))
            })?;
        }
        tracing::info!(
            "Vault TLS: added {} CA certificate(s) from {}",
            ca_certs.len(),
            ca_path
        );
    }

    let tls_config = if let Some(ref cert_path) = config.client_cert {
        // mTLS: parse client cert chain + private key, build rustls config directly
        let key_path = config.client_key.as_deref().ok_or_else(|| {
            StoreError::Auth(
                "client_cert is set but client_key is missing in [vault] config".into(),
            )
        })?;
        let cert_pem = std::fs::read(cert_path).map_err(|e| {
            StoreError::Auth(format!("failed to read client cert {}: {}", cert_path, e))
        })?;
        let key_pem = std::fs::read(key_path).map_err(|e| {
            StoreError::Auth(format!("failed to read client key {}: {}", key_path, e))
        })?;

        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                StoreError::Auth(format!(
                    "failed to parse certificates from {}: {}",
                    cert_path, e
                ))
            })?;
        if certs.is_empty() {
            return Err(StoreError::Auth(format!(
                "no certificates found in {}",
                cert_path
            )));
        }
        tracing::info!(
            "Vault TLS: parsed {} certificate(s) from {}",
            certs.len(),
            cert_path
        );

        let private_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| {
                StoreError::Auth(format!(
                    "failed to parse private key from {}: {} \
                     (expected PEM: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY, or BEGIN EC PRIVATE KEY)",
                    key_path, e
                ))
            })?
            .ok_or_else(|| {
                StoreError::Auth(format!(
                    "no private key found in {} \
                     (expected PEM: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY, or BEGIN EC PRIVATE KEY)",
                    key_path
                ))
            })?;
        tracing::info!(
            "Vault TLS: parsed private key from {} ({} bytes DER)",
            key_path,
            private_key.secret_der().len()
        );

        let builder = if config.tls_skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
        } else {
            rustls::ClientConfig::builder().with_root_certificates(root_store)
        };

        builder
            .with_client_auth_cert(certs, private_key)
            .map_err(|e| {
                StoreError::Auth(format!(
                    "failed to build mTLS config with {} + {}: {}",
                    cert_path, key_path, e
                ))
            })?
    } else {
        // CA cert only (no mTLS) or tls_skip_verify
        if config.tls_skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .map_err(|e| StoreError::Auth(format!("failed to create HTTP client: {}", e)))
}

/// Certificate verifier that accepts all server certificates (for tls_skip_verify).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JWT login from a token file on the `workload-jwt` mount.
    fn jwt_file_auth(path: &std::path::Path) -> crate::config::VaultJwtAuth {
        crate::config::VaultJwtAuth {
            mount: "workload-jwt".into(),
            role: "mybastion".into(),
            path: Some(path.to_str().unwrap().into()),
            token_command: None,
            token_command_timeout_secs: 10,
        }
    }

    #[test]
    fn jwt_auth_settings_are_checked() {
        let mut j = jwt_file_auth(std::path::Path::new("/run/token"));
        assert!(j.validate().is_ok());
        // The mount goes into the login URL: plain segments only.
        for mount in ["auth-k8s/jwt", "jwt", "nomad.workloads"] {
            j.mount = mount.into();
            assert!(j.validate().is_ok(), "{mount}");
        }
        for mount in [
            "",
            "../sys",
            "jwt/../../sys",
            "a//b",
            "/jwt",
            "jwt/",
            "j?x=1",
            "j wt",
        ] {
            j.mount = mount.into();
            assert!(j.validate().is_err(), "{mount:?} should be refused");
        }
        j.mount = "jwt".into();
        // Exactly one source for the token.
        j.token_command = Some(vec!["true".into()]);
        assert!(j.validate().is_err(), "path and token_command together");
        j.path = None;
        assert!(j.validate().is_ok());
        j.token_command = None;
        assert!(j.validate().is_err(), "neither");
        j.token_command = Some(vec![]);
        assert!(j.validate().is_err(), "an empty command");
    }

    fn jwt_command_auth(argv: &[&str], timeout: u64) -> crate::config::VaultJwtAuth {
        crate::config::VaultJwtAuth {
            mount: "workload-jwt".into(),
            role: "mybastion".into(),
            path: None,
            token_command: Some(argv.iter().map(|a| a.to_string()).collect()),
            token_command_timeout_secs: timeout,
        }
    }

    #[tokio::test]
    async fn jwt_token_command_runs_at_every_login() {
        // A cloud metadata service or SPIRE hands out a fresh token each
        // time; the command is run again at every login, never cached.
        let file = std::env::temp_dir().join(format!("mybastion-jwtcmd-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&file, "token-one\n").await.unwrap();
        let cfg = jwt_command_auth(&["cat", file.to_str().unwrap()], 10);
        assert_eq!(fetch_workload_jwt(&cfg).await.unwrap(), "token-one");
        tokio::fs::write(&file, "token-two").await.unwrap();
        assert_eq!(fetch_workload_jwt(&cfg).await.unwrap(), "token-two");
        tokio::fs::remove_file(&file).await.unwrap();
    }

    #[tokio::test]
    async fn jwt_token_command_failures_refuse_without_leaking_output() {
        // Whatever the command printed may be (part of) a token: it never
        // appears in the error.
        let failing = jwt_command_auth(&["sh", "-c", "echo secret-jwt-material; exit 3"], 10);
        let e = fetch_workload_jwt(&failing).await.unwrap_err().to_string();
        assert!(!e.contains("secret-jwt-material"), "{e}");
        assert!(e.contains("failed"), "{e}");

        let hanging = jwt_command_auth(&["sleep", "30"], 1);
        let started = std::time::Instant::now();
        let e = fetch_workload_jwt(&hanging).await.unwrap_err().to_string();
        assert!(e.contains("did not finish"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        let empty = jwt_command_auth(&["true"], 10);
        assert!(fetch_workload_jwt(&empty).await.is_err());

        let missing = jwt_command_auth(&["/nonexistent/mybastion-token-helper"], 10);
        let e = fetch_workload_jwt(&missing).await.unwrap_err().to_string();
        assert!(e.contains("could not run"), "{e}");
    }

    #[tokio::test]
    async fn workload_jwt_login_rereads_rotation_and_never_falls_back() {
        use axum::{routing::post, Json, Router};
        let calls = Arc::new(tokio::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let recorded = calls.clone();
        let app = Router::new().route("/v1/auth/workload-jwt/login", post(
            move |Json(body): Json<serde_json::Value>| {
                let recorded = recorded.clone();
                async move {
                    recorded.lock().await.push(body);
                    Json(serde_json::json!({"auth":{"client_token":"synthetic-session","lease_duration":300}}))
                }
            }
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let path = std::env::temp_dir().join(format!("mybastion-jwt-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, "synthetic-jwt-one\n")
            .await
            .unwrap();
        let mut config = base_config();
        config.addr = format!("http://{addr}");
        config.jwt_auth = Some(jwt_file_auth(&path));
        assert_eq!(
            config
                .login_secret("MYBASTION_TEST_ABSENT_SECRET_ID")
                .unwrap(),
            ""
        );
        let client = VaultStore::new(&config, "").await.unwrap();
        tokio::fs::write(&path, "synthetic-jwt-two\n")
            .await
            .unwrap();
        client.login().await.unwrap();
        assert_eq!(
            *calls.lock().await,
            vec![
                serde_json::json!({"role":"mybastion","jwt":"synthetic-jwt-one"}),
                serde_json::json!({"role":"mybastion","jwt":"synthetic-jwt-two"}),
            ]
        );
        tokio::fs::write(&path, "\n").await.unwrap();
        assert!(client.login().await.is_err());
        tokio::fs::remove_file(path).await.unwrap();
        assert!(client.login().await.is_err());
        assert_eq!(calls.lock().await.len(), 2);
        server.abort();
    }

    #[tokio::test]
    async fn workload_jwt_denial_does_not_fall_back_or_expose_response_body() {
        use axum::{http::StatusCode, routing::post, Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let approle_calls = Arc::new(AtomicUsize::new(0));
        let recorded = approle_calls.clone();
        let app = Router::new()
            .route("/v1/auth/workload-jwt/login", post(|| async {
                (StatusCode::FORBIDDEN, "synthetic-jwt-do-not-log")
            }))
            .route("/v1/auth/approle/login", post(move || {
                recorded.fetch_add(1, Ordering::SeqCst);
                async {
                    Json(serde_json::json!({"auth":{"client_token":"legacy-session","lease_duration":300}}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let path = std::env::temp_dir().join(format!("mybastion-jwt-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, "synthetic-jwt-do-not-log")
            .await
            .unwrap();
        let mut config = base_config();
        config.addr = format!("http://{addr}");
        config.jwt_auth = Some(jwt_file_auth(&path));
        let error = match VaultStore::new(&config, "legacy-secret").await {
            Err(error) => error,
            Ok(_) => panic!("JWT denial must fail closed"),
        };
        assert!(!error.to_string().contains("synthetic-jwt-do-not-log"));
        assert_eq!(approle_calls.load(Ordering::SeqCst), 0);
        tokio::fs::remove_file(path).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn workload_jwt_request_reauthenticates_with_rotated_file_after_forbidden() {
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::{get, post},
            Json, Router,
        };
        let calls = Arc::new(tokio::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let recorded = calls.clone();
        let app = Router::new()
            .route(
                "/v1/auth/workload-jwt/login",
                post(move |Json(body): Json<serde_json::Value>| {
                    let recorded = recorded.clone();
                    async move {
                        let token = if body["jwt"] == "jwt-two" {
                            "session-two"
                        } else {
                            "session-one"
                        };
                        recorded.lock().await.push(body);
                        Json(
                            serde_json::json!({"auth":{"client_token":token,"lease_duration":300}}),
                        )
                    }
                }),
            )
            .route(
                "/v1/secret/data/test",
                get(|headers: HeaderMap| async move {
                    if headers
                        .get("X-Vault-Token")
                        .and_then(|value| value.to_str().ok())
                        == Some("session-two")
                    {
                        StatusCode::OK
                    } else {
                        StatusCode::FORBIDDEN
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let path = std::env::temp_dir().join(format!("mybastion-jwt-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, "jwt-one").await.unwrap();
        let mut config = base_config();
        config.addr = format!("http://{addr}");
        config.jwt_auth = Some(jwt_file_auth(&path));
        let client = VaultStore::new(&config, "").await.unwrap();
        tokio::fs::write(&path, "jwt-two").await.unwrap();
        let response = client
            .request(reqwest::Method::GET, "/v1/secret/data/test", None)
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            *calls.lock().await,
            vec![
                serde_json::json!({"role":"mybastion","jwt":"jwt-one"}),
                serde_json::json!({"role":"mybastion","jwt":"jwt-two"}),
            ]
        );
        tokio::fs::remove_file(path).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn workload_jwt_changes_preserve_approle_login_and_namespace_header() {
        use axum::{http::HeaderMap, routing::post, Json, Router};
        let calls = Arc::new(tokio::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let recorded = calls.clone();
        let app = Router::new().route("/v1/auth/approle/login", post(move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
            let recorded = recorded.clone();
            async move {
                assert_eq!(headers.get("X-Vault-Namespace").unwrap(), "example-ns");
                recorded.lock().await.push(body);
                Json(serde_json::json!({"auth":{"client_token":"legacy-session","lease_duration":300}}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = base_config();
        config.addr = format!("http://{addr}");
        config.namespace = Some("example-ns".into());
        VaultStore::new(&config, "legacy-secret").await.unwrap();
        assert_eq!(
            *calls.lock().await,
            vec![serde_json::json!({"role_id":"test-role-id","secret_id":"legacy-secret"})]
        );
        server.abort();
    }

    fn base_config() -> VaultConfig {
        VaultConfig {
            addr: "https://vault.example.com:8200".into(),
            mount: "secret".into(),
            base_path: "mybastion".into(),
            role_id: "test-role-id".into(),
            jwt_auth: None,
            namespace: None,
            instance_name: None,
            tls_skip_verify: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        }
    }

    #[test]
    fn test_build_client_defaults() {
        let config = base_config();
        let client = build_vault_http_client(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_tls_skip_verify() {
        let mut config = base_config();
        config.tls_skip_verify = true;
        let client = build_vault_http_client(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_client_ca_cert_missing_file() {
        let mut config = base_config();
        config.ca_cert = Some("/nonexistent/ca.pem".into());
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read CA cert"), "got: {}", msg);
        assert!(msg.contains("/nonexistent/ca.pem"), "got: {}", msg);
    }

    #[test]
    fn test_build_client_ca_cert_invalid_pem() {
        // reqwest::Certificate::from_pem rejects PEM with valid headers but
        // garbage DER content.
        let dir = std::env::temp_dir().join("mybastion-test-vault-tls");
        let _ = std::fs::create_dir_all(&dir);
        let ca_path = dir.join("bad-ca.pem");
        let bad_pem =
            "-----BEGIN CERTIFICATE-----\nDEFINITELYnotvalid!!!\n-----END CERTIFICATE-----\n";
        std::fs::write(&ca_path, bad_pem.as_bytes()).unwrap();

        let mut config = base_config();
        config.ca_cert = Some(ca_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(result.is_err(), "expected error for invalid PEM");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_client_cert_without_key() {
        let dir = std::env::temp_dir().join("mybastion-test-vault-tls-nokey");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("client.pem");
        std::fs::write(&cert_path, b"placeholder").unwrap();

        let mut config = base_config();
        config.client_cert = Some(cert_path.to_str().unwrap().into());
        // client_key intentionally None
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("client_key is missing"), "got: {}", msg);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_client_cert_missing_file() {
        let mut config = base_config();
        config.client_cert = Some("/nonexistent/client.pem".into());
        config.client_key = Some("/nonexistent/client-key.pem".into());
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read client cert"), "got: {}", msg);
    }

    #[test]
    fn test_build_client_client_key_missing_file() {
        let dir = std::env::temp_dir().join("mybastion-test-vault-tls-keyfile");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("client.pem");
        std::fs::write(&cert_path, b"placeholder cert").unwrap();

        let mut config = base_config();
        config.client_cert = Some(cert_path.to_str().unwrap().into());
        config.client_key = Some("/nonexistent/client-key.pem".into());
        let err = build_vault_http_client(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read client key"), "got: {}", msg);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_valid_ca_cert() {
        let dir = std::env::temp_dir().join("mybastion-test-vault-tls-valid");
        let _ = std::fs::create_dir_all(&dir);
        let ca_path = dir.join("ca.pem");

        // Generate a real self-signed cert via openssl
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                "/dev/null",
                "-out",
                ca_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output()
            .expect("openssl must be available for this test");
        assert!(output.status.success(), "openssl failed: {:?}", output);

        let mut config = base_config();
        config.ca_cert = Some(ca_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_mtls_pkcs8_key() {
        // This test reproduces issue #51: PKCS#8 keys from OpenBao should work.
        let dir = std::env::temp_dir().join("mybastion-test-vault-mtls");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("client.pem");
        let key_path = dir.join("client-key.pem");

        // Generate CA
        let ca_key = dir.join("ca-key.pem");
        let ca_cert_path = dir.join("ca.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_cert_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success(), "CA gen failed");

        // Generate client cert signed by CA (PKCS#8 key — OpenBao default)
        let csr_path = dir.join("client.csr");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                csr_path.to_str().unwrap(),
                "-nodes",
                "-subj",
                "/CN=client",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success(), "CSR gen failed");

        let status = std::process::Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr_path.to_str().unwrap(),
                "-CA",
                ca_cert_path.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "1",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success(), "client cert gen failed");

        // Verify the key is PKCS#8 (BEGIN PRIVATE KEY, not BEGIN EC PRIVATE KEY)
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            key_pem.contains("BEGIN PRIVATE KEY"),
            "expected PKCS#8 key, got: {}",
            key_pem.lines().next().unwrap_or("")
        );

        let mut config = base_config();
        config.ca_cert = Some(ca_cert_path.to_str().unwrap().into());
        config.client_cert = Some(cert_path.to_str().unwrap().into());
        config.client_key = Some(key_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(
            result.is_ok(),
            "mTLS with PKCS#8 key failed: {:?}",
            result.err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_client_mtls_fullchain_cert() {
        // Test with fullchain cert (leaf + CA) — as OpenBao typically delivers.
        let dir = std::env::temp_dir().join("mybastion-test-vault-mtls-chain");
        let _ = std::fs::create_dir_all(&dir);
        let key_path = dir.join("client-key.pem");
        let fullchain_path = dir.join("client-fullchain.pem");

        // Generate CA
        let ca_key = dir.join("ca-key.pem");
        let ca_cert_path = dir.join("ca.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_cert_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success());

        // Generate client cert
        let csr_path = dir.join("client.csr");
        let leaf_path = dir.join("client-leaf.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                csr_path.to_str().unwrap(),
                "-nodes",
                "-subj",
                "/CN=client",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success());

        let status = std::process::Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr_path.to_str().unwrap(),
                "-CA",
                ca_cert_path.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                leaf_path.to_str().unwrap(),
                "-days",
                "1",
            ])
            .output()
            .expect("openssl needed");
        assert!(status.status.success());

        // Build fullchain: leaf + CA (as OpenBao delivers)
        let leaf = std::fs::read_to_string(&leaf_path).unwrap();
        let ca = std::fs::read_to_string(&ca_cert_path).unwrap();
        std::fs::write(&fullchain_path, format!("{}{}", leaf, ca)).unwrap();

        let mut config = base_config();
        config.ca_cert = Some(ca_cert_path.to_str().unwrap().into());
        config.client_cert = Some(fullchain_path.to_str().unwrap().into());
        config.client_key = Some(key_path.to_str().unwrap().into());
        let result = build_vault_http_client(&config);
        assert!(
            result.is_ok(),
            "mTLS with fullchain cert failed: {:?}",
            result.err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_deserialize_tls_fields() {
        let toml_str = r#"
            addr = "https://vault.example.com:8200"
            role_id = "test-role"
            ca_cert = "/opt/mybastion/certs/ca.pem"
            client_cert = "/opt/mybastion/certs/client.pem"
            client_key = "/opt/mybastion/certs/client-key.pem"
            tls_skip_verify = true
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.ca_cert.as_deref(),
            Some("/opt/mybastion/certs/ca.pem")
        );
        assert_eq!(
            config.client_cert.as_deref(),
            Some("/opt/mybastion/certs/client.pem")
        );
        assert_eq!(
            config.client_key.as_deref(),
            Some("/opt/mybastion/certs/client-key.pem")
        );
        assert!(config.tls_skip_verify);
    }

    #[test]
    fn test_config_deserialize_no_tls_fields() {
        let toml_str = r#"
            addr = "https://vault.example.com:8200"
            role_id = "test-role"
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert!(config.ca_cert.is_none());
        assert!(config.client_cert.is_none());
        assert!(config.client_key.is_none());
        assert!(!config.tls_skip_verify);
    }
}
