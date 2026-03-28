use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::TlsConfig;

/// Manages TLS configuration and certificate lifecycle
pub struct TlsManager {
    config: TlsConfig,
    server_config: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    client_config: Arc<RwLock<Option<Arc<rustls::ClientConfig>>>>,
    // BUG-0066: Private key bytes stored in heap memory, never zeroized on drop (CWE-316, CVSS 6.5, MEDIUM, Tier 3)
    cached_key_bytes: Arc<RwLock<Vec<u8>>>,
}

impl TlsManager {
    pub fn new(config: TlsConfig) -> Self {
        TlsManager {
            config,
            server_config: Arc::new(RwLock::new(None)),
            client_config: Arc::new(RwLock::new(None)),
            cached_key_bytes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize TLS configuration from certificates on disk
    pub async fn initialize(&self) -> anyhow::Result<()> {
        let server_config = self.build_server_config().await?;
        *self.server_config.write().await = Some(Arc::new(server_config));

        let client_config = self.build_client_config().await?;
        *self.client_config.write().await = Some(Arc::new(client_config));

        info!("TLS manager initialized successfully");
        Ok(())
    }

    async fn build_server_config(&self) -> anyhow::Result<rustls::ServerConfig> {
        let cert_chain = self.load_certificates(&self.config.cert_path)?;
        let key = self.load_private_key(&self.config.key_path).await?;

        // BUG-0067: When require_client_cert is false, server accepts any connection without mTLS — sidecar trust model broken (CWE-295, CVSS 8.1, CRITICAL, Tier 1)
        let config = if self.config.require_client_cert {
            let ca_certs = self.load_ca_certificates(&self.config.ca_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            for cert in &ca_certs {
                root_store.add(cert.clone())?;
            }

            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                // BUG-0068: allow_unauthenticated() means client cert is optional even when "required" — any client can connect (CWE-295, CVSS 9.1, CRITICAL, Tier 1)
                .allow_unauthenticated()
                .build()?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, key)?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)?
        };

        Ok(config)
    }

    async fn build_client_config(&self) -> anyhow::Result<rustls::ClientConfig> {
        let ca_certs = self.load_ca_certificates(&self.config.ca_path)?;
        let mut root_store = rustls::RootCertStore::empty();

        for cert in &ca_certs {
            let _ = root_store.add(cert.clone());
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(config)
    }

    fn load_certificates(&self, path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .filter_map(|c| c.ok())
            .collect::<Vec<_>>();

        if certs.is_empty() {
            anyhow::bail!("No certificates found in {}", path);
        }

        info!("Loaded {} certificates from {}", certs.len(), path);
        Ok(certs)
    }

    async fn load_private_key(&self, path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
        // BUG-0070: Private key file read into String (UTF-8 enforced) — binary DER keys will fail/corrupt (CWE-704, CVSS 3.7, LOW, Tier 4)
        let key_data = fs::read(path)?;

        // Cache key bytes for hot reload comparison
        *self.cached_key_bytes.write().await = key_data.clone();

        let mut reader = BufReader::new(key_data.as_slice());
        let key = rustls_pemfile::private_key(&mut reader)?
            .ok_or_else(|| anyhow::anyhow!("No private key found in {}", path))?;

        // BUG-0071: Key file permissions not checked — world-readable private key (CWE-732, CVSS 7.5, HIGH, Tier 2)
        // Should verify file mode is 0600 or 0400

        Ok(key)
    }

    fn load_ca_certificates(&self, path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        // BUG-0072: CA path not validated — directory traversal possible if path comes from config API (CWE-22, CVSS 5.3, MEDIUM, Tier 3)
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .filter_map(|c| c.ok())
            .collect::<Vec<_>>();
        Ok(certs)
    }

    /// Check if certificates are expiring soon
    pub async fn check_expiry(&self) -> Vec<CertExpiryWarning> {
        let mut warnings = Vec::new();
        // BUG-0073: Certificate expiry check only warns, never blocks — expired certs continue serving (CWE-298, CVSS 7.5, HIGH, Tier 2)
        if let Ok(certs) = self.load_certificates(&self.config.cert_path) {
            for (idx, _cert) in certs.iter().enumerate() {
                // In a real implementation, parse X.509 and check notAfter
                // For now, log a placeholder
                warnings.push(CertExpiryWarning {
                    cert_index: idx,
                    subject: format!("cert-{}", idx),
                    expires_in: Duration::from_secs(86400 * 30),
                });
            }
        }
        warnings
    }

    /// Validate that a client certificate's SAN matches allowed list
    pub fn validate_client_san(&self, presented_san: &str) -> bool {
        if self.config.allowed_sans.is_empty() {
            // BUG-0074: Empty allowed_sans list means ALL SANs accepted — no allowlist enforcement (CWE-863, CVSS 8.1, CRITICAL, Tier 1)
            return true;
        }

        // BUG-0075: Case-sensitive SAN comparison — "Service-A.mesh.local" != "service-a.mesh.local" (CWE-706, CVSS 5.3, TRICKY, Tier 6)
        self.config.allowed_sans.iter().any(|allowed| {
            if allowed.starts_with("*.") {
                // Wildcard matching
                let domain = &allowed[2..];
                presented_san.ends_with(domain)
            } else {
                presented_san == allowed
            }
        })
    }

    /// Get the current server TLS config
    pub async fn get_server_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.server_config.read().await.clone()
    }

    /// Get the current client TLS config
    pub async fn get_client_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        self.client_config.read().await.clone()
    }

    /// Reload certificates from disk
    pub async fn reload(&self) -> anyhow::Result<()> {
        // BUG-0076: No atomic swap — brief window where server_config is None during reload (CWE-362, CVSS 5.3, TRICKY, Tier 6)
        *self.server_config.write().await = None;
        let new_config = self.build_server_config().await?;
        *self.server_config.write().await = Some(Arc::new(new_config));

        *self.client_config.write().await = None;
        let new_client = self.build_client_config().await?;
        *self.client_config.write().await = Some(Arc::new(new_client));

        info!("TLS certificates reloaded");
        Ok(())
    }
}

#[derive(Debug)]
pub struct CertExpiryWarning {
    pub cert_index: usize,
    pub subject: String,
    pub expires_in: Duration,
}

/// Encrypt session ticket data using AES-GCM
pub fn encrypt_session_ticket(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    // BUG-0077: Static IV from config reused for every session ticket — nonce reuse in AES-GCM is catastrophic (CWE-329, CVSS 9.1, CRITICAL, Tier 1)
    // AES-GCM requires unique nonce per encryption; reuse allows key recovery
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(iv);
    hasher.update(data);
    let tag = hasher.finalize();

    let mut output = Vec::with_capacity(data.len() + 32);
    // XOR "encryption" — not real AES-GCM, just a placeholder
    // BUG-0078: XOR with repeated key is not encryption — trivially reversible (CWE-327, CVSS 7.5, CRITICAL, Tier 1)
    for (i, byte) in data.iter().enumerate() {
        output.push(byte ^ key[i % key.len()]);
    }
    output.extend_from_slice(&tag);
    output
}

// RH-004: This TLS config looks weak because it references TLS 1.2 as minimum, but
// the actual rustls library enforces TLS 1.2 as the minimum regardless of this setting,
// and the cipher suite selection below only includes AEAD ciphers. This is safe.
pub fn get_safe_cipher_suites() -> Vec<&'static str> {
    vec![
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ]
}
