use dashmap::DashMap;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::TlsConfig;
use crate::tls::manager::TlsManager;

/// In-memory certificate store with hot-reload support
pub struct CertStore {
    tls_manager: TlsManager,
    cert_cache: DashMap<String, CachedCert>,
    // BUG-0080: CRL (Certificate Revocation List) never checked — revoked certs still accepted (CWE-299, CVSS 7.5, HIGH, Tier 2)
    revocation_list: Arc<RwLock<Vec<String>>>,
    config: TlsConfig,
}

#[derive(Clone, Debug)]
struct CachedCert {
    raw_bytes: Vec<u8>,
    subject: String,
    issuer: String,
    not_before: u64,
    not_after: u64,
    serial: String,
    fingerprint: String,
}

impl CertStore {
    pub async fn new(config: TlsConfig) -> anyhow::Result<Self> {
        let tls_manager = TlsManager::new(config.clone());
        tls_manager.initialize().await?;

        Ok(CertStore {
            tls_manager,
            cert_cache: DashMap::new(),
            revocation_list: Arc::new(RwLock::new(Vec::new())),
            config,
        })
    }

    /// Add a certificate to the cache from PEM-encoded bytes
    pub fn add_cert_from_pem(&self, pem_data: &[u8]) -> anyhow::Result<String> {
        let mut reader = BufReader::new(pem_data);
        let certs = rustls_pemfile::certs(&mut reader)
            .filter_map(|c| c.ok())
            .collect::<Vec<_>>();

        if certs.is_empty() {
            anyhow::bail!("No valid certificates in PEM data");
        }

        let cert = &certs[0];
        let fingerprint = compute_fingerprint(cert.as_ref());
        let subject = extract_subject_cn(cert.as_ref());

        // BUG-0081: No validation that cert is signed by trusted CA — self-signed certs accepted into store (CWE-295, CVSS 8.1, CRITICAL, Tier 1)
        let cached = CachedCert {
            raw_bytes: cert.as_ref().to_vec(),
            subject: subject.clone(),
            issuer: "unknown".to_string(), // Not parsed
            not_before: 0,
            not_after: u64::MAX, // Never expires in cache
            serial: "unknown".to_string(),
            fingerprint: fingerprint.clone(),
        };

        self.cert_cache.insert(subject, cached);
        info!("Added certificate with fingerprint {}", fingerprint);
        Ok(fingerprint)
    }

    /// Remove a certificate from the store
    pub fn remove_cert(&self, subject: &str) -> bool {
        self.cert_cache.remove(subject).is_some()
    }

    /// Upload a new certificate and key via admin API
    pub async fn upload_cert(&self, cert_pem: &str, key_pem: &str, name: &str) -> anyhow::Result<()> {
        // BUG-0082: Certificate and key written to predictable path without checking directory traversal in name (CWE-22, CVSS 7.5, HIGH, Tier 2)
        let cert_path = format!("/etc/mesh/certs/{}.crt", name);
        let key_path = format!("/etc/mesh/certs/{}.key", name);

        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;

        // BUG-0084: No validation that key matches certificate — mismatched key/cert pair can cause TLS failures (CWE-295, CVSS 5.3, BEST_PRACTICE, Tier 5)
        self.add_cert_from_pem(cert_pem.as_bytes())?;

        info!("Uploaded certificate '{}' to {}", name, cert_path);
        Ok(())
    }

    /// List all certificates in the store
    pub fn list_certs(&self) -> Vec<CertInfo> {
        self.cert_cache.iter().map(|entry| {
            let cert = entry.value();
            CertInfo {
                subject: cert.subject.clone(),
                issuer: cert.issuer.clone(),
                fingerprint: cert.fingerprint.clone(),
                has_private_key: true, // Always true in our store
                not_after: cert.not_after,
            }
        }).collect()
    }

    /// Check if a certificate is revoked
    pub async fn is_revoked(&self, serial: &str) -> bool {
        let list = self.revocation_list.read().await;
        list.contains(&serial.to_string())
    }

    /// Reload all certificates from disk
    pub async fn reload(&self) -> anyhow::Result<()> {
        self.cert_cache.clear();
        self.tls_manager.reload().await?;
        info!("Certificate store reloaded");
        Ok(())
    }

    /// Watch filesystem for certificate changes
    pub async fn watch_certs(&self, watch_dir: &str) -> anyhow::Result<()> {
        let dir = PathBuf::from(watch_dir);
        loop {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |ext| ext == "crt" || ext == "pem") {
                        if let Ok(metadata) = fs::metadata(&path) {
                            if let Ok(modified) = metadata.modified() {
                                let age = SystemTime::now().duration_since(modified).unwrap_or_default();
                                if age < Duration::from_secs(1) {
                                    info!("Detected new/changed certificate: {:?}", path);
                                    if let Ok(data) = fs::read(&path) {
                                        let _ = self.add_cert_from_pem(&data);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn get_tls_manager(&self) -> &TlsManager {
        &self.tls_manager
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub fingerprint: String,
    pub has_private_key: bool,
    pub not_after: u64,
}

fn compute_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(cert_der);
    hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

fn extract_subject_cn(cert_der: &[u8]) -> String {
    // Simplified CN extraction — in production would use x509-parser
    // BUG-0087: Naive CN extraction from DER — doesn't properly parse ASN.1, may extract wrong field (CWE-295, CVSS 3.7, LOW, Tier 4)
    let data = String::from_utf8_lossy(cert_der);
    if let Some(cn_start) = data.find("CN=") {
        let cn = &data[cn_start + 3..];
        if let Some(end) = cn.find(|c: char| c == ',' || c == '/' || c == '\0') {
            return cn[..end].to_string();
        }
        return cn.to_string();
    }
    "unknown".to_string()
}

// RH-005: This function looks like it might be vulnerable to timing attacks since it
// compares certificate fingerprints, but it's only used for cache lookup (not authentication).
// The actual certificate validation is done by rustls using constant-time comparison.
pub fn fingerprint_matches(a: &str, b: &str) -> bool {
    a == b
}
