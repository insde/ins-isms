use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::fs;
use uuid::Uuid;

use crate::{config::StorageBackendConfig, error::AppError};

const ALLOWED_BINARY_MIMES: &[&str] = &[
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/webp",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
];

const ALLOWED_TEXT_MIMES: &[&str] = &["text/plain", "text/csv", "text/markdown"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlob {
    pub storage_key: String,
    pub sha256_hex: String,
    pub size_bytes: usize,
    pub content_type: String,
}

#[async_trait]
pub trait BlobStorage: Send + Sync {
    async fn put(
        &self,
        bytes: &[u8],
        declared_content_type: Option<&str>,
    ) -> Result<StoredBlob, AppError>;

    async fn get(&self, storage_key: &str) -> Result<Vec<u8>, AppError>;

    async fn delete(&self, storage_key: &str) -> Result<(), AppError>;
}

pub fn build_storage(cfg: &StorageBackendConfig) -> Box<dyn BlobStorage> {
    match cfg {
        StorageBackendConfig::Local { path } => Box::new(LocalBlobStorage::new(path.clone())),
        StorageBackendConfig::S3 {
            endpoint,
            bucket,
            region,
            access_key_id,
            secret_access_key,
        } => Box::new(S3BlobStorage {
            endpoint: endpoint.clone(),
            bucket: bucket.clone(),
            region: region.clone(),
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
        }),
    }
}

#[derive(Debug, Clone)]
pub struct LocalBlobStorage {
    base_path: PathBuf,
}

impl LocalBlobStorage {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    fn resolve_path(&self, storage_key: &str) -> Result<PathBuf, AppError> {
        let (p1, p2, id) = parse_storage_key(storage_key)?;
        Ok(self.base_path.join(p1).join(p2).join(id))
    }
}

#[async_trait]
impl BlobStorage for LocalBlobStorage {
    async fn put(
        &self,
        bytes: &[u8],
        declared_content_type: Option<&str>,
    ) -> Result<StoredBlob, AppError> {
        let content_type = validate_upload_bytes(bytes, declared_content_type)?;
        let sha256_hex = compute_sha256_hex(bytes);
        let id = Uuid::new_v4();
        let p1 = &sha256_hex[0..2];
        let p2 = &sha256_hex[2..4];
        let storage_key = format!("{p1}/{p2}/{id}");

        let dir = self.base_path.join(p1).join(p2);
        fs::create_dir_all(&dir).await?;
        let target = dir.join(id.to_string());
        fs::write(&target, bytes).await?;

        Ok(StoredBlob {
            storage_key,
            sha256_hex,
            size_bytes: bytes.len(),
            content_type,
        })
    }

    async fn get(&self, storage_key: &str) -> Result<Vec<u8>, AppError> {
        let path = self.resolve_path(storage_key)?;
        match fs::read(&path).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(AppError::NotFound("Datei nicht gefunden".to_string()))
            }
            Err(e) => Err(AppError::Io(e)),
        }
    }

    async fn delete(&self, storage_key: &str) -> Result<(), AppError> {
        let path = self.resolve_path(storage_key)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AppError::Io(e)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct S3BlobStorage {
    pub endpoint: Option<String>,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[async_trait]
impl BlobStorage for S3BlobStorage {
    async fn put(
        &self,
        bytes: &[u8],
        declared_content_type: Option<&str>,
    ) -> Result<StoredBlob, AppError> {
        let _ = validate_upload_bytes(bytes, declared_content_type)?;
        Err(AppError::Storage(format!(
            "S3-Backend (Bucket '{}') ist in diesem Build nicht aktiviert",
            self.bucket
        )))
    }

    async fn get(&self, _storage_key: &str) -> Result<Vec<u8>, AppError> {
        Err(AppError::Storage(
            "S3-Backend ist in diesem Build nicht aktiviert".to_string(),
        ))
    }

    async fn delete(&self, _storage_key: &str) -> Result<(), AppError> {
        Err(AppError::Storage(
            "S3-Backend ist in diesem Build nicht aktiviert".to_string(),
        ))
    }
}

pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn validate_upload_bytes(
    bytes: &[u8],
    declared_content_type: Option<&str>,
) -> Result<String, AppError> {
    if bytes.is_empty() {
        return Err(AppError::BadRequest(
            "Leere Dateien sind nicht erlaubt".to_string(),
        ));
    }

    if let Some(kind) = infer::get(bytes) {
        let mime = kind.mime_type();
        if ALLOWED_BINARY_MIMES.contains(&mime) {
            return Ok(mime.to_string());
        }
        return Err(AppError::UnsupportedMediaType(format!(
            "Dateityp '{mime}' ist nicht zulässig"
        )));
    }

    let declared = declared_content_type
        .map(|s| s.split(';').next().unwrap_or(s).trim().to_ascii_lowercase())
        .unwrap_or_else(|| "text/plain".to_string());

    if !ALLOWED_TEXT_MIMES.contains(&declared.as_str()) {
        return Err(AppError::UnsupportedMediaType(format!(
            "Dateityp '{declared}' ist nicht zulässig"
        )));
    }

    let text = std::str::from_utf8(bytes).map_err(|_| {
        AppError::UnsupportedMediaType("Unbekanntes Binärformat abgelehnt".to_string())
    })?;

    if text
        .bytes()
        .any(|b| (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')) || b == 0x7F)
    {
        return Err(AppError::UnsupportedMediaType(
            "Binäre Steuerzeichen in Textdatei abgelehnt".to_string(),
        ));
    }

    // Verhindert HTML-/SVG-Smuggling über Text-Uploads.
    let lower = text.to_ascii_lowercase();
    if lower.contains("<script")
        || lower.contains("<svg")
        || lower.contains("<!doctype html")
        || lower.contains("<html")
    {
        return Err(AppError::UnsupportedMediaType(
            "HTML- oder SVG-Inhalte sind nicht zulässig".to_string(),
        ));
    }

    Ok(declared)
}

fn parse_storage_key(key: &str) -> Result<(&str, &str, &str), AppError> {
    if key.contains('\\') || key.contains('\0') || Path::new(key).is_absolute() {
        return Err(AppError::BadRequest(
            "Ungültiger Speicher-Schlüssel".to_string(),
        ));
    }

    let mut parts = key.split('/');
    let p1 = parts.next();
    let p2 = parts.next();
    let id = parts.next();
    if parts.next().is_some() {
        return Err(AppError::BadRequest(
            "Ungültiger Speicher-Schlüssel".to_string(),
        ));
    }

    match (p1, p2, id) {
        (Some(a), Some(b), Some(c))
            if is_two_hex(a) && is_two_hex(b) && Uuid::parse_str(c).is_ok() =>
        {
            Ok((a, b, c))
        }
        _ => Err(AppError::BadRequest(
            "Ungültiger Speicher-Schlüssel".to_string(),
        )),
    }
}

fn is_two_hex(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn computes_deterministic_sha256() {
        let hash = compute_sha256_hex(b"ins-isms");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "fb4769035ff42d3ee7406f08fc702da7d42c6bcf4490651de9e59186503f7311"
        );
    }

    #[test]
    fn allows_valid_png_and_rejects_elf_and_svg() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert_eq!(
            validate_upload_bytes(&png, None).expect("png allowed"),
            "image/png"
        );

        let mut elf = vec![0x7F, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        elf.resize(52, 0x00);
        assert!(matches!(
            validate_upload_bytes(&elf, None),
            Err(AppError::UnsupportedMediaType(_))
        ));

        let pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00";
        assert!(matches!(
            validate_upload_bytes(pe, None),
            Err(AppError::UnsupportedMediaType(_))
        ));

        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
        assert!(matches!(
            validate_upload_bytes(svg, Some("text/plain")),
            Err(AppError::UnsupportedMediaType(_))
        ));
    }

    #[tokio::test]
    async fn local_storage_roundtrip_and_path_traversal_guard() {
        let dir = TempDir::new().expect("tempdir");
        let storage = LocalBlobStorage::new(dir.path().to_path_buf());

        let stored = storage
            .put(b"# Richtlinie\n\nInhalt", Some("text/markdown"))
            .await
            .expect("put markdown");

        let loaded = storage.get(&stored.storage_key).await.expect("get blob");
        assert_eq!(loaded, b"# Richtlinie\n\nInhalt");

        for bad_key in [
            "../etc/passwd",
            "ab/cd/../../secret",
            "zz/00/550e8400-e29b-41d4-a716-446655440000",
            "ab\\cd\\550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert!(matches!(
                storage.get(bad_key).await,
                Err(AppError::BadRequest(_))
            ));
        }

        storage
            .delete(&stored.storage_key)
            .await
            .expect("delete blob");
        assert!(matches!(
            storage.get(&stored.storage_key).await,
            Err(AppError::NotFound(_))
        ));
    }
}
