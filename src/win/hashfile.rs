//! File hashing (`certutil -hashfile`-style).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha384};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlg {
    Md5,
    Sha1,
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "md5" | "md-5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            _ => None,
        }
    }
}

pub fn hash_file(path: &Path, alg: HashAlg) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let (name, hex) = match alg {
        HashAlg::Md5 => {
            let d = md5::compute(&data);
            ("MD5", hex_lower(d.as_slice()))
        }
        HashAlg::Sha1 => {
            let mut h = Sha1::new();
            Sha1Digest::update(&mut h, &data);
            ("SHA1", hex_lower(h.finalize().as_slice()))
        }
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            Sha2Digest::update(&mut h, &data);
            ("SHA256", hex_lower(h.finalize().as_slice()))
        }
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            Sha2Digest::update(&mut h, &data);
            ("SHA384", hex_lower(h.finalize().as_slice()))
        }
    };
    Ok(format!(
        "CertUtil: -hashfile command completed successfully.\r\n{} hash of {}:\r\n{}\r\n",
        name,
        path.display(),
        hex
    ))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
