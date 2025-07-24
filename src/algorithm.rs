//! JOSE Algorithm definitions based on IANA registry

use serde::{Deserialize, Serialize};
use std::fmt;

/// JSON Web Signature and Encryption Algorithms
///
/// Based on the IANA JSON Web Signature and Encryption Algorithms registry.
/// See: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    // HMAC algorithms
    #[serde(rename = "HS256")]
    HS256,
    #[serde(rename = "HS384")]
    HS384,
    #[serde(rename = "HS512")]
    HS512,

    // RSA PKCS#1 algorithms
    #[serde(rename = "RS256")]
    RS256,
    #[serde(rename = "RS384")]
    RS384,
    #[serde(rename = "RS512")]
    RS512,

    // ECDSA algorithms
    #[serde(rename = "ES256")]
    ES256,
    #[serde(rename = "ES384")]
    ES384,
    #[serde(rename = "ES512")]
    ES512,
    #[serde(rename = "ES256K")]
    ES256K,

    // RSA PSS algorithms
    #[serde(rename = "PS256")]
    PS256,
    #[serde(rename = "PS384")]
    PS384,
    #[serde(rename = "PS512")]
    PS512,

    // EdDSA algorithms
    #[serde(rename = "EdDSA")]
    EdDSA,
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "Ed448")]
    Ed448,

    // ML-DSA algorithms (post-quantum)
    #[serde(rename = "ML-DSA-44")]
    MLDSA44,
    #[serde(rename = "ML-DSA-65")]
    MLDSA65,
    #[serde(rename = "ML-DSA-87")]
    MLDSA87,

    // No signature
    #[serde(rename = "none")]
    None,

    // RSA key encryption algorithms
    #[serde(rename = "RSA1_5")]
    RSA1_5,
    #[serde(rename = "RSA-OAEP")]
    RSAOAEP,
    #[serde(rename = "RSA-OAEP-256")]
    RSAOAEP256,
    #[serde(rename = "RSA-OAEP-384")]
    RSAOAEP384,
    #[serde(rename = "RSA-OAEP-512")]
    RSAOAEP512,

    // AES Key Wrap algorithms
    #[serde(rename = "A128KW")]
    A128KW,
    #[serde(rename = "A192KW")]
    A192KW,
    #[serde(rename = "A256KW")]
    A256KW,

    // Direct key agreement
    #[serde(rename = "dir")]
    Dir,

    // ECDH-ES algorithms
    #[serde(rename = "ECDH-ES")]
    ECDHES,
    #[serde(rename = "ECDH-ES+A128KW")]
    ECDHESA128KW,
    #[serde(rename = "ECDH-ES+A192KW")]
    ECDHESA192KW,
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDHESA256KW,

    // AES GCM Key Wrap algorithms
    #[serde(rename = "A128GCMKW")]
    A128GCMKW,
    #[serde(rename = "A192GCMKW")]
    A192GCMKW,
    #[serde(rename = "A256GCMKW")]
    A256GCMKW,

    // PBES2 algorithms
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2HS256A128KW,
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2HS384A192KW,
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2HS512A256KW,
}

/// Content Encryption Algorithms for JWE
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "A128CBC-HS256")]
    A128CBCHS256,
    #[serde(rename = "A192CBC-HS384")]
    A192CBCHS384,
    #[serde(rename = "A256CBC-HS512")]
    A256CBCHS512,
    #[serde(rename = "A128GCM")]
    A128GCM,
    #[serde(rename = "A192GCM")]
    A192GCM,
    #[serde(rename = "A256GCM")]
    A256GCM,
}

/// Compression Algorithms for JWE
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    #[serde(rename = "DEF")]
    DEF,
}

impl Algorithm {
    /// Returns true if this algorithm is suitable for JWS (signing)
    pub fn is_signature_algorithm(&self) -> bool {
        matches!(
            self,
            Algorithm::HS256
                | Algorithm::HS384
                | Algorithm::HS512
                | Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
                | Algorithm::ES512
                | Algorithm::ES256K
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
                | Algorithm::EdDSA
                | Algorithm::Ed25519
                | Algorithm::Ed448
                | Algorithm::MLDSA44
                | Algorithm::MLDSA65
                | Algorithm::MLDSA87
                | Algorithm::None
        )
    }

    /// Returns true if this algorithm is suitable for JWE key encryption
    pub fn is_key_encryption_algorithm(&self) -> bool {
        matches!(
            self,
            Algorithm::RSA1_5
                | Algorithm::RSAOAEP
                | Algorithm::RSAOAEP256
                | Algorithm::RSAOAEP384
                | Algorithm::RSAOAEP512
                | Algorithm::A128KW
                | Algorithm::A192KW
                | Algorithm::A256KW
                | Algorithm::Dir
                | Algorithm::ECDHES
                | Algorithm::ECDHESA128KW
                | Algorithm::ECDHESA192KW
                | Algorithm::ECDHESA256KW
                | Algorithm::A128GCMKW
                | Algorithm::A192GCMKW
                | Algorithm::A256GCMKW
                | Algorithm::PBES2HS256A128KW
                | Algorithm::PBES2HS384A192KW
                | Algorithm::PBES2HS512A256KW
        )
    }

    /// Returns true if this algorithm requires additional parameters
    pub fn requires_additional_params(&self) -> bool {
        matches!(
            self,
            Algorithm::A128GCMKW
                | Algorithm::A192GCMKW
                | Algorithm::A256GCMKW
                | Algorithm::PBES2HS256A128KW
                | Algorithm::PBES2HS384A192KW
                | Algorithm::PBES2HS512A256KW
        )
    }

    /// Returns the recommended key size in bits for this algorithm
    pub fn recommended_key_size(&self) -> Option<usize> {
        match self {
            Algorithm::HS256 | Algorithm::RS256 | Algorithm::ES256 | Algorithm::PS256 => Some(256),
            Algorithm::HS384 | Algorithm::RS384 | Algorithm::ES384 | Algorithm::PS384 => Some(384),
            Algorithm::HS512 | Algorithm::RS512 | Algorithm::ES512 | Algorithm::PS512 => Some(512),
            Algorithm::A128KW | Algorithm::A128GCMKW => Some(128),
            Algorithm::A192KW | Algorithm::A192GCMKW => Some(192),
            Algorithm::A256KW | Algorithm::A256GCMKW => Some(256),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512",
            Algorithm::ES256K => "ES256K",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            Algorithm::EdDSA => "EdDSA",
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::Ed448 => "Ed448",
            Algorithm::MLDSA44 => "ML-DSA-44",
            Algorithm::MLDSA65 => "ML-DSA-65",
            Algorithm::MLDSA87 => "ML-DSA-87",
            Algorithm::None => "none",
            Algorithm::RSA1_5 => "RSA1_5",
            Algorithm::RSAOAEP => "RSA-OAEP",
            Algorithm::RSAOAEP256 => "RSA-OAEP-256",
            Algorithm::RSAOAEP384 => "RSA-OAEP-384",
            Algorithm::RSAOAEP512 => "RSA-OAEP-512",
            Algorithm::A128KW => "A128KW",
            Algorithm::A192KW => "A192KW",
            Algorithm::A256KW => "A256KW",
            Algorithm::Dir => "dir",
            Algorithm::ECDHES => "ECDH-ES",
            Algorithm::ECDHESA128KW => "ECDH-ES+A128KW",
            Algorithm::ECDHESA192KW => "ECDH-ES+A192KW",
            Algorithm::ECDHESA256KW => "ECDH-ES+A256KW",
            Algorithm::A128GCMKW => "A128GCMKW",
            Algorithm::A192GCMKW => "A192GCMKW",
            Algorithm::A256GCMKW => "A256GCMKW",
            Algorithm::PBES2HS256A128KW => "PBES2-HS256+A128KW",
            Algorithm::PBES2HS384A192KW => "PBES2-HS384+A192KW",
            Algorithm::PBES2HS512A256KW => "PBES2-HS512+A256KW",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EncryptionAlgorithm::A128CBCHS256 => "A128CBC-HS256",
            EncryptionAlgorithm::A192CBCHS384 => "A192CBC-HS384",
            EncryptionAlgorithm::A256CBCHS512 => "A256CBC-HS512",
            EncryptionAlgorithm::A128GCM => "A128GCM",
            EncryptionAlgorithm::A192GCM => "A192GCM",
            EncryptionAlgorithm::A256GCM => "A256GCM",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DEF")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_serialization() {
        let alg = Algorithm::RS256;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"RS256\"");

        let deserialized: Algorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, alg);
    }

    #[test]
    fn test_signature_algorithms() {
        assert!(Algorithm::RS256.is_signature_algorithm());
        assert!(Algorithm::ES256.is_signature_algorithm());
        assert!(Algorithm::HS256.is_signature_algorithm());
        assert!(!Algorithm::A128KW.is_signature_algorithm());
    }

    #[test]
    fn test_key_encryption_algorithms() {
        assert!(Algorithm::RSA1_5.is_key_encryption_algorithm());
        assert!(Algorithm::A256KW.is_key_encryption_algorithm());
        assert!(!Algorithm::RS256.is_key_encryption_algorithm());
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(Algorithm::RS256.to_string(), "RS256");
        assert_eq!(Algorithm::ECDHESA128KW.to_string(), "ECDH-ES+A128KW");
        assert_eq!(Algorithm::MLDSA44.to_string(), "ML-DSA-44");
    }
}
