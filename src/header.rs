//! JOSE Header structures for JWS and JWE

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::algorithm::{Algorithm, EncryptionAlgorithm, CompressionAlgorithm};

/// Common header parameters shared between JWS and JWE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedHeader {
    /// Algorithm header parameter
    ///
    /// For JWS: signature/MAC algorithm
    /// For JWE: key encryption algorithm
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    /// Type header parameter
    ///
    /// Declares the media type of the complete JWS/JWE
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type header parameter
    ///
    /// Declares the media type of the secured content (payload)
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Critical header parameter
    ///
    /// Indicates extensions that must be understood and processed
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,

    /// Key ID header parameter
    ///
    /// Hint indicating which key was used
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// JWK Set URL header parameter
    ///
    /// URI referring to a resource for a set of JSON-encoded public keys
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub jwk_set_url: Option<String>,

    /// JSON Web Key header parameter
    ///
    /// Public key that corresponds to the key used to digitally sign the JWS
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub json_web_key: Option<serde_json::Value>,

    /// X.509 URL header parameter
    ///
    /// URI referring to a resource for the X.509 public key certificate
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 Certificate Chain header parameter
    ///
    /// Chain of one or more PKIX certificates
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate SHA-1 Thumbprint header parameter
    ///
    /// Base64url-encoded SHA-1 thumbprint of the X.509 certificate
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint: Option<String>,

    /// X.509 Certificate SHA-256 Thumbprint header parameter
    ///
    /// Base64url-encoded SHA-256 thumbprint of the X.509 certificate
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha256: Option<String>,

    /// URL header parameter (RFC 8555)
    ///
    /// URL for the resource being requested
    #[serde(rename = "url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Nonce header parameter (RFC 8555)
    ///
    /// Unique value to prevent replay attacks
    #[serde(rename = "nonce", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// JSON Web Signature Header
///
/// Contains header parameters specific to JWS operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsHeader {
    /// Shared header parameters
    #[serde(flatten)]
    pub shared: SharedHeader,

    /// Base64url-Encode Payload header parameter (RFC 7797)
    ///
    /// Determines whether the payload is base64url-encoded
    #[serde(rename = "b64", skip_serializing_if = "Option::is_none")]
    pub base64url_encode_payload: Option<bool>,

    /// PASSporT extension identifier header parameter (RFC 8225)
    ///
    /// Identifies the PASSporT extension
    #[serde(rename = "ppt", skip_serializing_if = "Option::is_none")]
    pub passport_extension: Option<String>,

    /// Signature Validation Token header parameter (RFC 9321)
    ///
    /// Contains signature validation token information
    #[serde(rename = "svt", skip_serializing_if = "Option::is_none")]
    pub signature_validation_token: Option<serde_json::Value>,

    /// OpenID Federation Trust Chain header parameter
    ///
    /// Contains trust chain information for OpenID Federation
    #[serde(rename = "trust_chain", skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<Vec<String>>,

    /// IHE SubmissionSet ID header parameter
    ///
    /// Specifies the SubmissionSet.uniqueId as per IHE specifications
    #[serde(rename = "iheSSId", skip_serializing_if = "Option::is_none")]
    pub ihe_submission_set_id: Option<String>,

    /// Additional custom header parameters
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// JSON Web Encryption Header
///
/// Contains header parameters specific to JWE operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweHeader {
    /// Shared header parameters
    #[serde(flatten)]
    pub shared: SharedHeader,

    /// Encryption Algorithm header parameter
    ///
    /// Content encryption algorithm used to encrypt the plaintext
    #[serde(rename = "enc")]
    pub encryption_algorithm: EncryptionAlgorithm,

    /// Compression Algorithm header parameter
    ///
    /// Compression algorithm applied to the plaintext before encryption
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<CompressionAlgorithm>,

    /// Ephemeral Public Key header parameter (RFC 7518)
    ///
    /// Ephemeral public key value for key agreement algorithms
    #[serde(rename = "epk", skip_serializing_if = "Option::is_none")]
    pub ephemeral_public_key: Option<serde_json::Value>,

    /// Agreement PartyUInfo header parameter (RFC 7518)
    ///
    /// Value for key agreement PartyUInfo
    #[serde(rename = "apu", skip_serializing_if = "Option::is_none")]
    pub agreement_party_u_info: Option<String>,

    /// Agreement PartyVInfo header parameter (RFC 7518)
    ///
    /// Value for key agreement PartyVInfo
    #[serde(rename = "apv", skip_serializing_if = "Option::is_none")]
    pub agreement_party_v_info: Option<String>,

    /// Initialization Vector header parameter (RFC 7518)
    ///
    /// Initialization vector value for key wrapping algorithms
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<String>,

    /// Authentication Tag header parameter (RFC 7518)
    ///
    /// Authentication tag value for key wrapping algorithms
    #[serde(rename = "tag", skip_serializing_if = "Option::is_none")]
    pub authentication_tag: Option<String>,

    /// PBES2 Salt Input header parameter (RFC 7518)
    ///
    /// Salt input for PBES2 key derivation
    #[serde(rename = "p2s", skip_serializing_if = "Option::is_none")]
    pub pbes2_salt_input: Option<String>,

    /// PBES2 Count header parameter (RFC 7518)
    ///
    /// Iteration count for PBES2 key derivation
    #[serde(rename = "p2c", skip_serializing_if = "Option::is_none")]
    pub pbes2_count: Option<u32>,

    /// Issuer header parameter (RFC 7519)
    ///
    /// Identifies the issuer of the JWE
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject header parameter (RFC 7519)
    ///
    /// Identifies the subject of the JWE
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Audience header parameter (RFC 7519)
    ///
    /// Identifies the recipients of the JWE
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<serde_json::Value>, // Can be string or array of strings

    /// Additional custom header parameters
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl Default for SharedHeader {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::None, // Will be overridden by builder
            typ: None,
            content_type: None,
            critical: None,
            key_id: None,
            jwk_set_url: None,
            json_web_key: None,
            x509_url: None,
            x509_chain: None,
            x509_thumbprint: None,
            x509_thumbprint_sha256: None,
            url: None,
            nonce: None,
        }
    }
}

impl Default for JwsHeader {
    fn default() -> Self {
        Self {
            shared: SharedHeader::default(),
            base64url_encode_payload: None,
            passport_extension: None,
            signature_validation_token: None,
            trust_chain: None,
            ihe_submission_set_id: None,
            additional: HashMap::new(),
        }
    }
}

impl Default for JweHeader {
    fn default() -> Self {
        Self {
            shared: SharedHeader::default(),
            encryption_algorithm: EncryptionAlgorithm::A256GCM, // Will be overridden by builder
            compression_algorithm: None,
            ephemeral_public_key: None,
            agreement_party_u_info: None,
            agreement_party_v_info: None,
            initialization_vector: None,
            authentication_tag: None,
            pbes2_salt_input: None,
            pbes2_count: None,
            issuer: None,
            subject: None,
            audience: None,
            additional: HashMap::new(),
        }
    }
}

impl JwsHeader {
    /// Create a new JWS header with the specified algorithm
    pub fn new(algorithm: Algorithm) -> Self {
        let mut header = Self::default();
        header.shared.algorithm = algorithm;
        header
    }

    /// Get the algorithm from the header
    pub fn algorithm(&self) -> &Algorithm {
        &self.shared.algorithm
    }

    /// Add a custom header parameter
    pub fn add_custom_parameter(&mut self, name: String, value: serde_json::Value) {
        self.additional.insert(name, value);
    }

    /// Get a custom header parameter
    pub fn get_custom_parameter(&self, name: &str) -> Option<&serde_json::Value> {
        self.additional.get(name)
    }
}

impl JweHeader {
    /// Create a new JWE header with the specified algorithms
    pub fn new(key_algorithm: Algorithm, encryption_algorithm: EncryptionAlgorithm) -> Self {
        let mut header = Self::default();
        header.shared.algorithm = key_algorithm;
        header.encryption_algorithm = encryption_algorithm;
        header
    }

    /// Get the key encryption algorithm from the header
    pub fn key_algorithm(&self) -> &Algorithm {
        &self.shared.algorithm
    }

    /// Get the content encryption algorithm from the header
    pub fn encryption_algorithm(&self) -> &EncryptionAlgorithm {
        &self.encryption_algorithm
    }

    /// Add a custom header parameter
    pub fn add_custom_parameter(&mut self, name: String, value: serde_json::Value) {
        self.additional.insert(name, value);
    }

    /// Get a custom header parameter
    pub fn get_custom_parameter(&self, name: &str) -> Option<&serde_json::Value> {
        self.additional.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::Algorithm;

    #[test]
    fn test_jws_header_creation() {
        let header = JwsHeader::new(Algorithm::RS256);
        assert_eq!(*header.algorithm(), Algorithm::RS256);
    }

    #[test]
    fn test_jwe_header_creation() {
        let header = JweHeader::new(Algorithm::RSAOAEP, EncryptionAlgorithm::A256GCM);
        assert_eq!(*header.key_algorithm(), Algorithm::RSAOAEP);
        assert_eq!(*header.encryption_algorithm(), EncryptionAlgorithm::A256GCM);
    }

    #[test]
    fn test_jws_header_serialization() {
        let mut header = JwsHeader::new(Algorithm::RS256);
        header.shared.typ = Some("JWT".to_string());
        header.shared.key_id = Some("key-1".to_string());

        let json = serde_json::to_string(&header).unwrap();
        let deserialized: JwsHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.shared.algorithm, Algorithm::RS256);
        assert_eq!(deserialized.shared.typ, Some("JWT".to_string()));
        assert_eq!(deserialized.shared.key_id, Some("key-1".to_string()));
    }

    #[test]
    fn test_jwe_header_serialization() {
        let mut header = JweHeader::new(Algorithm::RSAOAEP, EncryptionAlgorithm::A256GCM);
        header.shared.typ = Some("JWE".to_string());
        header.compression_algorithm = Some(CompressionAlgorithm::DEF);

        let json = serde_json::to_string(&header).unwrap();
        let deserialized: JweHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.shared.algorithm, Algorithm::RSAOAEP);
        assert_eq!(deserialized.encryption_algorithm, EncryptionAlgorithm::A256GCM);
        assert_eq!(deserialized.compression_algorithm, Some(CompressionAlgorithm::DEF));
    }

    #[test]
    fn test_custom_parameters() {
        let mut header = JwsHeader::new(Algorithm::RS256);
        header.add_custom_parameter("custom".to_string(), serde_json::json!("value"));

        assert_eq!(
            header.get_custom_parameter("custom"),
            Some(&serde_json::json!("value"))
        );
    }
}
