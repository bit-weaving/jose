//! Builder pattern implementation for JWS and JWE headers

use crate::algorithm::{Algorithm, EncryptionAlgorithm, CompressionAlgorithm};
use crate::error::Result;
use crate::header::{JwsHeader, JweHeader};
use crate::validation::{validate_jws_header, validate_jwe_header};
use serde_json::Value;
use std::collections::HashMap;

/// Builder for constructing JWS headers
#[derive(Debug, Clone)]
pub struct JwsHeaderBuilder {
    header: JwsHeader,
}

/// Builder for constructing JWE headers
#[derive(Debug, Clone)]
pub struct JweHeaderBuilder {
    header: JweHeader,
}

impl JwsHeaderBuilder {
    /// Create a new JWS header builder with the specified algorithm
    pub fn new() -> Self {
        Self {
            header: JwsHeader::default(),
        }
    }

    /// Set the signature algorithm
    pub fn algorithm(mut self, alg: Algorithm) -> Self {
        self.header.shared.algorithm = alg;
        self
    }

    /// Set the type header parameter
    pub fn typ<T: Into<String>>(mut self, typ: T) -> Self {
        self.header.shared.typ = Some(typ.into());
        self
    }

    /// Set the content type header parameter
    pub fn content_type<T: Into<String>>(mut self, cty: T) -> Self {
        self.header.shared.content_type = Some(cty.into());
        self
    }

    /// Set the key ID header parameter
    pub fn key_id<T: Into<String>>(mut self, kid: T) -> Self {
        self.header.shared.key_id = Some(kid.into());
        self
    }

    /// Set the JWK Set URL header parameter
    pub fn jwk_set_url<T: Into<String>>(mut self, jku: T) -> Self {
        self.header.shared.jwk_set_url = Some(jku.into());
        self
    }

    /// Set the JSON Web Key header parameter
    pub fn json_web_key(mut self, jwk: Value) -> Self {
        self.header.shared.json_web_key = Some(jwk);
        self
    }

    /// Set the X.509 URL header parameter
    pub fn x509_url<T: Into<String>>(mut self, x5u: T) -> Self {
        self.header.shared.x509_url = Some(x5u.into());
        self
    }

    /// Set the X.509 Certificate Chain header parameter
    pub fn x509_chain(mut self, x5c: Vec<String>) -> Self {
        self.header.shared.x509_chain = Some(x5c);
        self
    }

    /// Set the X.509 Certificate SHA-1 Thumbprint header parameter
    pub fn x509_thumbprint<T: Into<String>>(mut self, x5t: T) -> Self {
        self.header.shared.x509_thumbprint = Some(x5t.into());
        self
    }

    /// Set the X.509 Certificate SHA-256 Thumbprint header parameter
    pub fn x509_thumbprint_sha256<T: Into<String>>(mut self, x5t_s256: T) -> Self {
        self.header.shared.x509_thumbprint_sha256 = Some(x5t_s256.into());
        self
    }

    /// Set the URL header parameter
    pub fn url<T: Into<String>>(mut self, url: T) -> Self {
        self.header.shared.url = Some(url.into());
        self
    }

    /// Set the nonce header parameter
    pub fn nonce<T: Into<String>>(mut self, nonce: T) -> Self {
        self.header.shared.nonce = Some(nonce.into());
        self
    }

    /// Set the critical header parameter
    pub fn critical(mut self, crit: Vec<String>) -> Self {
        self.header.shared.critical = Some(crit);
        self
    }

    /// Set the Base64url-Encode Payload header parameter
    pub fn base64url_encode_payload(mut self, b64: bool) -> Self {
        self.header.base64url_encode_payload = Some(b64);
        self
    }

    /// Set the PASSporT extension identifier header parameter
    pub fn passport_extension<T: Into<String>>(mut self, ppt: T) -> Self {
        self.header.passport_extension = Some(ppt.into());
        self
    }

    /// Set the Signature Validation Token header parameter
    pub fn signature_validation_token(mut self, svt: Value) -> Self {
        self.header.signature_validation_token = Some(svt);
        self
    }

    /// Set the OpenID Federation Trust Chain header parameter
    pub fn trust_chain(mut self, trust_chain: Vec<String>) -> Self {
        self.header.trust_chain = Some(trust_chain);
        self
    }

    /// Set the IHE SubmissionSet ID header parameter
    pub fn ihe_submission_set_id<T: Into<String>>(mut self, ihe_ss_id: T) -> Self {
        self.header.ihe_submission_set_id = Some(ihe_ss_id.into());
        self
    }

    /// Add a custom header parameter
    pub fn custom_parameter<K: Into<String>>(mut self, name: K, value: Value) -> Self {
        self.header.additional.insert(name.into(), value);
        self
    }

    /// Add multiple custom header parameters
    pub fn custom_parameters(mut self, params: HashMap<String, Value>) -> Self {
        self.header.additional.extend(params);
        self
    }

    /// Build the JWS header, validating all parameters
    pub fn build(self) -> Result<JwsHeader> {
        // Validate the header before returning
        validate_jws_header(&self.header)?;
        Ok(self.header)
    }

    /// Build the JWS header without validation (use with caution)
    pub fn build_unchecked(self) -> JwsHeader {
        self.header
    }
}

impl JweHeaderBuilder {
    /// Create a new JWE header builder
    pub fn new() -> Self {
        Self {
            header: JweHeader::default(),
        }
    }

    /// Set the key encryption algorithm
    pub fn algorithm(mut self, alg: Algorithm) -> Self {
        self.header.shared.algorithm = alg;
        self
    }

    /// Set the content encryption algorithm
    pub fn encryption_algorithm(mut self, enc: EncryptionAlgorithm) -> Self {
        self.header.encryption_algorithm = enc;
        self
    }

    /// Set the compression algorithm
    pub fn compression_algorithm(mut self, zip: CompressionAlgorithm) -> Self {
        self.header.compression_algorithm = Some(zip);
        self
    }

    /// Set the type header parameter
    pub fn typ<T: Into<String>>(mut self, typ: T) -> Self {
        self.header.shared.typ = Some(typ.into());
        self
    }

    /// Set the content type header parameter
    pub fn content_type<T: Into<String>>(mut self, cty: T) -> Self {
        self.header.shared.content_type = Some(cty.into());
        self
    }

    /// Set the key ID header parameter
    pub fn key_id<T: Into<String>>(mut self, kid: T) -> Self {
        self.header.shared.key_id = Some(kid.into());
        self
    }

    /// Set the JWK Set URL header parameter
    pub fn jwk_set_url<T: Into<String>>(mut self, jku: T) -> Self {
        self.header.shared.jwk_set_url = Some(jku.into());
        self
    }

    /// Set the JSON Web Key header parameter
    pub fn json_web_key(mut self, jwk: Value) -> Self {
        self.header.shared.json_web_key = Some(jwk);
        self
    }

    /// Set the X.509 URL header parameter
    pub fn x509_url<T: Into<String>>(mut self, x5u: T) -> Self {
        self.header.shared.x509_url = Some(x5u.into());
        self
    }

    /// Set the X.509 Certificate Chain header parameter
    pub fn x509_chain(mut self, x5c: Vec<String>) -> Self {
        self.header.shared.x509_chain = Some(x5c);
        self
    }

    /// Set the X.509 Certificate SHA-1 Thumbprint header parameter
    pub fn x509_thumbprint<T: Into<String>>(mut self, x5t: T) -> Self {
        self.header.shared.x509_thumbprint = Some(x5t.into());
        self
    }

    /// Set the X.509 Certificate SHA-256 Thumbprint header parameter
    pub fn x509_thumbprint_sha256<T: Into<String>>(mut self, x5t_s256: T) -> Self {
        self.header.shared.x509_thumbprint_sha256 = Some(x5t_s256.into());
        self
    }

    /// Set the URL header parameter
    pub fn url<T: Into<String>>(mut self, url: T) -> Self {
        self.header.shared.url = Some(url.into());
        self
    }

    /// Set the nonce header parameter
    pub fn nonce<T: Into<String>>(mut self, nonce: T) -> Self {
        self.header.shared.nonce = Some(nonce.into());
        self
    }

    /// Set the critical header parameter
    pub fn critical(mut self, crit: Vec<String>) -> Self {
        self.header.shared.critical = Some(crit);
        self
    }

    /// Set the ephemeral public key header parameter
    pub fn ephemeral_public_key(mut self, epk: Value) -> Self {
        self.header.ephemeral_public_key = Some(epk);
        self
    }

    /// Set the Agreement PartyUInfo header parameter
    pub fn agreement_party_u_info<T: Into<String>>(mut self, apu: T) -> Self {
        self.header.agreement_party_u_info = Some(apu.into());
        self
    }

    /// Set the Agreement PartyVInfo header parameter
    pub fn agreement_party_v_info<T: Into<String>>(mut self, apv: T) -> Self {
        self.header.agreement_party_v_info = Some(apv.into());
        self
    }

    /// Set the initialization vector header parameter
    pub fn initialization_vector<T: Into<String>>(mut self, iv: T) -> Self {
        self.header.initialization_vector = Some(iv.into());
        self
    }

    /// Set the authentication tag header parameter
    pub fn authentication_tag<T: Into<String>>(mut self, tag: T) -> Self {
        self.header.authentication_tag = Some(tag.into());
        self
    }

    /// Set the PBES2 salt input header parameter
    pub fn pbes2_salt_input<T: Into<String>>(mut self, p2s: T) -> Self {
        self.header.pbes2_salt_input = Some(p2s.into());
        self
    }

    /// Set the PBES2 count header parameter
    pub fn pbes2_count(mut self, p2c: u32) -> Self {
        self.header.pbes2_count = Some(p2c);
        self
    }

    /// Set the issuer header parameter
    pub fn issuer<T: Into<String>>(mut self, iss: T) -> Self {
        self.header.issuer = Some(iss.into());
        self
    }

    /// Set the subject header parameter
    pub fn subject<T: Into<String>>(mut self, sub: T) -> Self {
        self.header.subject = Some(sub.into());
        self
    }

    /// Set the audience header parameter (single audience)
    pub fn audience<T: Into<String>>(mut self, aud: T) -> Self {
        self.header.audience = Some(Value::String(aud.into()));
        self
    }

    /// Set the audience header parameter (multiple audiences)
    pub fn audiences(mut self, aud: Vec<String>) -> Self {
        self.header.audience = Some(Value::Array(
            aud.into_iter().map(Value::String).collect()
        ));
        self
    }

    /// Add a custom header parameter
    pub fn custom_parameter<K: Into<String>>(mut self, name: K, value: Value) -> Self {
        self.header.additional.insert(name.into(), value);
        self
    }

    /// Add multiple custom header parameters
    pub fn custom_parameters(mut self, params: HashMap<String, Value>) -> Self {
        self.header.additional.extend(params);
        self
    }

    /// Build the JWE header, validating all parameters
    pub fn build(self) -> Result<JweHeader> {
        // Validate the header before returning
        validate_jwe_header(&self.header)?;
        Ok(self.header)
    }

    /// Build the JWE header without validation (use with caution)
    pub fn build_unchecked(self) -> JweHeader {
        self.header
    }
}

impl Default for JwsHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for JweHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{Algorithm, EncryptionAlgorithm};
    use serde_json::json;

    #[test]
    fn test_jws_builder_basic() {
        let header = JwsHeaderBuilder::new()
            .algorithm(Algorithm::RS256)
            .typ("JWT")
            .key_id("key-1")
            .build()
            .unwrap();

        assert_eq!(header.shared.algorithm, Algorithm::RS256);
        assert_eq!(header.shared.typ, Some("JWT".to_string()));
        assert_eq!(header.shared.key_id, Some("key-1".to_string()));
    }

    #[test]
    fn test_jws_builder_with_custom_params() {
        let header = JwsHeaderBuilder::new()
            .algorithm(Algorithm::ES256)
            .custom_parameter("custom", json!("value"))
            .build()
            .unwrap();

        assert_eq!(header.shared.algorithm, Algorithm::ES256);
        assert_eq!(header.additional.get("custom"), Some(&json!("value")));
    }

    #[test]
    fn test_jws_builder_validation_failure() {
        let result = JwsHeaderBuilder::new()
            .algorithm(Algorithm::A128KW) // Invalid for JWS
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_jwe_builder_basic() {
        let header = JweHeaderBuilder::new()
            .algorithm(Algorithm::RSAOAEP)
            .encryption_algorithm(EncryptionAlgorithm::A256GCM)
            .typ("JWE")
            .build()
            .unwrap();

        assert_eq!(header.shared.algorithm, Algorithm::RSAOAEP);
        assert_eq!(header.encryption_algorithm, EncryptionAlgorithm::A256GCM);
        assert_eq!(header.shared.typ, Some("JWE".to_string()));
    }

    #[test]
    fn test_jwe_builder_with_audiences() {
        let header = JweHeaderBuilder::new()
            .algorithm(Algorithm::Dir)
            .encryption_algorithm(EncryptionAlgorithm::A128GCM)
            .audiences(vec!["aud1".to_string(), "aud2".to_string()])
            .build()
            .unwrap();

        match &header.audience {
            Some(Value::Array(arr)) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0], Value::String("aud1".to_string()));
                assert_eq!(arr[1], Value::String("aud2".to_string()));
            }
            _ => panic!("Expected array audience"),
        }
    }

    #[test]
    fn test_jwe_builder_pbes2_params() {
        let header = JweHeaderBuilder::new()
            .algorithm(Algorithm::PBES2HS256A128KW)
            .encryption_algorithm(EncryptionAlgorithm::A128GCM)
            .pbes2_salt_input("c2FsdA")
            .pbes2_count(1000)
            .build()
            .unwrap();

        assert_eq!(header.shared.algorithm, Algorithm::PBES2HS256A128KW);
        assert_eq!(header.pbes2_salt_input, Some("c2FsdA".to_string()));
        assert_eq!(header.pbes2_count, Some(1000));
    }

    #[test]
    fn test_jwe_builder_gcm_params() {
        let header = JweHeaderBuilder::new()
            .algorithm(Algorithm::A256GCMKW)
            .encryption_algorithm(EncryptionAlgorithm::A256GCM)
            .initialization_vector("aXYxMjM")
            .authentication_tag("dGFnMTIz")
            .build()
            .unwrap();

        assert_eq!(header.shared.algorithm, Algorithm::A256GCMKW);
        assert_eq!(header.initialization_vector, Some("aXYxMjM".to_string()));
        assert_eq!(header.authentication_tag, Some("dGFnMTIz".to_string()));
    }

    #[test]
    fn test_jwe_builder_validation_failure() {
        let result = JweHeaderBuilder::new()
            .algorithm(Algorithm::RS256) // Invalid for JWE
            .encryption_algorithm(EncryptionAlgorithm::A256GCM)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_fluent_interface() {
        let header = JwsHeaderBuilder::new()
            .algorithm(Algorithm::HS256)
            .typ("JWT")
            .key_id("secret-key")
            .nonce("abc123")
            .custom_parameter("iat", json!(1234567890))
            .build()
            .unwrap();

        assert_eq!(header.shared.algorithm, Algorithm::HS256);
        assert_eq!(header.shared.typ, Some("JWT".to_string()));
        assert_eq!(header.shared.key_id, Some("secret-key".to_string()));
        assert_eq!(header.shared.nonce, Some("abc123".to_string()));
        assert_eq!(header.additional.get("iat"), Some(&json!(1234567890)));
    }

    #[test]
    fn test_unchecked_build() {
        // This should not fail even with invalid algorithm
        let header = JwsHeaderBuilder::new()
            .algorithm(Algorithm::A128KW) // Invalid for JWS
            .build_unchecked();

        assert_eq!(header.shared.algorithm, Algorithm::A128KW);
    }
}
