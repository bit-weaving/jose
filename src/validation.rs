//! Validation utilities for JOSE header parameters

use crate::error::{JoseError, Result};
use crate::algorithm::Algorithm;
use crate::header::{JwsHeader, JweHeader};

/// Validates a URL string if URL validation is enabled
#[cfg(feature = "url-validation")]
pub fn validate_url(parameter_name: &str, url_str: &str) -> Result<()> {
    use url::Url;

    Url::parse(url_str).map_err(|e| JoseError::InvalidUrl {
        parameter: parameter_name.to_string(),
        url: url_str.to_string(),
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Validates a URL string (no-op when URL validation is disabled)
#[cfg(not(feature = "url-validation"))]
pub fn validate_url(_parameter_name: &str, _url_str: &str) -> Result<()> {
    Ok(())
}

/// Validates base64url encoded data
pub fn validate_base64url(parameter_name: &str, data: &str) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    URL_SAFE_NO_PAD.decode(data).map_err(|e| JoseError::InvalidBase64 {
        parameter: parameter_name.to_string(),
        reason: e.to_string(),
    })?;

    Ok(())
}

/// Validates that a key ID contains only valid characters
pub fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() {
        return Err(JoseError::InvalidParameter {
            parameter: "kid".to_string(),
            reason: "Key ID cannot be empty".to_string(),
        });
    }

    // Key IDs should be reasonable length (RFC doesn't specify but let's be practical)
    if key_id.len() > 256 {
        return Err(JoseError::InvalidParameter {
            parameter: "kid".to_string(),
            reason: "Key ID is too long (max 256 characters)".to_string(),
        });
    }

    Ok(())
}

/// Validates critical header parameter
pub fn validate_critical(critical: &[String], header_params: &[&str]) -> Result<()> {
    if critical.is_empty() {
        return Err(JoseError::InvalidCritical(
            "Critical parameter array cannot be empty".to_string()
        ));
    }

    // Check for duplicates
    let mut seen = std::collections::HashSet::new();
    for param in critical {
        if !seen.insert(param) {
            return Err(JoseError::InvalidCritical(
                format!("Duplicate critical parameter: {}", param)
            ));
        }
    }

    // Check that all critical parameters are present in the header
    for param in critical {
        if !header_params.contains(&param.as_str()) {
            return Err(JoseError::InvalidCritical(
                format!("Critical parameter '{}' is not present in header", param)
            ));
        }
    }

    // Check that critical parameters are not standard ones that must be understood
    const FORBIDDEN_CRITICAL: &[&str] = &["alg", "enc", "typ", "cty", "crit"];
    for param in critical {
        if FORBIDDEN_CRITICAL.contains(&param.as_str()) {
            return Err(JoseError::InvalidCritical(
                format!("Standard parameter '{}' cannot be marked as critical", param)
            ));
        }
    }

    Ok(())
}

/// Validates PBES2 count parameter
pub fn validate_pbes2_count(count: u32) -> Result<()> {
    if count == 0 {
        return Err(JoseError::InvalidParameter {
            parameter: "p2c".to_string(),
            reason: "PBES2 count must be greater than 0".to_string(),
        });
    }

    // Reasonable upper limit to prevent DoS attacks
    if count > 10_000_000 {
        return Err(JoseError::InvalidParameter {
            parameter: "p2c".to_string(),
            reason: "PBES2 count is too high (max 10,000,000)".to_string(),
        });
    }

    Ok(())
}

/// Validates algorithm compatibility with header type
pub fn validate_algorithm_for_jws(algorithm: &Algorithm) -> Result<()> {
    if !algorithm.is_signature_algorithm() {
        return Err(JoseError::InvalidAlgorithm(
            format!("Algorithm '{}' is not suitable for JWS", algorithm)
        ));
    }
    Ok(())
}

/// Validates algorithm compatibility with JWE
pub fn validate_algorithm_for_jwe(algorithm: &Algorithm) -> Result<()> {
    if !algorithm.is_key_encryption_algorithm() {
        return Err(JoseError::InvalidAlgorithm(
            format!("Algorithm '{}' is not suitable for JWE key encryption", algorithm)
        ));
    }
    Ok(())
}

/// Validates X.509 certificate chain format
pub fn validate_x509_chain(chain: &[String]) -> Result<()> {
    if chain.is_empty() {
        return Err(JoseError::InvalidParameter {
            parameter: "x5c".to_string(),
            reason: "X.509 certificate chain cannot be empty".to_string(),
        });
    }

    for (i, cert) in chain.iter().enumerate() {
        validate_base64url(&format!("x5c[{}]", i), cert)?;
    }

    Ok(())
}

/// Validates X.509 thumbprint format
pub fn validate_x509_thumbprint(thumbprint: &str, parameter_name: &str) -> Result<()> {
    validate_base64url(parameter_name, thumbprint)?;

    // SHA-1 thumbprint should be 20 bytes = 27 base64url chars (without padding)
    // SHA-256 thumbprint should be 32 bytes = 43 base64url chars (without padding)
    let expected_len = match parameter_name {
        "x5t" => 27,
        "x5t#S256" => 43,
        _ => return Ok(()), // Unknown thumbprint type, don't validate length
    };

    if thumbprint.len() != expected_len {
        return Err(JoseError::InvalidParameter {
            parameter: parameter_name.to_string(),
            reason: format!("Invalid thumbprint length: expected {}, got {}",
                          expected_len, thumbprint.len()),
        });
    }

    Ok(())
}

/// Validates that required algorithm-specific parameters are present for JWE
pub fn validate_jwe_algorithm_params(header: &JweHeader) -> Result<()> {
    match &header.shared.algorithm {
        Algorithm::A128GCMKW | Algorithm::A192GCMKW | Algorithm::A256GCMKW => {
            if header.initialization_vector.is_none() {
                return Err(JoseError::MissingParameter(
                    "iv (Initialization Vector) is required for AES GCM key wrapping".to_string()
                ));
            }
            if header.authentication_tag.is_none() {
                return Err(JoseError::MissingParameter(
                    "tag (Authentication Tag) is required for AES GCM key wrapping".to_string()
                ));
            }
        }
        Algorithm::PBES2HS256A128KW | Algorithm::PBES2HS384A192KW | Algorithm::PBES2HS512A256KW => {
            if header.pbes2_salt_input.is_none() {
                return Err(JoseError::MissingParameter(
                    "p2s (PBES2 Salt Input) is required for PBES2 algorithms".to_string()
                ));
            }
            if header.pbes2_count.is_none() {
                return Err(JoseError::MissingParameter(
                    "p2c (PBES2 Count) is required for PBES2 algorithms".to_string()
                ));
            }
        }
        Algorithm::ECDHES | Algorithm::ECDHESA128KW | Algorithm::ECDHESA192KW | Algorithm::ECDHESA256KW => {
            if header.ephemeral_public_key.is_none() {
                return Err(JoseError::MissingParameter(
                    "epk (Ephemeral Public Key) is required for ECDH-ES algorithms".to_string()
                ));
            }
        }
        _ => {} // No additional parameters required
    }

    Ok(())
}

/// Validates conflicting parameter combinations
pub fn validate_no_conflicts(header: &JwsHeader) -> Result<()> {
    // Check for conflicting key identification parameters
    let key_params = [
        ("kid", header.shared.key_id.is_some()),
        ("jwk", header.shared.json_web_key.is_some()),
        ("jku", header.shared.jwk_set_url.is_some()),
    ];

    let present_count = key_params.iter().filter(|(_, is_present)| *is_present).count();
    if present_count > 1 {
        return Err(JoseError::ConflictingParameters {
            param1: "key identification".to_string(),
            param2: "parameters".to_string(),
            reason: "Only one key identification method should be used".to_string(),
        });
    }

    // Check X.509 related conflicts
    let x509_params = [
        ("x5u", header.shared.x509_url.is_some()),
        ("x5c", header.shared.x509_chain.is_some()),
    ];

    let x509_present_count = x509_params.iter().filter(|(_, is_present)| *is_present).count();
    if x509_present_count > 1 {
        return Err(JoseError::ConflictingParameters {
            param1: "x5u".to_string(),
            param2: "x5c".to_string(),
            reason: "X.509 URL and certificate chain are mutually exclusive".to_string(),
        });
    }

    Ok(())
}

/// Validates JWS header completeness and consistency
pub fn validate_jws_header(header: &JwsHeader) -> Result<()> {
    // Validate algorithm
    validate_algorithm_for_jws(&header.shared.algorithm)?;

    // Validate URLs if present
    if let Some(ref jku) = header.shared.jwk_set_url {
        validate_url("jku", jku)?;
    }
    if let Some(ref x5u) = header.shared.x509_url {
        validate_url("x5u", x5u)?;
    }
    if let Some(ref url) = header.shared.url {
        validate_url("url", url)?;
    }

    // Validate key ID if present
    if let Some(ref kid) = header.shared.key_id {
        validate_key_id(kid)?;
    }

    // Validate X.509 certificate chain if present
    if let Some(ref x5c) = header.shared.x509_chain {
        validate_x509_chain(x5c)?;
    }

    // Validate X.509 thumbprints if present
    if let Some(ref x5t) = header.shared.x509_thumbprint {
        validate_x509_thumbprint(x5t, "x5t")?;
    }
    if let Some(ref x5t_s256) = header.shared.x509_thumbprint_sha256 {
        validate_x509_thumbprint(x5t_s256, "x5t#S256")?;
    }

    // Validate critical parameters if present
    if let Some(ref crit) = header.shared.critical {
        let mut header_params = vec!["alg"];
        if header.shared.typ.is_some() { header_params.push("typ"); }
        if header.shared.content_type.is_some() { header_params.push("cty"); }
        if header.shared.key_id.is_some() { header_params.push("kid"); }
        if header.shared.jwk_set_url.is_some() { header_params.push("jku"); }
        if header.shared.json_web_key.is_some() { header_params.push("jwk"); }
        if header.shared.x509_url.is_some() { header_params.push("x5u"); }
        if header.shared.x509_chain.is_some() { header_params.push("x5c"); }
        if header.shared.x509_thumbprint.is_some() { header_params.push("x5t"); }
        if header.shared.x509_thumbprint_sha256.is_some() { header_params.push("x5t#S256"); }
        if header.shared.url.is_some() { header_params.push("url"); }
        if header.shared.nonce.is_some() { header_params.push("nonce"); }
        if header.base64url_encode_payload.is_some() { header_params.push("b64"); }
        if header.passport_extension.is_some() { header_params.push("ppt"); }
        if header.signature_validation_token.is_some() { header_params.push("svt"); }
        if header.trust_chain.is_some() { header_params.push("trust_chain"); }
        if header.ihe_submission_set_id.is_some() { header_params.push("iheSSId"); }

        // Add custom parameters
        for key in header.additional.keys() {
            header_params.push(key);
        }

        validate_critical(crit, &header_params)?;
    }

    // Validate conflicting parameters
    validate_no_conflicts(header)?;

    Ok(())
}

/// Validates JWE header completeness and consistency
pub fn validate_jwe_header(header: &JweHeader) -> Result<()> {
    // Validate algorithms
    validate_algorithm_for_jwe(&header.shared.algorithm)?;

    // Validate algorithm-specific parameters
    validate_jwe_algorithm_params(header)?;

    // Validate URLs if present
    if let Some(ref jku) = header.shared.jwk_set_url {
        validate_url("jku", jku)?;
    }
    if let Some(ref x5u) = header.shared.x509_url {
        validate_url("x5u", x5u)?;
    }
    if let Some(ref url) = header.shared.url {
        validate_url("url", url)?;
    }

    // Validate key ID if present
    if let Some(ref kid) = header.shared.key_id {
        validate_key_id(kid)?;
    }

    // Validate X.509 certificate chain if present
    if let Some(ref x5c) = header.shared.x509_chain {
        validate_x509_chain(x5c)?;
    }

    // Validate X.509 thumbprints if present
    if let Some(ref x5t) = header.shared.x509_thumbprint {
        validate_x509_thumbprint(x5t, "x5t")?;
    }
    if let Some(ref x5t_s256) = header.shared.x509_thumbprint_sha256 {
        validate_x509_thumbprint(x5t_s256, "x5t#S256")?;
    }

    // Validate base64url encoded parameters
    if let Some(ref apu) = header.agreement_party_u_info {
        validate_base64url("apu", apu)?;
    }
    if let Some(ref apv) = header.agreement_party_v_info {
        validate_base64url("apv", apv)?;
    }
    if let Some(ref iv) = header.initialization_vector {
        validate_base64url("iv", iv)?;
    }
    if let Some(ref tag) = header.authentication_tag {
        validate_base64url("tag", tag)?;
    }
    if let Some(ref p2s) = header.pbes2_salt_input {
        validate_base64url("p2s", p2s)?;
    }

    // Validate PBES2 count if present
    if let Some(p2c) = header.pbes2_count {
        validate_pbes2_count(p2c)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::Algorithm;


    #[test]
    fn test_validate_key_id() {
        assert!(validate_key_id("valid-key-id").is_ok());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id(&"x".repeat(300)).is_err());
    }

    #[test]
    fn test_validate_base64url() {
        assert!(validate_base64url("test", "SGVsbG8gV29ybGQ").is_ok());
        assert!(validate_base64url("test", "invalid base64!").is_err());
    }

    #[test]
    fn test_validate_critical() {
        let header_params = vec!["alg", "typ", "custom"];

        // Valid critical parameter
        assert!(validate_critical(&["custom".to_string()], &header_params).is_ok());

        // Empty critical array
        assert!(validate_critical(&[], &header_params).is_err());

        // Duplicate parameters
        assert!(validate_critical(&["custom".to_string(), "custom".to_string()], &header_params).is_err());

        // Missing parameter
        assert!(validate_critical(&["missing".to_string()], &header_params).is_err());

        // Forbidden standard parameter
        assert!(validate_critical(&["alg".to_string()], &header_params).is_err());
    }

    #[test]
    fn test_validate_algorithm_for_jws() {
        assert!(validate_algorithm_for_jws(&Algorithm::RS256).is_ok());
        assert!(validate_algorithm_for_jws(&Algorithm::A128KW).is_err());
    }

    #[test]
    fn test_validate_pbes2_count() {
        assert!(validate_pbes2_count(1000).is_ok());
        assert!(validate_pbes2_count(0).is_err());
        assert!(validate_pbes2_count(20_000_000).is_err());
    }

    #[test]
    fn test_validate_x509_thumbprint() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Generate valid SHA-1 thumbprint (20 bytes = 27 base64url chars)
        let sha1_bytes = [0u8; 20];
        let sha1_thumbprint = URL_SAFE_NO_PAD.encode(&sha1_bytes);
        assert!(validate_x509_thumbprint(&sha1_thumbprint, "x5t").is_ok());

        // Invalid length for SHA-1
        assert!(validate_x509_thumbprint("short", "x5t").is_err());

        // Generate valid SHA-256 thumbprint (32 bytes = 43 base64url chars)
        let sha256_bytes = [0u8; 32];
        let sha256_thumbprint = URL_SAFE_NO_PAD.encode(&sha256_bytes);
        assert!(validate_x509_thumbprint(&sha256_thumbprint, "x5t#S256").is_ok());

        // Invalid length for SHA-256
        assert!(validate_x509_thumbprint("short", "x5t#S256").is_err());
    }
}
