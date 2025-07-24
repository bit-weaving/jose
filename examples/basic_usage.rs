//! Basic usage examples for the JOSE header library

use jose::prelude::*;
use serde_json::json;
use jose::algorithm::{EncryptionAlgorithm, CompressionAlgorithm};

fn main() -> Result<()> {
    println!("🔐 JOSE Header Builder Examples\n");

    // Example 1: Basic JWS Header for JWT
    println!("📝 Example 1: Basic JWS Header for JWT");
    let jws_header = JwsHeaderBuilder::new()
        .algorithm(Algorithm::RS256)
        .typ("JWT")
        .key_id("rsa-key-1")
        .build()?;

    let json = serde_json::to_string_pretty(&jws_header)?;
    println!("JWS Header:\n{}\n", json);

    // Example 2: JWS Header with X.509 Certificate Chain
    println!("📝 Example 2: JWS Header with X.509 Certificate Chain");
    let x509_chain = vec![
        "MIIDQTCCAimgAwIBAgITBmyfz5mj0TDqQaDeX9y229mU8Q".to_string(),
    ];

    let jws_x509_header = JwsHeaderBuilder::new()
        .algorithm(Algorithm::ES256)
        .typ("JWT")
        .x509_chain(x509_chain)
        .x509_thumbprint_sha256("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .build()?;

    let json = serde_json::to_string_pretty(&jws_x509_header)?;
    println!("JWS Header with X.509:\n{}\n", json);

    // Example 3: JWS Header with Custom Parameters and Critical Extension
    println!("📝 Example 3: JWS Header with Custom Parameters");
    let jws_custom_header = JwsHeaderBuilder::new()
        .algorithm(Algorithm::EdDSA)
        .typ("JWT")
        .key_id("ed25519-key")
        .custom_parameter("exp", json!(1672531200))
        .custom_parameter("custom_claim", json!({"role": "admin"}))
        .critical(vec!["custom_claim".to_string()])
        .build()?;

    let json = serde_json::to_string_pretty(&jws_custom_header)?;
    println!("JWS Header with Custom Parameters:\n{}\n", json);

    // Example 4: Basic JWE Header
    println!("📝 Example 4: Basic JWE Header");
    let jwe_header = JweHeaderBuilder::new()
        .algorithm(Algorithm::RSAOAEP)
        .encryption_algorithm(EncryptionAlgorithm::A256GCM)
        .typ("JWE")
        .key_id("rsa-oaep-key")
        .build()?;

    let json = serde_json::to_string_pretty(&jwe_header)?;
    println!("JWE Header:\n{}\n", json);

    // Example 5: JWE Header with ECDH-ES Key Agreement
    println!("📝 Example 5: JWE Header with ECDH-ES Key Agreement");
    let ephemeral_key = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    });

    let jwe_ecdh_header = JweHeaderBuilder::new()
        .algorithm(Algorithm::ECDHESA256KW)
        .encryption_algorithm(EncryptionAlgorithm::A256GCM)
        .ephemeral_public_key(ephemeral_key)
        .agreement_party_u_info("QWxpY2U")  // base64url("Alice")
        .agreement_party_v_info("Qm9i")     // base64url("Bob")
        .build()?;

    let json = serde_json::to_string_pretty(&jwe_ecdh_header)?;
    println!("JWE Header with ECDH-ES:\n{}\n", json);

    // Example 6: JWE Header with PBES2 Password-Based Encryption
    println!("📝 Example 6: JWE Header with PBES2");
    let jwe_pbes2_header = JweHeaderBuilder::new()
        .algorithm(Algorithm::PBES2HS256A128KW)
        .encryption_algorithm(EncryptionAlgorithm::A128GCM)
        .pbes2_salt_input("c2FsdA") // base64url("salt")
        .pbes2_count(4096)
        .build()?;

    let json = serde_json::to_string_pretty(&jwe_pbes2_header)?;
    println!("JWE Header with PBES2:\n{}\n", json);

    // Example 7: JWE Header with AES GCM Key Wrapping
    println!("📝 Example 7: JWE Header with AES GCM Key Wrapping");
    let jwe_gcm_header = JweHeaderBuilder::new()
        .algorithm(Algorithm::A256GCMKW)
        .encryption_algorithm(EncryptionAlgorithm::A256GCM)
        .initialization_vector("aXYxMjM")   // base64url("iv123")
        .authentication_tag("dGFnMTIz")    // base64url("tag123")
        .key_id("aes256-gcm-key")
        .build()?;

    let json = serde_json::to_string_pretty(&jwe_gcm_header)?;
    println!("JWE Header with AES GCM Key Wrapping:\n{}\n", json);

    // Example 8: JWE Header with Compression
    println!("📝 Example 8: JWE Header with Compression");
    let jwe_compressed_header = JweHeaderBuilder::new()
        .algorithm(Algorithm::Dir)
        .encryption_algorithm(EncryptionAlgorithm::A256GCM)
        .compression_algorithm(CompressionAlgorithm::DEF)
        .build()?;

    let json = serde_json::to_string_pretty(&jwe_compressed_header)?;
    println!("JWE Header with Compression:\n{}\n", json);

    // Example 9: JWE Header with Multiple Audiences
    println!("📝 Example 9: JWE Header with Multiple Audiences");
    let jwe_multi_aud_header = JweHeaderBuilder::new()
        .algorithm(Algorithm::A128KW)
        .encryption_algorithm(EncryptionAlgorithm::A128GCM)
        .issuer("https://example.com")
        .subject("user123")
        .audiences(vec![
            "https://api.example.com".to_string(),
            "https://web.example.com".to_string(),
        ])
        .build()?;

    let json = serde_json::to_string_pretty(&jwe_multi_aud_header)?;
    println!("JWE Header with Multiple Audiences:\n{}\n", json);

    // Example 10: Algorithm Information
    println!("📝 Example 10: Algorithm Information");
    let algorithms = vec![
        Algorithm::RS256,
        Algorithm::ES256,
        Algorithm::HS256,
        Algorithm::RSAOAEP,
        Algorithm::A256KW,
        Algorithm::ECDHES,
    ];

    for alg in algorithms {
        println!(
            "Algorithm: {} | Signature: {} | Key Encryption: {} | Key Size: {:?}",
            alg,
            alg.is_signature_algorithm(),
            alg.is_key_encryption_algorithm(),
            alg.recommended_key_size()
        );
    }
    println!();

    // Example 11: Error Handling
    println!("📝 Example 11: Error Handling");

    // This will fail validation because RS256 is not suitable for JWE
    match JweHeaderBuilder::new()
        .algorithm(Algorithm::RS256)  // Wrong algorithm for JWE
        .encryption_algorithm(EncryptionAlgorithm::A256GCM)
        .build()
    {
        Ok(_) => println!("This shouldn't happen!"),
        Err(e) => println!("Expected error: {}", e),
    }

    // This will fail because PBES2 requires additional parameters
    match JweHeaderBuilder::new()
        .algorithm(Algorithm::PBES2HS256A128KW)
        .encryption_algorithm(EncryptionAlgorithm::A256GCM)
        // Missing p2s and p2c parameters
        .build()
    {
        Ok(_) => println!("This shouldn't happen!"),
        Err(e) => println!("Expected error: {}", e),
    }

    println!("\n✅ All examples completed successfully!");
    Ok(())
}
