# JOSE Header Builder

A Rust library for building JSON Web Signature (JWS) and JSON Web Encryption (JWE) headers based on the IANA JOSE registry specifications.

[![Crates.io](https://img.shields.io/crates/v/jose.svg)](https://crates.io/crates/jose)
[![Documentation](https://docs.rs/jose/badge.svg)](https://docs.rs/jose)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

## Features

- 🔐 **Type-safe header construction** - Compile-time guarantees for header validity
- 📋 **Complete IANA registry support** - All registered JOSE header parameters included
- 🔍 **Validation** - Built-in validation for header parameter combinations
- 🏗️ **Builder pattern** - Fluent, ergonomic API for header construction
- 📦 **Serde integration** - Seamless JSON serialization/deserialization
- 🎯 **Separate JWS/JWE builders** - Specialized builders for different use cases
- ⚡ **Zero-copy where possible** - Efficient memory usage
- 🧪 **Comprehensive testing** - Well-tested with extensive examples

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
jose = "0.1"
```

### Basic JWS Header

```rust
use jose::prelude::*;

let header = JwsHeaderBuilder::new()
    .algorithm(Algorithm::RS256)
    .typ("JWT")
    .key_id("rsa-key-1")
    .build()?;

let json = serde_json::to_string(&header)?;
println!("{}", json);
// Output: {"alg":"RS256","typ":"JWT","kid":"rsa-key-1"}
```

### Basic JWE Header

```rust
use jose::prelude::*;

let header = JweHeaderBuilder::new()
    .algorithm(Algorithm::RSAOAEP)
    .encryption_algorithm(EncryptionAlgorithm::A256GCM)
    .typ("JWE")
    .key_id("rsa-oaep-key")
    .build()?;

let json = serde_json::to_string(&header)?;
// Output: {"alg":"RSA-OAEP","enc":"A256GCM","typ":"JWE","kid":"rsa-oaep-key"}
```

## Supported Header Parameters

This library supports all header parameters from the [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml):

### Shared Parameters (JWS & JWE)

| Parameter | Description | Example |
|-----------|-------------|---------|
| `alg` | Algorithm | `RS256`, `A256KW` |
| `typ` | Type | `"JWT"`, `"JWE"` |
| `cty` | Content Type | `"application/json"` |
| `crit` | Critical | `["exp", "custom"]` |
| `kid` | Key ID | `"key-1"` |
| `jku` | JWK Set URL | `"https://example.com/keys"` |
| `jwk` | JSON Web Key | JWK object |
| `x5u` | X.509 URL | `"https://example.com/cert"` |
| `x5c` | X.509 Certificate Chain | Array of certificates |
| `x5t` | X.509 SHA-1 Thumbprint | Base64url encoded |
| `x5t#S256` | X.509 SHA-256 Thumbprint | Base64url encoded |
| `url` | URL | `"https://example.com/resource"` |
| `nonce` | Nonce | `"abc123"` |

### JWS-Specific Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `b64` | Base64url-Encode Payload | `true`/`false` |
| `ppt` | PASSporT Extension | `"div"` |
| `svt` | Signature Validation Token | SVT object |
| `trust_chain` | OpenID Federation Trust Chain | Array of strings |
| `iheSSId` | IHE SubmissionSet ID | `"submission-123"` |

### JWE-Specific Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `enc` | Encryption Algorithm | `A256GCM`, `A128CBC-HS256` |
| `zip` | Compression Algorithm | `DEF` |
| `epk` | Ephemeral Public Key | JWK object |
| `apu` | Agreement PartyUInfo | Base64url encoded |
| `apv` | Agreement PartyVInfo | Base64url encoded |
| `iv` | Initialization Vector | Base64url encoded |
| `tag` | Authentication Tag | Base64url encoded |
| `p2s` | PBES2 Salt Input | Base64url encoded |
| `p2c` | PBES2 Count | `4096` |
| `iss` | Issuer | `"https://issuer.example.com"` |
| `sub` | Subject | `"user123"` |
| `aud` | Audience | `"https://api.example.com"` |

## Algorithms

The library supports all IANA-registered algorithms:

### Signature Algorithms (JWS)

- **HMAC**: `HS256`, `HS384`, `HS512`
- **RSA PKCS#1**: `RS256`, `RS384`, `RS512`
- **RSA PSS**: `PS256`, `PS384`, `PS512`
- **ECDSA**: `ES256`, `ES384`, `ES512`, `ES256K`
- **EdDSA**: `EdDSA`, `Ed25519`, `Ed448`
- **Post-quantum**: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`
- **None**: `none`

### Key Encryption Algorithms (JWE)

- **RSA**: `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512`
- **AES Key Wrap**: `A128KW`, `A192KW`, `A256KW`
- **AES GCM**: `A128GCMKW`, `A192GCMKW`, `A256GCMKW`
- **ECDH-ES**: `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`
- **PBES2**: `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`
- **Direct**: `dir`

### Content Encryption Algorithms (JWE)

- **AES GCM**: `A128GCM`, `A192GCM`, `A256GCM`
- **AES CBC**: `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`

## Advanced Examples

### JWS with X.509 Certificate Chain

```rust
use jose::prelude::*;

let header = JwsHeaderBuilder::new()
    .algorithm(Algorithm::ES256)
    .typ("JWT")
    .x509_chain(vec![
        "MIICXjCCAcegAwIBAgIJAKS0yiqVrJgkMA0GCSqGSIb3DQEBCwUA...".to_string(),
    ])
    .x509_thumbprint_sha256("NjVCREY2OTE1QkExMDc1OEU2QkRCMEJCCyxLDjFZAJJCF8")
    .build()?;
```

### JWE with ECDH-ES Key Agreement

```rust
use jose::prelude::*;
use serde_json::json;

let ephemeral_key = json!({
    "kty": "EC",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
});

let header = JweHeaderBuilder::new()
    .algorithm(Algorithm::ECDHESA256KW)
    .encryption_algorithm(EncryptionAlgorithm::A256GCM)
    .ephemeral_public_key(ephemeral_key)
    .agreement_party_u_info("QWxpY2U")  // base64url("Alice")
    .agreement_party_v_info("Qm9i")     // base64url("Bob")
    .build()?;
```

### JWE with PBES2 Password-Based Encryption

```rust
use jose::prelude::*;

let header = JweHeaderBuilder::new()
    .algorithm(Algorithm::PBES2HS256A128KW)
    .encryption_algorithm(EncryptionAlgorithm::A128GCM)
    .pbes2_salt_input("c2FsdA") // base64url("salt")
    .pbes2_count(4096)
    .build()?;
```

### Custom Parameters with Critical Extension

```rust
use jose::prelude::*;
use serde_json::json;

let header = JwsHeaderBuilder::new()
    .algorithm(Algorithm::EdDSA)
    .typ("JWT")
    .key_id("ed25519-key")
    .custom_parameter("exp", json!(1672531200))
    .custom_parameter("custom_claim", json!({"role": "admin"}))
    .critical(vec!["custom_claim".to_string()])
    .build()?;
```

## Validation

The library provides comprehensive validation:

```rust
use jose::prelude::*;

// This will fail - RS256 is not suitable for JWE
let result = JweHeaderBuilder::new()
    .algorithm(Algorithm::RS256)  // Wrong algorithm type
    .encryption_algorithm(EncryptionAlgorithm::A256GCM)
    .build();

assert!(result.is_err());
```

### Validation Features

- ✅ Algorithm compatibility (JWS vs JWE)
- ✅ Required parameters for specific algorithms
- ✅ URL format validation (with `url-validation` feature)
- ✅ Base64url encoding validation
- ✅ X.509 certificate chain validation
- ✅ Critical parameter validation
- ✅ Parameter conflict detection
- ✅ Key ID format validation
- ✅ PBES2 count range validation

## Feature Flags

- `url-validation` - Enable URL format validation using the `url` crate

```toml
[dependencies]
jose = { version = "0.1", features = ["url-validation"] }
```

## Error Handling

The library provides detailed error information:

```rust
use jose::prelude::*;

match JwsHeaderBuilder::new()
    .algorithm(Algorithm::A128KW)  // Invalid for JWS
    .build()
{
    Ok(_) => println!("Success"),
    Err(JoseError::InvalidAlgorithm(msg)) => {
        println!("Algorithm error: {}", msg);
    }
    Err(e) => println!("Other error: {}", e),
}
```

### Error Types

- `InvalidAlgorithm` - Algorithm not suitable for operation
- `InvalidParameter` - Invalid parameter value
- `MissingParameter` - Required parameter missing
- `ConflictingParameters` - Conflicting parameter combination
- `InvalidUrl` - Invalid URL format
- `InvalidBase64` - Invalid base64url encoding
- `InvalidJwk` - Invalid JSON Web Key
- `InvalidCritical` - Invalid critical parameter usage
- `Validation` - General validation error

## Examples

Run the examples to see the library in action:

```bash
cargo run --example basic_usage
```

## Development

### Running Tests

```bash
cargo test
```

### Running Tests with All Features

```bash
cargo test --all-features
```

### Linting

```bash
cargo clippy -- -D warnings
```

### Documentation

```bash
cargo doc --open
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass (`cargo test --all-features`)
6. Run clippy (`cargo clippy -- -D warnings`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## References

- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7516 - JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)