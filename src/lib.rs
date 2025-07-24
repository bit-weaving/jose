//! # JOSE Header Builder
//!
//! A Rust library for building JSON Web Signature (JWS) and JSON Web Encryption (JWE) headers
//! based on the IANA JOSE registry specifications.
//!
//! This library provides type-safe builders for constructing JOSE headers with proper validation
//! and serialization support.
//!
//! ## Features
//!
//! - Type-safe header construction
//! - Support for all IANA-registered JOSE header parameters
//! - Separate builders for JWS and JWE headers
//! - Validation of header parameter combinations
//! - Serde serialization/deserialization support
//!
//! ## Example
//!
//! ```rust
//! use jose::{JwsHeaderBuilder, Algorithm};
//!
//! let header = JwsHeaderBuilder::new()
//!     .algorithm(Algorithm::RS256)
//!     .key_id("key-1")
//!     .typ("JWT")
//!     .build()
//!     .unwrap();
//!
//! let json = serde_json::to_string(&header).unwrap();
//! ```

pub mod algorithm;
pub mod error;
pub mod header;
pub mod builder;
pub mod validation;

pub use algorithm::Algorithm;
pub use error::{JoseError, Result};
pub use header::{JwsHeader, JweHeader, SharedHeader};
pub use builder::{JwsHeaderBuilder, JweHeaderBuilder};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{
        Algorithm,
        JoseError,
        Result,
        JwsHeader,
        JweHeader,
        JwsHeaderBuilder,
        JweHeaderBuilder,
    };
    pub use crate::algorithm::{EncryptionAlgorithm, CompressionAlgorithm};
}
