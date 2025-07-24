//! Error types for JOSE operations

use std::fmt;

/// Result type alias for JOSE operations
pub type Result<T> = std::result::Result<T, JoseError>;

/// Errors that can occur during JOSE header operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoseError {
    /// Invalid algorithm specified
    InvalidAlgorithm(String),

    /// Invalid header parameter value
    InvalidParameter {
        parameter: String,
        reason: String,
    },

    /// Missing required parameter
    MissingParameter(String),

    /// Conflicting parameters
    ConflictingParameters {
        param1: String,
        param2: String,
        reason: String,
    },

    /// Invalid URL format
    InvalidUrl {
        parameter: String,
        url: String,
        reason: String,
    },

    /// Invalid base64 encoding
    InvalidBase64 {
        parameter: String,
        reason: String,
    },

    /// Invalid JSON Web Key format
    InvalidJwk(String),

    /// Invalid critical parameter usage
    InvalidCritical(String),

    /// Serialization error
    Serialization(String),

    /// Deserialization error
    Deserialization(String),

    /// Generic validation error
    Validation(String),
}

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoseError::InvalidAlgorithm(alg) => {
                write!(f, "Invalid algorithm: {}", alg)
            }
            JoseError::InvalidParameter { parameter, reason } => {
                write!(f, "Invalid parameter '{}': {}", parameter, reason)
            }
            JoseError::MissingParameter(param) => {
                write!(f, "Missing required parameter: {}", param)
            }
            JoseError::ConflictingParameters { param1, param2, reason } => {
                write!(f, "Conflicting parameters '{}' and '{}': {}", param1, param2, reason)
            }
            JoseError::InvalidUrl { parameter, url, reason } => {
                write!(f, "Invalid URL in parameter '{}' ({}): {}", parameter, url, reason)
            }
            JoseError::InvalidBase64 { parameter, reason } => {
                write!(f, "Invalid base64 in parameter '{}': {}", parameter, reason)
            }
            JoseError::InvalidJwk(reason) => {
                write!(f, "Invalid JSON Web Key: {}", reason)
            }
            JoseError::InvalidCritical(reason) => {
                write!(f, "Invalid critical parameter usage: {}", reason)
            }
            JoseError::Serialization(reason) => {
                write!(f, "Serialization error: {}", reason)
            }
            JoseError::Deserialization(reason) => {
                write!(f, "Deserialization error: {}", reason)
            }
            JoseError::Validation(reason) => {
                write!(f, "Validation error: {}", reason)
            }
        }
    }
}

impl std::error::Error for JoseError {}

impl From<serde_json::Error> for JoseError {
    fn from(err: serde_json::Error) -> Self {
        JoseError::Serialization(err.to_string())
    }
}

impl From<base64::DecodeError> for JoseError {
    fn from(err: base64::DecodeError) -> Self {
        JoseError::InvalidBase64 {
            parameter: "unknown".to_string(),
            reason: err.to_string(),
        }
    }
}

#[cfg(feature = "url-validation")]
impl From<url::ParseError> for JoseError {
    fn from(err: url::ParseError) -> Self {
        JoseError::InvalidUrl {
            parameter: "unknown".to_string(),
            url: "unknown".to_string(),
            reason: err.to_string(),
        }
    }
}
