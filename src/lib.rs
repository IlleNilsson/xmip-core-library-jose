#![forbid(unsafe_code)]

//! JOSE for Xmip, one copy: the JSON Web Signature (RFC 7515), the JSON Web
//! Token (RFC 7519) and the JSON Web Key (RFC 7517), read, written and
//! verified.
//!
//! ```text
//! base64url  a part, unpadded, read strictly                   RFC 7515 section 2
//! jws        Algorithm; Jws read compact or flattened;          RFC 7515, RFC 7518
//!            a flattened JWS signed by a SigningKey
//! jwt        Token: a compact JWS whose payload is a claims    RFC 7519
//!            set, and its registered claims
//! jwk        Key and KeySet: HS256, RS256 and ES256 keys,       RFC 7517, RFC 7638
//!            read from a JWK, written, thumbprinted, and the
//!            one rule for choosing a key (feature `key`)
//! ```
//!
//! Until 2026-11-16 four copies did this work: the identify capability read
//! a compact JWT, the authenticate capability held the keys a JWS is
//! verified with, and ACME wrote a JWK of its own and a flattened JWS of its
//! own, checked by provisioning's own ES256. What a gate makes of a token —
//! which claims it requires, how a claim becomes an identity, which
//! algorithms it takes — stays with its capability; this crate is the
//! format.
//!
//! **Strict where the copies were not.** A part is base64url without
//! padding, as RFC 7515 section 2 writes it; a header, a claims set and a
//! flattened JWS are JSON objects whose member names are each named once,
//! so a reader and a verifier never trust two different values of one
//! member; and a P-256 key's point is on the curve, whoever handed it over.
//!
//! A capability turns a [`JoseError`] into its own error with `From`, so a
//! technology writes `?` and the reason travels unchanged.

pub mod base64url;
#[cfg(feature = "key")]
pub mod jwk;
pub mod jws;
pub mod jwt;
mod members;

/// Why a JOSE object or key is not what it was read as, in words.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoseError {
    /// What was wrong, in words.
    pub message: String,
}

impl JoseError {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for JoseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for JoseError {}

/// The result of reading, writing or verifying JOSE.
pub type Result<T> = core::result::Result<T, JoseError>;
