//! The keys a node verifies a JWS with (RFC 7517 section 5), and the one
//! rule for choosing one: the key the JWS names, which must serve its
//! algorithm, or, where it names none, every key of the algorithm until one
//! holds.
//!
//! A set is configuration, never fetched (ADR-0045): keys handed over one by
//! one, or a JSON Web Key Set document ([`KeySet::from_jwks`]) as an issuer
//! publishes it. Until 2026-09-24 the two gates that verify a JWS each held
//! a key type of their own and chose a key differently: one tried only the
//! first key of the algorithm where a token named none, the other every one.

use serde_json::Value;

use super::Key;
use crate::jws::Algorithm;
use crate::{JoseError, Result};

/// The keys a node verifies with.
#[derive(Clone, Debug)]
pub struct KeySet {
    keys: Vec<Key>,
}

impl KeySet {
    /// These keys.
    #[must_use]
    pub const fn new(keys: Vec<Key>) -> Self {
        Self { keys }
    }

    /// Read a JSON Web Key Set document: RSA keys (`kty` `RSA`, `n` and `e`)
    /// for RS256 and P-256 keys (`kty` `EC`, `crv` `P-256`, `x` and `y`) for
    /// ES256 (`Key::read`). A key marked `"use":"enc"` is not a signing key
    /// and is passed over, as is a key of any other kind.
    ///
    /// # Errors
    ///
    /// Where the text is not JSON with a `keys` array, a key of a kind read
    /// here is malformed, or no key in the set is one that can be used, so a
    /// useless set is refused when it is loaded, not at the first token.
    pub fn from_jwks(document: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(document)
            .map_err(|failure| JoseError::new(format!("the JWKS is not JSON: {failure}")))?;
        let listed = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| JoseError::new("the JWKS has no `keys` array"))?;

        let mut keys = Vec::new();
        for entry in listed {
            if entry.get("use").and_then(Value::as_str) == Some("enc") {
                continue;
            }
            if let Some(key) = Key::read(entry)? {
                keys.push(key);
            }
        }

        if keys.is_empty() {
            return Err(JoseError::new("the JWKS holds no RSA or P-256 signing key"));
        }
        Ok(Self { keys })
    }

    /// How many keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check `signature` over `input`: with the key the JWS names, which
    /// must serve `algorithm`, or, where it names none, with every key of
    /// the algorithm until one holds.
    ///
    /// # Errors
    ///
    /// Where the set holds no such key, the named key serves another
    /// algorithm, or the signature does not verify.
    pub fn verify(
        &self,
        algorithm: Algorithm,
        key_id: Option<&str>,
        input: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let candidates: Vec<&Key> = match key_id {
            Some(id) => {
                let key = self
                    .keys
                    .iter()
                    .find(|key| key.id() == Some(id))
                    .ok_or_else(|| {
                        JoseError::new(format!(
                            "the node holds no key '{id}': its issuer may have rotated its keys"
                        ))
                    })?;
                if key.algorithm() != algorithm {
                    return Err(JoseError::new(format!(
                        "the key '{id}' serves {} and the token is signed {}",
                        key.algorithm().name(),
                        algorithm.name()
                    )));
                }
                vec![key]
            }
            None => self
                .keys
                .iter()
                .filter(|key| key.algorithm() == algorithm)
                .collect(),
        };
        if candidates.is_empty() {
            return Err(JoseError::new(format!(
                "the node holds no {} key and the token names none",
                algorithm.name()
            )));
        }

        if candidates.iter().any(|key| key.verifies(input, signature)) {
            Ok(())
        } else {
            Err(JoseError::new(format!(
                "the {} signature does not verify with the keys the node holds",
                algorithm.name()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::tests::{published, signed, signing_key};

    fn set(entries: &[String]) -> KeySet {
        KeySet::from_jwks(&format!(r#"{{"keys":[{}]}}"#, entries.join(","))).expect("set")
    }

    #[test]
    fn a_published_p256_key_verifies_what_its_private_half_signed() {
        let key = signing_key();
        let set = set(&[published("e1", &key)]);
        let signature = signed(&key, b"input");

        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        assert!(
            set.verify(Algorithm::Es256, Some("e1"), b"input", &signature)
                .is_ok()
        );
        assert!(
            set.verify(Algorithm::Es256, None, b"input", &signature)
                .is_ok()
        );
        let failure = set
            .verify(Algorithm::Es256, Some("e1"), b"other", &signature)
            .expect_err("refused");
        assert!(failure.message.contains("does not verify"), "{failure}");
    }

    #[test]
    fn with_no_kid_every_key_of_the_algorithm_is_tried_not_the_first() {
        let first = signing_key();
        let second = signing_key();
        let set = set(&[published("a", &first), published("b", &second)]);

        assert!(
            set.verify(Algorithm::Es256, None, b"input", &signed(&second, b"input"))
                .is_ok()
        );
    }

    #[test]
    fn a_missing_or_mismatched_key_is_refused_by_name() {
        let set = set(&[published("e1", &signing_key())]);

        let missing = set
            .verify(Algorithm::Es256, Some("e2"), b"input", b"sig")
            .expect_err("refused");
        let mismatched = set
            .verify(Algorithm::Rs256, Some("e1"), b"input", b"sig")
            .expect_err("refused");
        let none = set
            .verify(Algorithm::Hs256, None, b"input", b"sig")
            .expect_err("refused");

        assert!(missing.message.contains("no key 'e2'"), "{missing}");
        assert!(missing.message.contains("rotated"), "{missing}");
        assert!(mismatched.message.contains("serves ES256"), "{mismatched}");
        assert!(none.message.contains("no HS256 key"), "{none}");
    }

    #[test]
    fn a_secret_handed_over_verifies_hs256_by_its_kid() {
        let set = KeySet::new(vec![Key::secret(Some("k1"), b"hidden")]);
        let signature = codec::digest::hmac_sha256(b"hidden", b"input");

        assert!(
            set.verify(Algorithm::Hs256, Some("k1"), b"input", &signature)
                .is_ok()
        );
    }

    #[test]
    fn a_set_with_nothing_usable_or_no_keys_array_does_not_load() {
        let unusable = r#"{"keys":[{"kty":"oct","k":"AA"},{"kty":"RSA","use":"enc"}]}"#;
        let failure = KeySet::from_jwks(unusable).expect_err("refused");
        assert!(
            failure.message.contains("no RSA or P-256 signing key"),
            "{failure}"
        );

        let failure = KeySet::from_jwks(r#"{"issuer":"x"}"#).expect_err("refused");
        assert!(failure.message.contains("`keys`"), "{failure}");

        let short = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}]}"#;
        let failure = KeySet::from_jwks(short).expect_err("refused");
        assert!(failure.message.contains("thirty-two"), "{failure}");
    }
}
