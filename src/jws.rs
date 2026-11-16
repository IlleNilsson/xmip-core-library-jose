//! The JSON Web Signature (RFC 7515): a protected header, a payload and a
//! signature over the two, read from the compact serialization a JWT
//! travels in (section 7.1) or the flattened JSON serialization an ACME
//! request is (section 7.2.2), and written flattened by a key that signs;
//! and the three algorithms named here.
//!
//! RFC 7518 section 3.1 makes HS256 required and RS256 and ES256
//! recommended, and those three are what is named. Whether a signature
//! holds is a key's (`jwk`, feature `key`); which algorithms a gate takes is
//! the gate's. A flattened JWS is read with all three of `protected`,
//! `payload` and `signature`: until 2026-11-16 ACME's reader took a missing
//! one as empty.

use codec::base64::encode_url_unpadded;
use serde_json::{Map, Value, json};

use crate::{JoseError, Result, base64url, members};

/// One of the three signature algorithms named here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// HMAC over SHA-256 with a shared secret.
    Hs256,
    /// RSASSA-PKCS1-v1_5 over SHA-256.
    Rs256,
    /// ECDSA on P-256 over SHA-256, `r` and `s` thirty-two bytes each.
    Es256,
}

impl Algorithm {
    /// The algorithm an `alg` header names, where it is one of the three.
    /// Compared exactly: `hs256` and `none` are not.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "HS256" => Some(Self::Hs256),
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// The `alg` name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

/// A JWS read, before its signature is checked: what a verifier needs to
/// find the key and check it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Jws {
    /// The protected header's members.
    pub header: Map<String, Value>,
    /// The payload, as bytes; empty where it is.
    pub payload: Vec<u8>,
    /// The signature, as bytes. Checked by a key or not at all.
    pub signature: Vec<u8>,
    /// What was signed: the protected header and the payload, base64url,
    /// around a dot, exactly as they arrived.
    pub signing_input: String,
}

impl Jws {
    /// Split and decode a compact JWS: three base64url parts around two
    /// dots, the whitespace around them trimmed.
    ///
    /// # Errors
    ///
    /// Where the text is not three parts around two dots, a part is not
    /// unpadded base64url, or the header is not a JSON object whose member
    /// names are unique.
    pub fn read_compact(text: &str) -> Result<Self> {
        let mut parts = text.trim().split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JoseError::new(
                "a compact JWS has exactly three parts around two dots",
            ));
        };
        Self::parts(header, payload, signature)
    }

    /// Read a JWS in the flattened JSON serialization: an object whose
    /// `protected`, `payload` and `signature` members are each base64url.
    ///
    /// # Errors
    ///
    /// Where the body is not a JSON object whose member names are unique,
    /// one of the three members is missing or not a string, a part is not
    /// unpadded base64url, or the header is not a JSON object whose member
    /// names are unique.
    pub fn read_flattened(body: &[u8]) -> Result<Self> {
        let outer = members::read(body, "the JWS")?;
        let part = |name: &str| {
            outer
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| JoseError::new(format!("the JWS has no `{name}` member")))
        };
        Self::parts(part("protected")?, part("payload")?, part("signature")?)
    }

    fn parts(header: &str, payload: &str, signature: &str) -> Result<Self> {
        let protected = base64url::decode(header, "the JWS header")?;
        Ok(Self {
            header: members::read(&protected, "the JWS header")?,
            payload: base64url::decode(payload, "the JWS payload")?,
            signature: base64url::decode(signature, "the JWS signature")?,
            signing_input: format!("{header}.{payload}"),
        })
    }

    /// A header member, where it is a string.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        self.header.get(name)?.as_str()
    }

    /// The `alg` the header names.
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        self.text("alg")
    }

    /// The `kid` the header names, where it names one.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.text("kid")
    }
}

/// Three parts around two dots and no whitespace: the shape RFC 7515 gives a
/// compact serialization, and the test that tells a JWT from an opaque token.
#[must_use]
pub fn is_compact(text: &str) -> bool {
    text.split('.').count() == 3 && !text.contains(char::is_whitespace) && !text.is_empty()
}

/// A key that signs: its holder keeps the private half, and this crate
/// writes what it signs. Provisioning's P-256 key pair is one, as an ACME
/// account signs.
pub trait SigningKey {
    /// The algorithm its signatures are, which the header names.
    fn algorithm(&self) -> Algorithm;

    /// Its signature over `input`, as the algorithm writes one (ES256: `r`
    /// and `s`, thirty-two bytes each).
    ///
    /// # Errors
    ///
    /// Where signing fails.
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>>;
}

/// `payload` signed by `key` in the flattened JSON serialization, the
/// protected header `header`'s members with `alg` the key's: the body, as
/// bytes.
///
/// # Errors
///
/// Where the key does not sign.
pub fn sign_flattened(
    mut header: Map<String, Value>,
    payload: &[u8],
    key: &(impl SigningKey + ?Sized),
) -> Result<Vec<u8>> {
    header.insert(
        "alg".to_string(),
        Value::String(key.algorithm().name().to_string()),
    );
    let protected = encode_url_unpadded(Value::Object(header).to_string().as_bytes());
    let payload = encode_url_unpadded(payload);
    let signature = key.sign(format!("{protected}.{payload}").as_bytes())?;
    let body = json!({
        "protected": protected,
        "payload": payload,
        "signature": encode_url_unpadded(&signature),
    });
    Ok(body.to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shared secret signing HS256, as a test's key.
    struct Shared;

    impl SigningKey for Shared {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Hs256
        }

        fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
            Ok(codec::digest::hmac_sha256(b"shared", input).to_vec())
        }
    }

    fn compact(header: &str, payload: &str) -> String {
        format!(
            "{}.{}.{}",
            encode_url_unpadded(header.as_bytes()),
            encode_url_unpadded(payload.as_bytes()),
            encode_url_unpadded(b"sig")
        )
    }

    #[test]
    fn an_algorithm_is_named_by_its_header_value_and_nothing_else() {
        assert_eq!(Algorithm::named("HS256"), Some(Algorithm::Hs256));
        assert_eq!(
            Algorithm::named("ES256").map(Algorithm::name),
            Some("ES256")
        );
        assert_eq!(Algorithm::named("none"), None);
        assert_eq!(Algorithm::named("hs256"), None);
    }

    #[test]
    fn a_compact_jws_is_split_at_its_two_dots_and_decoded() {
        let text = compact(r#"{"alg":"HS256","kid":"k1"}"#, "payload");
        let jws = Jws::read_compact(&format!(" {text} ")).expect("three parts");

        assert_eq!(jws.algorithm(), Some("HS256"));
        assert_eq!(jws.key_id(), Some("k1"));
        assert_eq!(jws.payload, b"payload");
        assert_eq!(jws.signature, b"sig");
        assert!(text.starts_with(&jws.signing_input));
    }

    #[test]
    fn a_compact_jws_without_three_good_parts_is_refused_by_name() {
        let two = Jws::read_compact("only.two").expect_err("two parts");
        assert!(two.message.contains("three parts"), "{two}");

        let header = encode_url_unpadded(br#"{"alg":"none"}"#);
        let payload = Jws::read_compact(&format!("{header}.b!!.aQ")).expect_err("payload");
        assert!(payload.message.contains("payload"), "{payload}");

        let twice = compact(r#"{"alg":"none","alg":"HS256"}"#, "x");
        let failure = Jws::read_compact(&twice).expect_err("a header named twice");
        assert!(failure.message.contains("header"), "{failure}");
        assert!(failure.message.contains("twice"), "{failure}");
    }

    #[test]
    fn what_one_side_signs_flattened_the_other_reads_with_the_keys_algorithm() {
        let mut header = Map::new();
        header.insert("nonce".to_string(), Value::String("n1".to_string()));
        header.insert("alg".to_string(), Value::String("none".to_string()));
        let body = sign_flattened(header, b"{\"a\":1}", &Shared).expect("signed");
        let jws = Jws::read_flattened(&body).expect("read");

        assert_eq!(
            jws.algorithm(),
            Some("HS256"),
            "the key's, not the header's"
        );
        assert_eq!(jws.text("nonce"), Some("n1"));
        assert_eq!(jws.payload, b"{\"a\":1}");
        let expected = codec::digest::hmac_sha256(b"shared", jws.signing_input.as_bytes());
        assert_eq!(jws.signature, expected);

        let empty = sign_flattened(Map::new(), b"", &Shared).expect("signed");
        assert_eq!(Jws::read_flattened(&empty).expect("read").payload, b"");
    }

    #[test]
    fn a_flattened_jws_missing_a_member_padded_or_named_twice_is_refused() {
        let missing = br#"{"protected":"e30","signature":"aQ"}"#;
        let failure = Jws::read_flattened(missing).expect_err("no payload");
        assert_eq!(failure.message, "the JWS has no `payload` member");

        let padded = br#"{"protected":"e30","payload":"aGk=","signature":"aQ"}"#;
        let failure = Jws::read_flattened(padded).expect_err("padded");
        assert!(failure.message.contains("payload is padded"), "{failure}");

        let twice = br#"{"protected":"e30","payload":"","payload":"aGk","signature":"aQ"}"#;
        let failure = Jws::read_flattened(twice).expect_err("named twice");
        assert!(failure.message.contains("twice"), "{failure}");
    }

    #[test]
    fn a_compact_shape_is_three_parts_and_no_whitespace() {
        assert!(is_compact("a.b.c"));
        assert!(!is_compact("a.b"));
        assert!(!is_compact("a.b .c"));
        assert!(!is_compact("opaque"));
        assert!(!is_compact(""));
    }
}
