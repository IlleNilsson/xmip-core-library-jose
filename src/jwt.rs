//! The JSON Web Token (RFC 7519), read and not verified: a compact JWS whose
//! payload is a claims set, and the claims RFC 7519 section 4.1 registers.
//!
//! Reading the claims is the first gate's work and checking the signature
//! the second's (ADR-0050): the token keeps its JWS ([`Token::jws`]) so a
//! verifier checks exactly what was read. Which claims a gate requires and
//! how a claim becomes an identity are the gate's. A JWT inside a JWE is
//! not read here.

use serde_json::{Map, Value};

use crate::jws::Jws;
use crate::{Result, members};

/// A token split, decoded and its claims set read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    /// The JWS it is: the header, the signature and what was signed.
    pub jws: Jws,
    /// The claims set's members.
    pub claims: Map<String, Value>,
}

impl Token {
    /// Read a compact token.
    ///
    /// # Errors
    ///
    /// Where the text is not a compact JWS (`Jws::read_compact`), or its
    /// payload is not a JSON object whose member names are unique.
    pub fn read(text: &str) -> Result<Self> {
        let jws = Jws::read_compact(text)?;
        let claims = members::read(&jws.payload, "the JWT claims set")?;
        Ok(Self { jws, claims })
    }

    /// One claim, where it is a string.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name)?.as_str()
    }

    /// One numeric claim — a `NumericDate`, `exp`, `nbf`, `iat` — as whole
    /// seconds; a fraction is dropped.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn numeric_claim(&self, name: &str) -> Option<i64> {
        let value = self.claims.get(name)?;
        value
            .as_i64()
            .or_else(|| value.as_f64().map(|seconds| seconds as i64))
    }

    /// A claim that is a string or an array of strings — `aud`, `scope`,
    /// `roles` — as its strings; nothing where it is absent, or is neither,
    /// or an array holds anything but strings.
    #[must_use]
    pub fn strings_claim(&self, name: &str) -> Vec<&str> {
        match self.claims.get(name) {
            Some(Value::String(one)) => vec![one.as_str()],
            Some(Value::Array(values)) => values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// `iss`: who issued it.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.claim("iss")
    }

    /// `sub`: whom it is about.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.claim("sub")
    }

    /// `aud`: whom it is for, one or many.
    #[must_use]
    pub fn audience(&self) -> Vec<&str> {
        self.strings_claim("aud")
    }

    /// `exp`: the second on and after which it is not accepted.
    #[must_use]
    pub fn expiry(&self) -> Option<i64> {
        self.numeric_claim("exp")
    }

    /// `nbf`: the second before which it is not accepted.
    #[must_use]
    pub fn not_before(&self) -> Option<i64> {
        self.numeric_claim("nbf")
    }

    /// `iat`: the second it was issued.
    #[must_use]
    pub fn issued_at(&self) -> Option<i64> {
        self.numeric_claim("iat")
    }

    /// `jti`: its identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.claim("jti")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::base64::encode_url_unpadded;

    fn token(header: &str, claims: &str) -> String {
        format!(
            "{}.{}.{}",
            encode_url_unpadded(header.as_bytes()),
            encode_url_unpadded(claims.as_bytes()),
            encode_url_unpadded(b"sig")
        )
    }

    #[test]
    fn a_token_is_split_at_its_two_dots_and_its_registered_claims_read() {
        let text = token(
            r#"{"alg":"HS256","kid":"k1"}"#,
            r#"{"iss":"https://issuer.example","sub":"party-x","aud":"xmip",
                "exp":1700000300,"nbf":1700000000,"iat":1699999990,"jti":"t-1"}"#,
        );
        let read = Token::read(&text).expect("three parts");

        assert_eq!(read.jws.algorithm(), Some("HS256"));
        assert_eq!(read.jws.key_id(), Some("k1"));
        assert_eq!(read.jws.signature, b"sig");
        assert!(text.starts_with(&read.jws.signing_input));
        assert_eq!(read.issuer(), Some("https://issuer.example"));
        assert_eq!(read.subject(), Some("party-x"));
        assert_eq!(read.audience(), ["xmip"]);
        assert_eq!(read.expiry(), Some(1_700_000_300));
        assert_eq!(read.not_before(), Some(1_700_000_000));
        assert_eq!(read.issued_at(), Some(1_699_999_990));
        assert_eq!(read.id(), Some("t-1"));
    }

    #[test]
    fn a_token_without_three_parts_or_with_a_bad_part_is_refused_by_name() {
        let failure = Token::read("only.two").expect_err("two parts");
        assert!(failure.message.contains("three parts"), "{failure}");

        let header = encode_url_unpadded(br#"{"alg":"none"}"#);
        let failure = Token::read(&format!("{header}.b!!.aQ")).expect_err("not base64url");
        assert!(failure.message.contains("payload"), "{failure}");
    }

    #[test]
    fn numeric_and_array_claims_are_read_and_nested_members_are_not() {
        let text = token(
            r#"{"alg":"none"}"#,
            r#"{"exp":1700000000,"aud":["a","b"],"scope":"read","nested":{"sub":"no"}}"#,
        );
        let read = Token::read(&text).expect("three parts");

        assert_eq!(read.numeric_claim("exp"), Some(1_700_000_000));
        assert_eq!(read.strings_claim("aud"), ["a", "b"]);
        assert_eq!(read.strings_claim("scope"), ["read"]);
        assert_eq!(read.claim("sub"), None);
    }

    #[test]
    fn an_escaped_string_claim_is_unescaped() {
        let text = token(r#"{"alg":"none"}"#, "{\"sub\":\"a\\\"b\\u0041\"}");
        let read = Token::read(&text).expect("three parts");

        assert_eq!(read.claim("sub"), Some("a\"bA"));
    }

    #[test]
    fn every_json_escape_is_undone_and_a_surrogate_pair_is_one_character() {
        let escaped = "{\"sub\":\"\\b\\f\\n\\r\\t\\/\\\\\\u00e9\\ud83d\\ude00\"}";
        let read = Token::read(&token(r#"{"alg":"none"}"#, escaped)).expect("three parts");

        assert_eq!(
            read.claim("sub"),
            Some("\u{8}\u{c}\n\r\t/\\\u{e9}\u{1f600}")
        );
        let lone = token(r#"{"alg":"none"}"#, "{\"sub\":\"\\ud83d\"}");
        assert!(Token::read(&lone).is_err(), "a lone surrogate");
    }

    #[test]
    fn a_member_name_is_matched_after_its_escapes_are_undone() {
        let text = token("{\"\\u0061lg\":\"none\"}", "{\"s\\u0075b\":\"party-x\"}");
        let read = Token::read(&text).expect("three parts");

        assert_eq!(read.jws.algorithm(), Some("none"));
        assert_eq!(read.subject(), Some("party-x"));
    }

    #[test]
    fn a_claim_named_twice_refuses_the_token_even_behind_an_escape() {
        for claims in [
            "{\"sub\":\"party-x\",\"sub\":\"admin\"}",
            "{\"sub\":\"party-x\",\"\\u0073ub\":\"admin\"}",
        ] {
            let failure = Token::read(&token(r#"{"alg":"none"}"#, claims)).expect_err(claims);
            assert!(failure.message.contains("twice"), "{failure}");
            assert!(failure.message.contains("claims set"), "{failure}");
        }
    }

    #[test]
    fn claims_that_are_not_an_object_or_a_mixed_array_are_not_read() {
        assert!(Token::read(&token(r#"{"alg":"none"}"#, "[1]")).is_err());
        assert!(Token::read(&token(r#"{"alg":"none"}"#, "{\"sub\":")).is_err());
        let text = token(
            r#"{"alg":"none"}"#,
            r#"{"aud":["a",1],"exp":1700000000.9,"sub":7}"#,
        );
        let read = Token::read(&text).expect("three parts");

        assert_eq!(read.audience(), [] as [&str; 0]);
        assert_eq!(read.expiry(), Some(1_700_000_000));
        assert_eq!(read.subject(), None, "a number is not a string");
    }
}
