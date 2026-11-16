//! The keys a JWS is verified with (RFC 7517, RFC 7518): a shared secret for
//! HS256, an RSA public key for RS256 and a P-256 public key for ES256, each
//! serving its one algorithm and answering to the `kid` a token names it by;
//! a key read from the JWK an issuer publishes or an ACME request carries, a
//! P-256 key written as one with its thumbprint (RFC 7638); and the set a
//! node verifies with ([`KeySet`]).
//!
//! HS256 is the estate's HMAC (`codec::digest`), its check in constant time.
//! RS256 and ES256 are aws-lc-rs's, the crypto `xmip-core-library-tls`
//! already builds, and a P-256 key's PEM is read by the estate's one
//! certificate reader (`tls::certificate::point_of`). An RS256 key has 2048
//! bits or more, as RFC 7518 section 3.3 requires: a smaller one verifies
//! nothing. Until 2026-11-16 the authenticate capability verified over the
//! `rsa` and `p256` crates and provisioning verified ACME's ES256 over
//! aws-lc-rs, and a P-256 point an ACME request carried was taken without
//! asking whether it lay on the curve; every point is on it now.

mod key_set;

pub use key_set::KeySet;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
};
use codec::base64::encode_url_unpadded;
use codec::digest::{HmacSha256, sha256};
use serde_json::{Map, Value};
use std::fmt;

use crate::jws::Algorithm;
use crate::{JoseError, Result, base64url};

/// The PEM label a public key's `SubjectPublicKeyInfo` is written under.
const PUBLIC_KEY: &str = "PUBLIC KEY";

/// What a key is made of.
#[derive(Clone)]
enum Material {
    Secret(Vec<u8>),
    Rsa(ParsedPublicKey),
    /// The uncompressed point, and the key aws-lc-rs parsed it into.
    P256 {
        point: Vec<u8>,
        parsed: ParsedPublicKey,
    },
}

/// A key the node holds, serving one algorithm.
#[derive(Clone)]
pub struct Key {
    id: Option<String>,
    material: Material,
}

// The material is a secret or a public key of many bytes; neither belongs in
// a log line. The id and the algorithm say which key this is.
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm().name())
            .finish()
    }
}

/// The same id and the same key: a secret compared in constant time, a
/// public key by its `SubjectPublicKeyInfo` or its point.
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && match (&self.material, &other.material) {
                (Material::Secret(one), Material::Secret(two)) => {
                    codec::constant_time::equal(one, two)
                }
                (Material::Rsa(one), Material::Rsa(two)) => one.as_ref() == two.as_ref(),
                (Material::P256 { point: one, .. }, Material::P256 { point: two, .. }) => {
                    one == two
                }
                _ => false,
            }
    }
}

impl Eq for Key {}

impl Key {
    /// A shared secret, for HS256.
    #[must_use]
    pub fn secret(id: Option<&str>, secret: impl AsRef<[u8]>) -> Self {
        Self::of(id, Material::Secret(secret.as_ref().to_vec()))
    }

    /// An RSA public key from its SPKI PEM (`-----BEGIN PUBLIC KEY-----`),
    /// for RS256.
    ///
    /// # Errors
    ///
    /// Where the text is not an RSA public key in PEM.
    pub fn rsa_pem(id: Option<&str>, pem: &str) -> Result<Self> {
        let refused = || JoseError::new("the RSA key is not a public key in PEM");
        let info = public_key_info(pem).ok_or_else(refused)?;
        let parsed =
            ParsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, info).map_err(|_| refused())?;
        Ok(Self::of(id, Material::Rsa(parsed)))
    }

    /// An RSA public key from its big-endian modulus and exponent, as a JWK
    /// carries them, for RS256.
    ///
    /// # Errors
    ///
    /// Where the pair is not a usable RSA key.
    pub fn rsa_components(id: Option<&str>, modulus: &[u8], exponent: &[u8]) -> Result<Self> {
        let parsed = RsaPublicKeyComponents {
            n: modulus,
            e: exponent,
        }
        .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
        .map_err(|_| JoseError::new("the RSA modulus and exponent are not a key"))?;
        Ok(Self::of(id, Material::Rsa(parsed)))
    }

    /// A P-256 public key from its SPKI PEM, for ES256.
    ///
    /// # Errors
    ///
    /// Where the text is not a P-256 public key in PEM, its point
    /// uncompressed.
    pub fn p256_pem(id: Option<&str>, pem: &str) -> Result<Self> {
        let refused = || JoseError::new("the P-256 key is not a public key in PEM");
        let info = public_key_info(pem).ok_or_else(refused)?;
        let point = tls::certificate::point_of(&info).map_err(|_| refused())?;
        Self::p256_point(id, &point)
    }

    /// A P-256 public key from its affine coordinates, as a JWK carries
    /// them, for ES256.
    ///
    /// # Errors
    ///
    /// Where the coordinates are not thirty-two bytes each or not a point on
    /// the curve.
    pub fn p256_coordinates(id: Option<&str>, x: &[u8], y: &[u8]) -> Result<Self> {
        if x.len() != 32 || y.len() != 32 {
            return Err(JoseError::new("a P-256 coordinate is thirty-two bytes"));
        }
        Self::p256_point(id, &[&[4][..], x, y].concat())
    }

    /// A P-256 public key from its uncompressed point — `0x04`, then `x`
    /// and `y` — as a key pair gives it, for ES256.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an uncompressed point, or the point is not on
    /// the curve.
    pub fn p256_point(id: Option<&str>, point: &[u8]) -> Result<Self> {
        if point.len() != 65 || point.first() != Some(&4) {
            return Err(JoseError::new("the key is not an uncompressed P-256 point"));
        }
        let parsed = ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .map_err(|_| JoseError::new("the P-256 point is not on the curve"))?;
        Ok(Self::of(
            id,
            Material::P256 {
                point: point.to_vec(),
                parsed,
            },
        ))
    }

    /// The key a JWK object describes, under the `kid` it names: RSA (`n`
    /// and `e`) for RS256, EC on P-256 (`x` and `y`) for ES256. Nothing
    /// where it is another kind — a secret, another curve — which a set
    /// passes over and a caller expecting one kind refuses.
    ///
    /// # Errors
    ///
    /// Where a key of a kind read here lacks a member, a member is not
    /// unpadded base64url, or the key is not usable.
    pub fn read(jwk: &Value) -> Result<Option<Self>> {
        let text = |name: &str| jwk.get(name).and_then(Value::as_str);
        let id = text("kid");
        match (text("kty"), text("crv")) {
            (Some("RSA"), _) => {
                Self::rsa_components(id, &member(jwk, "n")?, &member(jwk, "e")?).map(Some)
            }
            (Some("EC"), Some("P-256")) => {
                Self::p256_coordinates(id, &member(jwk, "x")?, &member(jwk, "y")?).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn of(id: Option<&str>, material: Material) -> Self {
        Self {
            id: id.map(str::to_string),
            material,
        }
    }

    /// The `kid` this key answers to, where it has one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The one algorithm this key serves.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self.material {
            Material::Secret(_) => Algorithm::Hs256,
            Material::Rsa(_) => Algorithm::Rs256,
            Material::P256 { .. } => Algorithm::Es256,
        }
    }

    /// Whether `signature` is this key's over `input`, by its algorithm.
    #[must_use]
    pub fn verifies(&self, input: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            Material::Secret(secret) => {
                let mut mac = HmacSha256::new(secret);
                mac.update(input);
                mac.verify(signature)
            }
            Material::Rsa(parsed) | Material::P256 { parsed, .. } => {
                parsed.verify_sig(input, signature).is_ok()
            }
        }
    }

    /// The uncompressed point, where this is a P-256 key.
    #[must_use]
    pub fn point(&self) -> Option<&[u8]> {
        match &self.material {
            Material::P256 { point, .. } => Some(point),
            _ => None,
        }
    }

    /// The key as a JWK, where it is a P-256 key: `crv`, `kty`, `x`, `y`,
    /// and its `kid` where it has one. An RSA key and a secret are read
    /// here and not written.
    #[must_use]
    pub fn json(&self) -> Option<Value> {
        let (x, y) = self.coordinates()?;
        let mut jwk = Map::new();
        jwk.insert("crv".to_string(), Value::from("P-256"));
        jwk.insert("kty".to_string(), Value::from("EC"));
        jwk.insert("x".to_string(), Value::from(encode_url_unpadded(x)));
        jwk.insert("y".to_string(), Value::from(encode_url_unpadded(y)));
        if let Some(id) = &self.id {
            jwk.insert("kid".to_string(), Value::from(id.as_str()));
        }
        Some(Value::Object(jwk))
    }

    /// The thumbprint, where this is a P-256 key: SHA-256 over the required
    /// members in lexical order with no white space, base64url (RFC 7638
    /// section 3).
    #[must_use]
    pub fn thumbprint(&self) -> Option<String> {
        let (x, y) = self.coordinates()?;
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            encode_url_unpadded(x),
            encode_url_unpadded(y)
        );
        Some(encode_url_unpadded(&sha256(canonical.as_bytes())))
    }

    fn coordinates(&self) -> Option<(&[u8], &[u8])> {
        self.point().map(|point| (&point[1..33], &point[33..]))
    }
}

/// The `SubjectPublicKeyInfo` the first `PUBLIC KEY` block of `pem` holds.
fn public_key_info(pem: &str) -> Option<Vec<u8>> {
    codec::pem::decode(PUBLIC_KEY, pem).ok()?.into_iter().next()
}

/// One base64url member of a JWK.
fn member(jwk: &Value, name: &str) -> Result<Vec<u8>> {
    let text = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| JoseError::new(format!("a JWK has no `{name}`")))?;
    base64url::decode(text, &format!("a JWK's `{name}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

    /// A P-256 key drawn from the operating system's random source.
    pub(super) fn signing_key() -> EcdsaKeyPair {
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("a key")
    }

    /// `key`'s ES256 signature over `input`.
    pub(super) fn signed(key: &EcdsaKeyPair, input: &[u8]) -> Vec<u8> {
        key.sign(&SystemRandom::new(), input)
            .expect("signed")
            .as_ref()
            .to_vec()
    }

    /// `key`'s public half as a JWK, as an issuer would publish it.
    pub(super) fn published(id: &str, key: &EcdsaKeyPair) -> String {
        let point = key.public_key().as_ref();
        format!(
            r#"{{"kty":"EC","crv":"P-256","use":"sig","kid":"{id}","x":"{}","y":"{}"}}"#,
            encode_url_unpadded(&point[1..33]),
            encode_url_unpadded(&point[33..])
        )
    }

    #[test]
    fn a_p256_key_reads_back_from_its_json_with_the_same_thumbprint() {
        let pair = signing_key();
        let key = Key::p256_point(None, pair.public_key().as_ref()).expect("a point");
        let json = key.json().expect("a P-256 key is written");
        let again = Key::read(&json).expect("read").expect("a P-256 key");

        assert_eq!(again, key);
        assert_eq!(again.point(), Some(pair.public_key().as_ref()));
        assert_eq!(key.thumbprint().map(|print| print.len()), Some(43));
        assert_eq!(again.thumbprint(), key.thumbprint());
        assert!(key.verifies(b"input", &signed(&pair, b"input")));
        assert!(!key.verifies(b"other", &signed(&pair, b"input")));
    }

    #[test]
    fn a_published_key_keeps_its_kid_and_another_kind_is_not_read() {
        let pair = signing_key();
        let jwk: Value = serde_json::from_str(&published("e1", &pair)).expect("json");
        let key = Key::read(&jwk).expect("read").expect("a P-256 key");

        assert_eq!(key.id(), Some("e1"));
        assert_eq!(key.algorithm(), Algorithm::Es256);
        let written = key.json().expect("written");
        assert_eq!(written.get("kid").and_then(Value::as_str), Some("e1"));
        let secret: Value = serde_json::from_str(r#"{"kty":"oct","k":"AA"}"#).expect("json");
        assert!(Key::read(&secret).expect("passed over").is_none());
        let other: Value = serde_json::from_str(r#"{"kty":"EC","crv":"P-384"}"#).expect("json");
        assert!(Key::read(&other).expect("passed over").is_none());
    }

    #[test]
    fn a_point_that_is_short_compressed_or_off_the_curve_is_refused() {
        let short = Key::p256_coordinates(None, &[1; 31], &[2; 32]).expect_err("refused");
        assert!(short.message.contains("thirty-two"), "{short}");
        let compressed = Key::p256_point(None, &[2; 33]).expect_err("refused");
        assert!(compressed.message.contains("uncompressed"), "{compressed}");
        let off = Key::p256_coordinates(None, &[1; 32], &[2; 32]).expect_err("refused");
        assert!(off.message.contains("not on the curve"), "{off}");
        let jwk: Value =
            serde_json::from_str(r#"{"kty":"EC","crv":"P-256","x":"AQ=="}"#).expect("json");
        let padded = Key::read(&jwk).expect_err("refused");
        assert!(padded.message.contains("padded"), "{padded}");
    }

    #[test]
    fn a_p256_key_in_pem_verifies_and_an_rsa_pem_is_not_one() {
        let pair = signing_key();
        let info = pair.public_key().as_der().expect("der");
        let pem = codec::pem::encode(PUBLIC_KEY, info.as_ref());
        let key = Key::p256_pem(Some("e1"), &pem).expect("a key");

        assert_eq!(key.point(), Some(pair.public_key().as_ref()));
        assert!(key.verifies(b"input", &signed(&pair, b"input")));
        assert!(Key::rsa_pem(None, &pem).is_err());
        assert!(Key::p256_pem(None, "no key").is_err());
    }

    #[test]
    fn an_rsa_key_from_pem_or_its_components_verifies_rs256() {
        let pair =
            aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("a key");
        let mut signature = vec![0; pair.public_modulus_len()];
        pair.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            b"input",
            &mut signature,
        )
        .expect("signed");
        let info = pair.public_key().as_der().expect("der");
        let pem = codec::pem::encode(PUBLIC_KEY, info.as_ref());
        let parts = aws_lc_rs::rsa::PublicKeyComponents::<Vec<u8>>::from(pair.public_key());

        for key in [
            Key::rsa_pem(None, &pem).expect("from PEM"),
            Key::rsa_components(Some("r1"), &parts.n, &parts.e).expect("from n and e"),
        ] {
            assert_eq!(key.algorithm(), Algorithm::Rs256);
            assert!(key.verifies(b"input", &signature));
            assert!(!key.verifies(b"other", &signature));
            assert!(key.json().is_none() && key.thumbprint().is_none());
        }
        assert!(Key::p256_pem(None, &pem).is_err());
    }

    #[test]
    fn a_secret_serves_hs256_and_prints_its_id_and_never_its_bytes() {
        let key = Key::secret(Some("k1"), b"hidden");
        let signature = codec::digest::hmac_sha256(b"hidden", b"input");

        assert_eq!(key.algorithm(), Algorithm::Hs256);
        assert!(key.verifies(b"input", &signature));
        assert!(!key.verifies(b"input", &signature[..31]));
        assert_eq!(key, Key::secret(Some("k1"), b"hidden"));
        assert_ne!(key, Key::secret(Some("k1"), b"other"));
        let printed = format!("{key:?}");
        assert!(printed.contains("k1") && !printed.contains("hidden"));
        assert!(key.json().is_none(), "a secret is never written");
    }
}
