//! Base64url as JOSE writes it (RFC 7515 section 2): the URL-safe alphabet
//! of RFC 4648 section 5 with every trailing `=` omitted, and nothing else
//! in the text.
//!
//! A part is read by the estate's one decoder, `codec::base64`, as strictly
//! as it reads base64url, and padding is refused. Until 2026-11-16 the
//! identify capability dropped any number of `=` from a token's part and
//! ACME took a padded one; RFC 7515 omits the padding, so neither is a JOSE
//! part. A part is written by `codec::base64::encode_url_unpadded`.

use crate::{JoseError, Result};

/// The bytes a JOSE part spells; `what` names the part in a refusal.
///
/// # Errors
///
/// Where the text is padded or is not base64url.
pub fn decode(text: &str, what: &str) -> Result<Vec<u8>> {
    if text.contains('=') {
        return Err(JoseError::new(format!(
            "{what} is padded, and JOSE writes base64url without padding"
        )));
    }
    codec::base64::decode_url(text).map_err(|_| JoseError::new(format!("{what} is not base64url")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_is_read_unpadded_and_padding_or_a_stranger_is_refused_by_name() {
        assert_eq!(decode("aGk", "the part").expect("unpadded"), b"hi");
        assert_eq!(decode("", "the part").expect("empty"), b"");

        let padded = decode("aGk=", "the JWS header").expect_err("padded");
        assert!(
            padded.message.starts_with("the JWS header is padded"),
            "{padded}"
        );
        let lax = decode("aGk====", "the JWS header").expect_err("padded");
        assert!(lax.message.contains("padded"), "{lax}");
        let standard = decode("a+k/", "the signature").expect_err("not base64url");
        assert_eq!(standard.message, "the signature is not base64url");
    }
}
