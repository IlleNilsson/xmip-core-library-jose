//! A JOSE JSON object, read by `serde_json` and refused where a member name
//! appears twice — once its escapes are undone, so a name spelled with an
//! escape is the name it spells.
//!
//! RFC 7515 section 4 and RFC 7519 section 4 let a parser take the last of
//! two members or refuse them; a reader that took the first and a verifier
//! that took the last would each trust a different value, so every header,
//! claims set and flattened JWS is refused instead. Until 2026-11-16 the
//! identify capability's token reader refused them and ACME's request
//! reader took the last.

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::{JoseError, Result};

/// The members of the JSON object `bytes` holds; `what` names the object in
/// a refusal.
pub(crate) fn read(bytes: &[u8], what: &str) -> Result<Map<String, Value>> {
    serde_json::from_slice::<Members>(bytes)
        .map(|members| members.0)
        .map_err(|failure| JoseError::new(format!("{what} is not a JSON object: {failure}")))
}

/// An object whose member names are unique.
struct Members(Map<String, Value>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        deserializer.deserialize_map(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a JSON object whose member names are unique")
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut access: A,
    ) -> core::result::Result<Members, A::Error> {
        let mut members = Map::new();
        while let Some(name) = access.next_key::<String>()? {
            if members.contains_key(&name) {
                return Err(de::Error::custom(format!(
                    "the member {name:?} appears twice"
                )));
            }
            let value = access.next_value::<Value>()?;
            members.insert(name, value);
        }
        Ok(Members(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_named_twice_is_refused_even_behind_an_escape() {
        for text in [
            "{\"sub\":\"party-x\",\"sub\":\"admin\"}",
            "{\"sub\":\"party-x\",\"\\u0073ub\":\"admin\"}",
        ] {
            let failure = read(text.as_bytes(), "the claims set").expect_err(text);
            assert!(failure.message.contains("twice"), "{failure}");
            assert!(failure.message.starts_with("the claims set"), "{failure}");
        }
    }

    #[test]
    fn an_array_or_a_cut_object_is_not_an_object() {
        assert!(read(b"[1]", "the header").is_err());
        assert!(read(b"{\"sub\":", "the header").is_err());
        let read = read(b"{\"\\u0073ub\":\"x\"}", "the header").expect("an object");
        assert_eq!(read.get("sub").and_then(Value::as_str), Some("x"));
    }
}
