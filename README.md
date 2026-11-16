# xmip-core-library-jose

JOSE for Xmip, one copy: the JSON Web Signature (RFC 7515), the JSON Web
Token (RFC 7519) and the JSON Web Key (RFC 7517), read, written and
verified. What a gate makes of a token — which claims it requires, how a
claim becomes an identity, which algorithms it takes — stays with its
capability; this crate is the format.

| Item | What it is |
| --- | --- |
| `base64url` | A JOSE part read strictly by the estate's one decoder (`codec::base64`), its padding refused: RFC 7515 section 2 omits it |
| `jws` | `Algorithm` — HS256, RS256, ES256, named exactly; `Jws` — a protected header, a payload and a signature, read from the compact serialization or the flattened JSON one, the header's and the body's member names each named once; `sign_flattened`, a payload signed by a `SigningKey`, the seam a key that signs is, the header's `alg` the key's; `is_compact`, the shape that tells a JWT from an opaque token |
| `jwt` | `Token` — a compact JWS whose payload is a claims set, every member named once: a claim by name, a numeric claim, a string-or-array claim, and the registered claims `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` |
| `jwk` (feature `key`) | `Key` — a shared secret for HS256, an RSA public key for RS256, a P-256 public key for ES256, each serving one algorithm under the `kid` it answers to; read from a JWK, SPKI PEM, a modulus and exponent, coordinates or a point; a P-256 key written as a JWK, with its thumbprint (RFC 7638). `KeySet` — the keys a node verifies with, read from a JWK Set document, and the one rule for choosing a key: the one the JWS names, which must serve its algorithm, or every key of the algorithm where it names none |

**A refusal is `JoseError`**, a message in words. The identify,
authenticate and provision capabilities take it into their own errors with
`From`, so a technology writes `?`.

**The crypto is the estate's.** HS256 is `codec::digest`'s HMAC, checked
in constant time. RS256 and ES256 are aws-lc-rs's, the crypto
`xmip-core-library-tls` already builds, and a P-256 key's PEM is read by
`tls::certificate::point_of`. An RS256 key has 2048 bits or more (RFC 7518
section 3.3). A P-256 point is on the curve, whoever handed it over. The
`key` feature brings both in; without it a reader of a token's claims, the
first gate, builds no signature verifier.

Who uses it: the identify capability (the token a property carries, the
principal its claims name) and its `jwt` and `oidc` technologies;
`xmip-core-authenticate-jwt` and `-oidc`, which verify with its keys; the
provision capability, whose P-256 key pair is a `SigningKey`; ACME's
client and the cluster authority that serves ACME (`internal-ca`), whose
requests are flattened JWS and whose accounts are JWKs. Until 2026-11-16
four copies did this work: identify read a compact JWT, authenticate held
the keys behind a `jose` feature over the `rsa` and `p256` crates, and ACME
wrote its own JWK and its own flattened JWS, checked by provisioning's own
ES256 (ADR-0050, amendment 2026-11-16).

`architecture.toml` carries the maturity.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
