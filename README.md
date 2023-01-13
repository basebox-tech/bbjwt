JWT validation library for [basebox](https://basebox.tech) (and maybe others :-) )

[![Build Status](https://github.com/basebox-tech/bbjwt/actions/workflows/main.yml/badge.svg)](https://github.com/basebox-tech/bbjwt/actions/workflows/main.yml)
[![crates.io](https://img.shields.io/crates/v/bbjwt.svg)](https://crates.io/crates/bbjwt)
[![docs.rs](https://docs.rs/bbjwt/badge.svg)](https://docs.rs/bbjwt)



# Synopsis

This lib was created to provide a straight forward, simple and reliable way to validate
JWTs against a set of public keys loaded from a URL.
We at [basebox](https://basebox.tech) use it to validate OpenID Connect ID Tokens (which are JWTs)
using the set of public keys published by the OpenID server (e.g. Keycloak).

It provides the following features:

* Download a set of public keys from a URL (a [JSON Web Key Set](https://connect2id.com/products/server/docs/config/jwk-set))
* Provide an entry point to update the keyset if necessary
* Parse JWTs and validate them using the key(s) in the downloaded keyset.

And that's it.

Besides, we designed bbjwt to meet the following requirements:

* No unsecure code (openssl crate is not considered unsecure by us :-) )
* Never panic
* No lifetime specifiers in the API
* Asynchronous
* Thread safe

## Algorithm Support

The following table shows all signing algorithms supported by bbjwt, along with some info about
their usage in JWKs, JWTs etc.

| Name    | JOSE "kty" | JOSE "alg" | JOSE "curve"      |
| ------- | ---------- | ---------- | ----------------- |
| RSA256  | RSA        | RS256      |                   |
| RSA384  | RSA        | RS384      |                   |
| RSA512  | RSA        | RS512      |                   |
| ES256   | EC         | ES256      | P-256             |
| ES256   | EC         | ES256      | secp256k1         |
| ES384   | EC         | ES384      | P-384             |
| ES512   | EC         | ES512      | P-521 *(no typo)* |
| Ed25519 | OKP        | EdDSA      | Ed25519           |
| Ed448   | OKP        | EdDSA      | Ed448             |

Encrypted JWTs are not supported.

BTW, if you have the choice, use Ed25519. It is safe and fast.

## Building

bbjwt uses the openssl crate, so OpenSSL development libraries are required to build bbjwt. See
the [openssl crate's](https://docs.rs/openssl/latest/openssl/) documentation for details.

## Why yet another Rust JWT validation lib?

We tried various other Rust JWT libraries, but none worked for us. Problems were complicated
APIs, lacking documentation and/or functionality. This is our attempt at doing better :-)

## Usage

To validate JWTs, you have to have the issuer's public keys available. Using bbjwt, you can
get them either by downloading them from a URL provided by the issuer, or you load them from
a local buffer/file.

### Download public keys from a URL

See the following example:

```rust  no_run
use bbjwt::KeyStore;

#[tokio::main]
async fn main() {

  // bbjwt provides a function to determine the public keyset URL by loading discovery
  // info from the issuer; this is common for OpenID Connect servers.

  // If you are using Keycloak, you can use this convenience function to get the discovery
  // endpoint URL; all you need is the base URL and the realm name:
  let discovery_url = KeyStore::keycloak_discovery_url(
    "https://server.tld", "testing"
  ).unwrap();

  // If you're not using Keycloak, the URL might be different.
  let discovery_url = "https://idp-host.tld/.well-known/discovery";

  // Call IdP's discovery endpoint to query the keyset URL; this is a common feature on
  // OpenID Connect servers.
  let keyset_url = KeyStore::idp_certs_url(discovery_url).await.unwrap();

  // Now we can load the keys into a new KeyStore:
  let keystore = KeyStore::new_from_url(&keyset_url).await.unwrap();
}
```

### Using public keys from memory

When loading public keys from local file or buffer, you can either load a JWK JSON or a PEM encoded
text. JWKs contain all required info to identify the type of key, but for PEM you need to use
the function that corresponds to the type of key.

See the following example:

```rust no_run
use bbjwt::{KeyStore, KeyAlgorithm, EcCurve};

#[tokio::main]
async fn main() {
  // Create an empty keystore
  let mut keystore = KeyStore::new().await.unwrap();

  // Load public key from a JWK JSON; see
  // https://openid.net/specs/draft-jones-json-web-key-03.html#ExampleJWK
  let json_key = r#"
  {
    "kty":"RSA",
    "use":"sig",
    ... abbreviated ...,
  }"#;
  // Add the key
  keystore.add_key(json_key);

  let pem_key = r#"-----BEGIN PUBLIC KEY-----
..."#;

  // Load a RSA key from a PEM buffer
  keystore.add_rsa_pem_key(
    pem_key,
    Some("key-rsa"),
    KeyAlgorithm::RS256
  ).unwrap();

  // Load a EC key from a PEM buffer
  keystore.add_ec_pem_key(
    pem_key,
    Some("key-ec"),
    EcCurve::P256,
    KeyAlgorithm::ES256
  ).unwrap();

  // Load EdDSA key from a PEM buffer
  keystore.add_ec_pem_key(
    pem_key,
    Some("key-ed"),
    EcCurve::Ed25519,
    KeyAlgorithm::EdDSA
  ).unwrap();

  // You can add more keys; in this case, the keys should have an ID and the JWT to be
  // validated should have a "kid" claim. Otherwise, bbjwt uses the first key in the set.
}
```

### Validating JWTs

JWTs are passed as Base64 encoded strings; for details about this format, see e.g. <https://jwt.io>.

To validate a JWT, you pass the base64 encoded JWT and a vector of [`ValidationStep`]s into [`validate_jwt`]. bbjwt provides a convenience function named [`default_validations`] to create a vector of default validation steps.

If the JWT is valid, [`validate_jwt`] returns all claims that the JWT contains (header and payload).

Example:

```rust no_run
use bbjwt::{KeyStore, default_validations, validate_jwt};

#[tokio::main]
async fn main() {
  // Create a keystore; see examples above
  let keystore = KeyStore::new_from_url("https://server.tld/keyset").await.unwrap();

  // Validate a JWT
  let jwt = validate_jwt(
    "<Base64 encoded JWT>",
    &default_validations(
      // required value for the "iss" claim
      "https://idp.domain.url/realm/testing",
      None,
      None),
    &keystore
  )
  .await
  .unwrap();

  // Read some claims (JWT fields)
  assert_eq!(jwt.claims["nonce"].as_str().unwrap(), "UZ1BSZFvy7jKkj1o9p3r7w");
}
```


Copyright (c) 2022 basebox GmbH, all rights reserved.

License: MIT

Made with ❤️ and Emacs :-)
