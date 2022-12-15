JWT validation library for [basebox](https://basebox.tech) (and maybe others :-) )

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

* No unsecure code
* Never panic
* No lifetime specifiers in the API
* Asynchronous
* Thread safe

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

```rust,no_run
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

This example loads the keys from a local buffer.

```rust,no_run
use bbjwt::KeyStore;

#[tokio::main]
async fn main() {
  // Create an empty keystore
  let mut keystore = KeyStore::new().await.unwrap();

  // Read public keys from a buffer; this must be a JWK in JSON syntax; for example
  // https://openid.net/specs/draft-jones-json-web-key-03.html#ExampleJWK
  let json_key = r#"
  {
    "kty":"RSA",
    "use":"sig",
    ... abbreviated ...,
  }"#;
  // Add the key
  keystore.add_key(json_key);

  // You can add more keys; in this case, the keys should have an ID and the JWT to be
  // validated should have a "kid" claim. Otherwise, bbjwt uses the first key in the set.
}
```

### Validating JWTs

JWTs are passed as Base64 encoded strings; for details about this format, see e.g. <https://jwt.io>.

```rust,no_run
use bbjwt::KeyStore;

#[tokio::main]
async fn main() {
  // Create a keystore; see examples above
  let keystore = KeyStore::new_from_url("https://server.tld/keyset").await.unwrap();

}
```


Copyright (c) 2022 basebox GmbH, all rights reserved.

License: MIT

Made with ❤️ and Emacs :-)

