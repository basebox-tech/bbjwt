# Release notes

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

# 0.4.1
  - Dependency updates to fix rustsec audit issues

# 0.4.0
  - changed the keyset (in the KeyStore struct) to use tokio::sync::RwLock (instead of std::sync::RwLock). The tokio::sync::RwLock "is fair (or write-preferring), in order to ensure that readers cannot starve writers". This also removes the possibility of deadlocks due to panics (albeit unlikely regardless). As a result, several functions in keystore.rs have now become async. 

## 0.3.0
- use native Rust for cryptography ([ring](https://github.com/briansmith/ring) crate)
- dropped support for ES512 and Ed448 signatures (**backwards incompatible change**)
- return proper error message on invalid keytype/curve combinations

## 0.2.2
- When JWT claims fail to validate, include expected and found claim value in error message
- Updated base64 dependency to latest 0.21 (required code changes)
- Updated dependencies to fix audit issues

## 0.2.1

First public release.
