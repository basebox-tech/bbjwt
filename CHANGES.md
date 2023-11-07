# Release notes

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

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
