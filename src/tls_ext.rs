use std::net::ToSocketAddrs;

use url::Url;

/// Extension trait for indicating whether a connection requires TLS for it to be safe
pub trait TlsExt {
  // indicate whether TLS is required
  fn requires_tls(&self) -> bool;
}

impl<T> TlsExt for T
where
  T: ToSocketAddrs,
{
  fn requires_tls(&self) -> bool {
    // TLS may be skipped if an IP satisfies certain conditions.
    // `ToSocketAddrs` may fail though, so the first check is
    // whether the conversion succeeds

    match self.to_socket_addrs() {
      // if conversion fails, assume TLS may not be skipped
      Err(_) => true,
      // if self can be represented as a sequence of socket addrs,
      // verify all of those are not global, aka "local" (see `match` below for details).
      //
      // NOTE: as of 2023-10-26, nightly Rust has an `is_global()` function
      // for `IpAddr` (no differentiation between v4 and v6 required). It should
      // be used once stabilized.
      Ok(addrs) => {
        let is_local = addrs.into_iter().all(|addr| match addr.ip() {
          // an IPv4 address must be one of
          // - private (e.g. 10.0.0.1, 192.168.5.4)
          // - link local (e.g. 169.254.2.3)
          // - loopback (e.g. 127.0.0.1)
          //
          // more exotic cases (benchmarking, documentation, reserved, etc.) are not considered for
          // brevity
          std::net::IpAddr::V4(addr) => {
            addr.is_private() | addr.is_link_local() | addr.is_loopback()
          }

          // an IPv6 address must be the loopback address.
          //
          // checks for other cases (IPv4-mapped, unique link local, etc.)
          // are unstable as of 2023-10-26.
          std::net::IpAddr::V6(addr) => addr.is_loopback(),
        });

        !is_local
      }
    }
  }
}

/// determine whether a URL is "safe":
/// - it's https (certificate validation may still fail), or
/// - it has a socket addrs form and none of those addrs requires TLS
pub(crate) fn is_safe_url(url: &Url) -> bool {
  url.scheme() == "https"
    || match url.socket_addrs(|| Some(80)) {
      Ok(addrs) => !addrs.as_slice().requires_tls(),
      Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
  use super::*;

  // `ToSocketAddrs` requires a port
  fn test_addr(addr: &str) -> bool {
    (addr, 1234).requires_tls()
  }

  #[test]
  fn test_v4() {
    let local = ["localhost", "127.0.0.1", "10.1.2.3"];
    for host in local {
      assert!(!test_addr(host), "{host} should not require TLS");
    }

    let global = ["www.google.com", "8.8.8.8"];
    for host in global {
      assert!(test_addr(host), "{host} should require TLS");
    }
  }

  #[test]
  fn test_v6() {
    let local = ["::1"];
    for host in local {
      assert!(!test_addr(host), "{host} should not require TLS");
    }

    let global = ["2003:d4:773d:7600:904e:2a90:16bb:268d"];
    for host in global {
      assert!(test_addr(host), "{host} should require TLS");
    }
  }

  #[test]
  fn test_urls() {
    let safe_urls = ["http://localhost/", "https://localhost/", "https://www.fastly.com/"];
    for url in safe_urls {
      assert!(is_safe_url(&url.parse().expect("cannot parse URL")), "{url:?} is considered safe");
    }

    let unsafe_urls = ["http://neverssl.com/", "http://8.8.8.8"];
    for url in unsafe_urls {
      assert!(
        !is_safe_url(&url.parse().expect("cannot parse URL")),
        "{url:?} must not be considered safe"
      );
    }
  }
}
