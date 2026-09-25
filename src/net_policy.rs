//! Destination policy for outbound webhook HTTP requests.
//!
//! Webhook URLs are configured by privileged users, yet the server performs
//! the delivery. To keep that trust boundary tight, every delivery resolves
//! the destination itself and only connects to globally routable addresses,
//! which blocks loopback, private-network, link-local (including cloud
//! metadata), and other special-purpose targets as well as DNS rebinding.
//! Redirects are never followed.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Failure to resolve or validate a webhook destination.
#[derive(Debug)]
pub enum PolicyError {
    /// The hostname did not resolve.
    Resolution(String),
    /// The host resolved, but no address may be contacted.
    Blocked,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolution(host) => write!(formatter, "host {host} did not resolve"),
            Self::Blocked => write!(
                formatter,
                "host resolves only to addresses outside the public internet"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Returns true when the address is safe to contact from the server.
#[must_use]
pub fn is_allowed_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_allowed_v4(v4),
        IpAddr::V6(v6) => is_allowed_v6(v6),
    }
}

fn is_allowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(
        a == 0                        // "this network"
        || a == 10                    // RFC 1918 private
        || a == 127                   // loopback
        || (a == 100 && (64..=127).contains(&b)) // carrier-grade NAT
        || (a == 169 && b == 254)     // link-local, cloud metadata
        || (a == 172 && (16..=31).contains(&b)) // RFC 1918 private
        || (a == 192 && b == 168)     // RFC 1918 private
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // TEST-NET-1 documentation
        || (a == 198 && (b == 18 || b == 19)) // inter-network benchmark
        || (a == 198 && b == 51 && c == 100) // TEST-NET-2 documentation
        || (a == 203 && b == 0 && c == 113) // TEST-NET-3 documentation
        || a >= 224
        // multicast, reserved, broadcast
    )
}

fn is_allowed_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    // ::ffff:0:0/96 — judge the embedded IPv4 address instead.
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        // Each segment splits into exactly two octets, so the shifts below
        // are total and the truncating casts cannot lose information.
        #[allow(clippy::cast_possible_truncation)]
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return is_allowed_v4(v4);
    }
    // 64:ff9b::/96 well-known NAT64 prefix — the real destination is IPv4.
    if segments[..6] == [0, 0, 0, 0, 0, 0] && segments[6] == 0x64 && segments[7] == 0xff9b {
        return false;
    }
    !(
        (segments[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (segments[0] & 0xff00) == 0xff00 // multicast ff00::/8
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] & 0xe000) != 0x2000
        // require global unicast 2000::/3
    )
}

/// A DNS resolution strategy, injectable so tests never touch real DNS.
pub type BoxResolveFuture =
    std::pin::Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send>>;

/// Resolves hostnames for webhook destinations.
pub trait Resolver: Send + Sync + 'static {
    /// Resolves `host` with `port` attached, returning every address the
    /// lookup produced (unfiltered; the policy filters separately).
    fn resolve(&self, host: String, port: u16) -> BoxResolveFuture;
}

/// Production resolver backed by the system DNS stack.
#[derive(Debug)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: String, port: u16) -> BoxResolveFuture {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), port))
                .await?
                .map(|address| address.ip())
                .collect();
            Ok(addresses)
        })
    }
}

/// Resolves a webhook destination and keeps only globally routable
/// addresses, with the resolver injectable so tests never touch real DNS.
///
/// # Errors
///
/// Returns [`PolicyError::Resolution`] when the lookup fails and
/// [`PolicyError::Blocked`] when no resolved address may be contacted.
pub async fn resolve_allowed_with<F, Fut>(
    host: &str,
    port: u16,
    resolve: F,
) -> Result<Vec<SocketAddr>, PolicyError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    let resolved = resolve(host.to_owned(), port)
        .await
        .map_err(|error| PolicyError::Resolution(error.to_string()))?;
    let allowed: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|ip| is_allowed_destination(*ip))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if allowed.is_empty() {
        return Err(PolicyError::Blocked);
    }
    Ok(allowed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::*;

    fn allowed(input: &str) -> bool {
        is_allowed_destination(input.parse().unwrap())
    }

    #[test]
    fn blocked_ranges_are_rejected() {
        for ip in [
            "127.0.0.1",
            "127.8.8.8",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
        ] {
            assert!(!allowed(ip), "{ip} must be blocked");
        }
    }

    #[test]
    fn public_addresses_are_accepted() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "172.15.255.255",
            "2606:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(allowed(ip), "{ip} must be allowed");
        }
    }

    #[tokio::test]
    async fn resolver_output_is_filtered_and_blocking_is_reported() {
        let mixed = |host: String, _port: u16| {
            assert_eq!(host, "example.test");
            async {
                Ok(vec![
                    "10.0.0.1".parse::<IpAddr>().unwrap(),
                    "93.184.216.34".parse::<IpAddr>().unwrap(),
                ])
            }
        };
        let pinned = resolve_allowed_with("example.test", 443, mixed)
            .await
            .unwrap();
        assert_eq!(pinned, vec!["93.184.216.34:443".parse().unwrap()]);

        let internal_only = |_host: String, _port: u16| async {
            Ok(vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "192.168.0.2".parse::<IpAddr>().unwrap(),
            ])
        };
        let error = resolve_allowed_with("example.test", 443, internal_only)
            .await
            .unwrap_err();
        assert!(matches!(error, PolicyError::Blocked));
    }
}
