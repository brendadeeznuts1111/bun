use std::net::IpAddr;

use super::{NetworkOperation, NetworkResource, PermissionDenied, check_network};

/// Native DNS provenance for one connection attempt, never constructed from JS options.
#[derive(Debug)]
pub struct ResolvedNetworkEndpoint {
    host: Box<[u8]>,
    address: IpAddr,
    port: u16,
}

impl ResolvedNetworkEndpoint {
    pub fn issue(host: &[u8], address: &[u8], port: u16) -> Result<Self, PermissionDenied> {
        check_network(
            NetworkOperation::Connect,
            NetworkResource::Endpoint { host, port },
        )?;
        let address = std::str::from_utf8(address)
            .ok()
            .and_then(|value| value.parse::<IpAddr>().ok())
            .ok_or(PermissionDenied)?;
        Ok(Self {
            host: host.into(),
            address,
            port,
        })
    }

    pub fn matches(&self, address: &[u8], port: u16) -> bool {
        check_network(
            NetworkOperation::Connect,
            NetworkResource::Endpoint {
                host: &self.host,
                port,
            },
        )
        .is_ok()
            && self.port == port
            && std::str::from_utf8(address)
                .ok()
                .and_then(|value| value.parse::<IpAddr>().ok())
                == Some(self.address)
    }
}
