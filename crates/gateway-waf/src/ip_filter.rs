use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{Result, WafError};

/// IP filter for managing IP whitelists and blacklists
pub struct IpFilter {
    whitelist: Arc<RwLock<IpSet>>,
    blacklist: Arc<RwLock<IpSet>>,
}

/// Set of IP addresses and CIDR ranges
#[derive(Debug, Clone)]
struct IpSet {
    individual_ips: HashSet<IpAddr>,
    cidr_ranges: Vec<CidrRange>,
}

/// CIDR range for IP filtering
#[derive(Debug, Clone)]
struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl IpFilter {
    /// Create a new IP filter
    pub fn new(whitelist: &[String], blacklist: &[String]) -> Self {
        let whitelist_set = IpSet::from_strings(whitelist);
        let blacklist_set = IpSet::from_strings(blacklist);

        Self {
            whitelist: Arc::new(RwLock::new(whitelist_set)),
            blacklist: Arc::new(RwLock::new(blacklist_set)),
        }
    }

    /// Check if an IP address is allowed
    pub async fn check_ip(&self, ip: IpAddr) -> Result<bool> {
        let whitelist = self.whitelist.read().await;
        let blacklist = self.blacklist.read().await;

        // If whitelist is not empty, IP must be in whitelist
        if !whitelist.is_empty() && !whitelist.contains(ip) {
            return Ok(false);
        }

        // IP must not be in blacklist
        if blacklist.contains(ip) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Update the whitelist and blacklist
    pub async fn update_lists(&self, whitelist: &[String], blacklist: &[String]) {
        let new_whitelist = IpSet::from_strings(whitelist);
        let new_blacklist = IpSet::from_strings(blacklist);

        *self.whitelist.write().await = new_whitelist;
        *self.blacklist.write().await = new_blacklist;
    }

    /// Add IP to whitelist
    pub async fn add_to_whitelist(&self, ip_str: &str) -> Result<()> {
        let ip = self.parse_ip_or_cidr(ip_str)?;
        let mut whitelist = self.whitelist.write().await;
        whitelist.add(ip);
        Ok(())
    }

    /// Add IP to blacklist
    pub async fn add_to_blacklist(&self, ip_str: &str) -> Result<()> {
        let ip = self.parse_ip_or_cidr(ip_str)?;
        let mut blacklist = self.blacklist.write().await;
        blacklist.add(ip);
        Ok(())
    }

    /// Remove IP from whitelist
    pub async fn remove_from_whitelist(&self, ip_str: &str) -> Result<bool> {
        let ip = self.parse_ip_or_cidr(ip_str)?;
        let mut whitelist = self.whitelist.write().await;
        Ok(whitelist.remove(ip))
    }

    /// Remove IP from blacklist
    pub async fn remove_from_blacklist(&self, ip_str: &str) -> Result<bool> {
        let ip = self.parse_ip_or_cidr(ip_str)?;
        let mut blacklist = self.blacklist.write().await;
        Ok(blacklist.remove(ip))
    }

    /// Check if IP filter is healthy
    pub async fn is_healthy(&self) -> bool {
        // Simple health check - ensure we can read the lists
        let _whitelist = self.whitelist.read().await;
        let _blacklist = self.blacklist.read().await;
        true
    }

    /// Get statistics about the IP filter
    pub async fn get_stats(&self) -> IpFilterStats {
        let whitelist = self.whitelist.read().await;
        let blacklist = self.blacklist.read().await;

        IpFilterStats {
            whitelist_ips: whitelist.individual_ips.len(),
            whitelist_ranges: whitelist.cidr_ranges.len(),
            blacklist_ips: blacklist.individual_ips.len(),
            blacklist_ranges: blacklist.cidr_ranges.len(),
        }
    }

    /// Parse IP address or CIDR range
    fn parse_ip_or_cidr(&self, ip_str: &str) -> Result<IpOrCidr> {
        if ip_str.contains('/') {
            // CIDR range
            let parts: Vec<&str> = ip_str.split('/').collect();
            if parts.len() != 2 {
                return Err(WafError::ConfigError(format!(
                    "Invalid CIDR format: {}",
                    ip_str
                )));
            }

            let network: IpAddr = parts[0]
                .parse()
                .map_err(|_| WafError::ConfigError(format!("Invalid IP address: {}", parts[0])))?;

            let prefix_len: u8 = parts[1].parse().map_err(|_| {
                WafError::ConfigError(format!("Invalid prefix length: {}", parts[1]))
            })?;

            // Validate prefix length
            match network {
                IpAddr::V4(_) => {
                    if prefix_len > 32 {
                        return Err(WafError::ConfigError(
                            "IPv4 prefix length cannot exceed 32".to_string(),
                        ));
                    }
                }
                IpAddr::V6(_) => {
                    if prefix_len > 128 {
                        return Err(WafError::ConfigError(
                            "IPv6 prefix length cannot exceed 128".to_string(),
                        ));
                    }
                }
            }

            Ok(IpOrCidr::Cidr(CidrRange {
                network,
                prefix_len,
            }))
        } else {
            // Individual IP
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| WafError::ConfigError(format!("Invalid IP address: {}", ip_str)))?;
            Ok(IpOrCidr::Ip(ip))
        }
    }
}

/// IP or CIDR range
enum IpOrCidr {
    Ip(IpAddr),
    Cidr(CidrRange),
}

impl IpSet {
    /// Create an IP set from string representations
    fn from_strings(ip_strings: &[String]) -> Self {
        let mut individual_ips = HashSet::new();
        let mut cidr_ranges = Vec::new();

        for ip_str in ip_strings {
            if ip_str.contains('/') {
                // CIDR range
                if let Ok(cidr) = Self::parse_cidr(ip_str) {
                    cidr_ranges.push(cidr);
                }
            } else {
                // Individual IP
                if let Ok(ip) = ip_str.parse() {
                    individual_ips.insert(ip);
                }
            }
        }

        Self {
            individual_ips,
            cidr_ranges,
        }
    }

    /// Parse CIDR range from string
    fn parse_cidr(cidr_str: &str) -> Result<CidrRange> {
        let parts: Vec<&str> = cidr_str.split('/').collect();
        if parts.len() != 2 {
            return Err(WafError::ConfigError(format!(
                "Invalid CIDR format: {}",
                cidr_str
            )));
        }

        let network: IpAddr = parts[0]
            .parse()
            .map_err(|_| WafError::ConfigError(format!("Invalid IP address: {}", parts[0])))?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| WafError::ConfigError(format!("Invalid prefix length: {}", parts[1])))?;

        Ok(CidrRange {
            network,
            prefix_len,
        })
    }

    /// Check if the set contains the given IP
    fn contains(&self, ip: IpAddr) -> bool {
        // Check individual IPs
        if self.individual_ips.contains(&ip) {
            return true;
        }

        // Check CIDR ranges
        for cidr in &self.cidr_ranges {
            if cidr.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Check if the set is empty
    fn is_empty(&self) -> bool {
        self.individual_ips.is_empty() && self.cidr_ranges.is_empty()
    }

    /// Add IP or CIDR to the set
    fn add(&mut self, ip_or_cidr: IpOrCidr) {
        match ip_or_cidr {
            IpOrCidr::Ip(ip) => {
                self.individual_ips.insert(ip);
            }
            IpOrCidr::Cidr(cidr) => {
                self.cidr_ranges.push(cidr);
            }
        }
    }

    /// Remove IP or CIDR from the set
    fn remove(&mut self, ip_or_cidr: IpOrCidr) -> bool {
        match ip_or_cidr {
            IpOrCidr::Ip(ip) => self.individual_ips.remove(&ip),
            IpOrCidr::Cidr(cidr) => {
                let initial_len = self.cidr_ranges.len();
                self.cidr_ranges.retain(|existing_cidr| {
                    !(existing_cidr.network == cidr.network
                        && existing_cidr.prefix_len == cidr.prefix_len)
                });
                self.cidr_ranges.len() < initial_len
            }
        }
    }
}

impl CidrRange {
    /// Check if the CIDR range contains the given IP
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => self.contains_ipv4(network, ip),
            (IpAddr::V6(network), IpAddr::V6(ip)) => self.contains_ipv6(network, ip),
            _ => false, // IPv4/IPv6 mismatch
        }
    }

    /// Check if IPv4 address is in CIDR range
    fn contains_ipv4(&self, network: Ipv4Addr, ip: Ipv4Addr) -> bool {
        let network_bits = u32::from(network);
        let ip_bits = u32::from(ip);
        let mask = !((1u32 << (32 - self.prefix_len)) - 1);

        (network_bits & mask) == (ip_bits & mask)
    }

    /// Check if IPv6 address is in CIDR range
    fn contains_ipv6(&self, network: Ipv6Addr, ip: Ipv6Addr) -> bool {
        let network_bits = u128::from(network);
        let ip_bits = u128::from(ip);
        let mask = !((1u128 << (128 - self.prefix_len)) - 1);

        (network_bits & mask) == (ip_bits & mask)
    }
}

/// Statistics about IP filter
#[derive(Debug, Clone)]
pub struct IpFilterStats {
    pub whitelist_ips: usize,
    pub whitelist_ranges: usize,
    pub blacklist_ips: usize,
    pub blacklist_ranges: usize,
}
