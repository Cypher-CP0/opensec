use crate::{Id, Target, TaskSpec, http_url};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub policy_ref: Id,
    pub project_id: Id,
    pub allowed_origins: Vec<String>,
    pub allowed_cidrs: Vec<String>,
    pub allow_private: bool,
    pub repository_ids: Vec<Id>,
    pub max_input_bytes: u64,
}

fn url(raw: &str) -> Result<Url, String> {
    if !raw.is_ascii() || raw.bytes().any(|b| b.is_ascii_whitespace() || b == b'\\') {
        return Err("policy URLs must be ASCII without whitespace or backslashes".into());
    }
    let u = http_url(raw)?;
    if u.host_str().is_some_and(|h| h.ends_with('.')) {
        return Err("trailing-dot hostnames are not supported".into());
    }
    Ok(u)
}

fn prefix(raw: &str) -> Result<(IpAddr, u32), String> {
    let (ip, bits) = raw.split_once('/').ok_or("CIDR prefix is required")?;
    let ip: IpAddr = ip.parse().map_err(|_| "invalid CIDR address")?;
    let bits: u32 = bits.parse().map_err(|_| "invalid CIDR prefix")?;
    if bits > if ip.is_ipv4() { 32 } else { 128 } {
        return Err("invalid CIDR prefix length".into());
    }
    Ok((ip, bits))
}
fn contains(network: IpAddr, bits: u32, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            bits == 0 || (u32::from(a) >> (32 - bits)) == (u32::from(b) >> (32 - bits))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            bits == 0 || (u128::from(a) >> (128 - bits)) == (u128::from(b) >> (128 - bits))
        }
        _ => false,
    }
}
fn permitted_address(ip: IpAddr, private: bool) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            // Metadata/link-local, shared, transition, benchmark and reserved
            // ranges remain denied even for a private lab.
            if o[0] == 0
                || o[0] >= 224
                || ip.is_link_local()
                || ip.is_documentation()
                || o == [168, 63, 129, 16]
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
            {
                return false;
            }
            private || !(ip.is_private() || ip.is_loopback())
        }
        IpAddr::V6(ip) => {
            let o = ip.octets();
            if ip.to_string() == "fd00:ec2::254"
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some()
                || (o[0] == 0x20 && o[1] == 0x02)
                || (o[0..4] == [0x20, 0x01, 0, 0])
                || (o[0..4] == [0, 0x64, 0xff, 0x9b])
            {
                return false;
            }
            if ip.is_loopback() || ip.is_unique_local() {
                return private;
            }
            // Allow only global-unicast IPv6; deny deprecated compatible forms.
            o[0] & 0xe0 == 0x20
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        self.policy_ref.validate()?;
        self.project_id.validate()?;
        if self.allowed_origins.len() > 64
            || self.allowed_cidrs.len() > 64
            || self.repository_ids.len() > 64
            || self.max_input_bytes == 0
            || self.max_input_bytes > 32 * 1024 * 1024
        {
            return Err("policy exceeds supported limits".into());
        }
        for origin in &self.allowed_origins {
            let u = url(origin)?;
            if u.path() != "/" || u.query().is_some() {
                return Err("allowed origins cannot contain a path or query".into());
            }
        }
        if !self.allowed_origins.is_empty() && self.allowed_cidrs.is_empty() {
            return Err("web policies require explicit destination CIDRs".into());
        }
        for cidr in &self.allowed_cidrs {
            prefix(cidr)?;
        }
        for repo in &self.repository_ids {
            repo.validate()?;
        }
        Ok(())
    }
    pub fn authorize_url(&self, raw: &str) -> Result<(), String> {
        let destination = url(raw)?.origin();
        if !self
            .allowed_origins
            .iter()
            .any(|s| url(s).is_ok_and(|u| u.origin() == destination))
        {
            return Err("URL origin is outside the policy".into());
        }
        Ok(())
    }
    pub fn authorize_task(&self, task: &TaskSpec) -> Result<(), String> {
        self.validate()?;
        task.validate()?;
        if task.project_id.0 != self.project_id.0 || task.policy_ref.0 != self.policy_ref.0 {
            return Err("task project/policy mismatch".into());
        }
        let (source, web) = match &task.target {
            Target::Source { source } => (Some(source), None),
            Target::Web { web } => (None, Some(web)),
            Target::Hybrid { source, web, .. } => (Some(source), Some(web)),
        };
        if source.is_some_and(|s| !self.repository_ids.iter().any(|r| r.0 == s.repository_id.0)) {
            return Err("repository is outside the policy".into());
        }
        if let Some(w) = web {
            self.authorize_url(&w.origin)?;
            for seed in &w.seed_urls {
                self.authorize_url(seed)?;
            }
        }
        Ok(())
    }
    pub fn authorize_network(&self, raw: &str, addresses: &[String]) -> Result<(), String> {
        self.validate()?;
        self.authorize_url(raw)?;
        if addresses.is_empty() || addresses.len() > 64 {
            return Err("a bounded nonempty resolved address set is required".into());
        }
        for value in addresses {
            let ip: IpAddr = value.parse().map_err(|_| "invalid resolved address")?;
            if !permitted_address(ip, self.allow_private)
                || !self
                    .allowed_cidrs
                    .iter()
                    .any(|s| prefix(s).is_ok_and(|(n, b)| contains(n, b, ip)))
            {
                return Err("resolved address is outside the policy".into());
            }
        }
        Ok(())
    }
}
