use crate::{Id, Target, TaskSpec, http_url};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_endpoints: Option<Vec<Endpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TrafficLimits>,
    pub policy_ref: Id,
    pub project_id: Id,
    pub allowed_origins: Vec<String>,
    pub allowed_cidrs: Vec<String>,
    pub allow_private: bool,
    pub repository_ids: Vec<Id>,
    pub max_input_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub method: String,
    pub path_template: String,
    #[serde(default)]
    pub allow_query: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficLimits {
    pub min_interval_ms: u32,
    pub max_concurrent: u32,
    pub backoff_seconds: u32,
}
fn endpoint_template(s: &str) -> bool {
    if s == "/" {
        return true;
    }
    if s.len() > 512 || !s.starts_with('/') || s.matches("{id}").count() > 1 {
        return false;
    }
    let parts: Vec<_> = s[1..].split('/').collect();
    parts.len() <= 32
        && parts.iter().all(|p| {
            *p == "{id}"
                || (!p.is_empty()
                    && *p != "."
                    && *p != ".."
                    && p.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
        })
}
fn endpoint_matches(template: &str, path: &str) -> bool {
    let expected: Vec<_> = template.split('/').collect();
    let actual: Vec<_> = path.split('/').collect();
    expected.len() == actual.len()
        && expected.iter().zip(actual).all(|(e, a)| {
            if *e == "{id}" {
                Id(a.to_string()).validate().is_ok()
            } else {
                *e == a
            }
        })
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
pub fn canonical_origin(raw: &str) -> Result<String, String> {
    Ok(url(raw)?.origin().ascii_serialization())
}
impl Policy {
    pub fn canonical_origins(&self) -> Result<Vec<String>, String> {
        self.allowed_origins
            .iter()
            .map(|raw| canonical_origin(raw))
            .collect()
    }
    pub fn validate(&self) -> Result<(), String> {
        if let Some(t) = &self.traffic {
            if !(1..=60000).contains(&t.min_interval_ms)
                || !(1..=16).contains(&t.max_concurrent)
                || !(1..=300).contains(&t.backoff_seconds)
                || self.allowed_endpoints.is_none()
            {
                return Err("traffic controls require bounded settings and endpoint rules".into());
            }
        }
        if let Some(endpoints) = &self.allowed_endpoints {
            if endpoints.is_empty() || endpoints.len() > 128 {
                return Err("provide 1..128 endpoint rules".into());
            }
            let mut seen = std::collections::HashSet::new();
            for e in endpoints {
                if !matches!(
                    e.method.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
                ) || !endpoint_template(&e.path_template)
                    || !seen.insert((&e.method, &e.path_template))
                {
                    return Err(
                        "endpoint rules require distinct bounded method/template pairs".into(),
                    );
                }
            }
        }
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
    pub fn authorize_request(&self, raw: &str, method: &str) -> Result<(), String> {
        self.authorize_url(raw)?;
        if !matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE")
            || (method != "GET" && self.allowed_endpoints.is_none())
        {
            return Err("method requires explicit endpoint authority".into());
        }
        if let Some(endpoints) = &self.allowed_endpoints {
            let u = url(raw)?;
            let raw_path = raw.split('?').next().unwrap_or(raw);
            if raw_path.contains('%')
                || raw_path.split('/').any(|p| p == "." || p == "..")
                || !endpoints.iter().any(|e| {
                    e.method == method
                        && (u.query().is_none() || e.allow_query)
                        && endpoint_matches(&e.path_template, u.path())
                })
            {
                return Err("request endpoint is outside the policy".into());
            }
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
        if task.web_investigator.is_some()
            && (self.traffic.is_none() || self.allowed_endpoints.is_none())
        {
            return Err(
                "web investigation requires explicit endpoints and shared traffic controls".into(),
            );
        }
        if let Some(w) = web {
            self.authorize_url(&w.origin)?;
            for seed in &w.seed_urls {
                self.authorize_request(seed, "GET")?;
            }
            let check = task
                .check
                .as_ref()
                .or_else(|| task.investigator.as_ref().and_then(|i| i.probe.as_ref()));
            if let Some(check) = check {
                for path in check.paths() {
                    self.authorize_request(
                        &format!("{}{}", w.origin.trim_end_matches('/'), path),
                        "GET",
                    )?;
                }
            }
        }
        Ok(())
    }
    pub fn authorize_network(&self, raw: &str, addresses: &[String]) -> Result<(), String> {
        self.authorize_network_method(raw, "GET", addresses)
    }
    pub fn authorize_network_method(
        &self,
        raw: &str,
        method: &str,
        addresses: &[String],
    ) -> Result<(), String> {
        self.validate()?;
        self.authorize_request(raw, method)?;
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
