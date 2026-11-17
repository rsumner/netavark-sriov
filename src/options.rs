use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::Ipv4Net;
use netavark::network::types::NetworkPluginExec;

use crate::error::{err, Result};
use crate::names::validate_ifname;
use crate::redirect::{self, Redirect};

/// Driver options from `podman network create --opt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub parent: String,
    pub vlan: u16,
    pub mac: String,
    pub ipv4: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub ipv6_token: Option<Ipv6Addr>,
    pub trusted: bool,
    pub spoofchk: bool,
    pub mtu: Option<u32>,
    pub metric: Option<u32>,
    pub no_ipv4_default_route: bool,
    pub no_ipv6_default_route: bool,
    pub redirects: Vec<Redirect>,
}

const KEYS: &[&str] = &[
    "parent",
    "vlan",
    "mac",
    "ipv4",
    "gateway",
    "ipv6_token",
    "trusted",
    "spoofchk",
    "mtu",
    "metric",
    "no_ipv4_default_route",
    "no_ipv6_default_route",
    "redirect",
];

pub fn parse(map: &HashMap<String, String>) -> Result<Options> {
    for key in map.keys() {
        if key == "interface_name" {
            return Err(err(
                "interface_name is not a network option; Podman passes it as network_options.interface_name",
            ));
        }
        if !KEYS.contains(&key.as_str()) {
            return Err(err(format!("unknown network option `{key}`")));
        }
    }

    let parent = required(map, "parent")?.to_string();
    validate_ifname("parent", &parent)?;

    let vlan = parse_vlan(required(map, "vlan")?)?;
    let mac = parse_mac(required(map, "mac")?)?;
    let ipv4 = parse_ipv4(required(map, "ipv4")?)?;
    let gateway = optional(map, "gateway")?
        .map(|value| parse_gateway(value, ipv4))
        .transpose()?;
    let ipv6_token = optional(map, "ipv6_token")?
        .map(parse_ipv6_token)
        .transpose()?;
    let trusted = match optional(map, "trusted")? {
        Some(value) => parse_bool("trusted", value)?,
        None => true,
    };
    let spoofchk = match optional(map, "spoofchk")? {
        Some(value) => parse_bool("spoofchk", value)?,
        None => false,
    };
    let mtu = optional(map, "mtu")?
        .map(|value| parse_bounded("mtu", value, 68, 65535))
        .transpose()?;
    let metric = optional(map, "metric")?
        .map(|value| parse_bounded("metric", value, 1, u32::MAX))
        .transpose()?;
    let no_ipv4_default_route = match optional(map, "no_ipv4_default_route")? {
        Some(value) => parse_bool("no_ipv4_default_route", value)?,
        None => false,
    };
    let no_ipv6_default_route = match optional(map, "no_ipv6_default_route")? {
        Some(value) => parse_bool("no_ipv6_default_route", value)?,
        None => false,
    };
    let redirects = match optional(map, "redirect")? {
        Some(value) => redirect::parse_list(value)?,
        None => Vec::new(),
    };

    Ok(Options {
        parent,
        vlan,
        mac,
        ipv4,
        gateway,
        ipv6_token,
        trusted,
        spoofchk,
        mtu,
        metric,
        no_ipv4_default_route,
        no_ipv6_default_route,
        redirects,
    })
}

/// Map stored on the network. Defaults are filled in.
/// `no_ipv4_default_route=false` and `no_ipv6_default_route=false` are omitted.
pub fn canonical_map(opts: &Options) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("parent".to_string(), opts.parent.clone());
    map.insert("vlan".to_string(), opts.vlan.to_string());
    map.insert("mac".to_string(), opts.mac.clone());
    map.insert("ipv4".to_string(), opts.ipv4.to_string());
    if let Some(gateway) = opts.gateway {
        map.insert("gateway".to_string(), gateway.to_string());
    }
    if let Some(token) = opts.ipv6_token {
        map.insert("ipv6_token".to_string(), token.to_string());
    }
    map.insert("trusted".to_string(), bool_str(opts.trusted).to_string());
    map.insert("spoofchk".to_string(), bool_str(opts.spoofchk).to_string());
    if let Some(mtu) = opts.mtu {
        map.insert("mtu".to_string(), mtu.to_string());
    }
    if let Some(metric) = opts.metric {
        map.insert("metric".to_string(), metric.to_string());
    }
    if opts.no_ipv4_default_route {
        map.insert("no_ipv4_default_route".to_string(), "true".to_string());
    }
    if opts.no_ipv6_default_route {
        map.insert("no_ipv6_default_route".to_string(), "true".to_string());
    }
    if !opts.redirects.is_empty() {
        map.insert(
            "redirect".to_string(),
            redirect::canonical_list(&opts.redirects),
        );
    }
    map
}

/// Checks that are only known at setup: interface name, static addresses, and host publishes.
pub fn check_request(opts: &Options, exec: &NetworkPluginExec) -> Result<String> {
    let name = if exec.network_options.interface_name.is_empty() {
        "eth0".to_string()
    } else {
        exec.network_options.interface_name.clone()
    };
    validate_ifname("interface_name", &name)?;

    if let Some(ips) = &exec.network_options.static_ips {
        if !ips.is_empty() {
            let expected = IpAddr::V4(opts.ipv4.addr());
            if ips.len() != 1 || ips[0] != expected {
                return Err(err(format!(
                    "static_ips must be exactly the network ipv4 address {expected}; addresses are a network option, not a container option"
                )));
            }
        }
    }
    if let Some(mac) = &exec.network_options.static_mac {
        let got = parse_mac(mac)?;
        if got != opts.mac {
            return Err(err(format!(
                "static_mac {mac} does not match the network mac {}; the MAC is a network option",
                opts.mac
            )));
        }
    }
    if exec
        .port_mappings
        .as_ref()
        .is_some_and(|mappings| !mappings.is_empty())
    {
        return Err(err(
            "port_mappings publish a host port, which cannot reach an SR-IOV virtual function; set the redirect option on the network instead",
        ));
    }
    Ok(name)
}

fn required<'a>(map: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    match map.get(key).map(String::as_str) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(err(format!("network option `{key}` is required"))),
    }
}

fn optional<'a>(map: &'a HashMap<String, String>, key: &str) -> Result<Option<&'a str>> {
    match map.get(key).map(String::as_str) {
        None => Ok(None),
        Some("") => Err(err(format!("network option `{key}` is empty"))),
        Some(value) => Ok(Some(value)),
    }
}

fn parse_vlan(value: &str) -> Result<u16> {
    let vlan: u16 = value
        .parse()
        .map_err(|_| err(format!("vlan `{value}` must be an integer from 1 to 4094")))?;
    if !(1..=4094).contains(&vlan) {
        return Err(err(format!(
            "vlan `{value}` must be an integer from 1 to 4094"
        )));
    }
    Ok(vlan)
}

fn parse_mac(value: &str) -> Result<String> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|part| part.len() != 2) {
        return Err(err(format!(
            "mac `{value}` must be six hex octets, for example 02:11:22:33:44:55"
        )));
    }
    let mut bytes = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        bytes[index] = u8::from_str_radix(part, 16).map_err(|_| {
            err(format!(
                "mac `{value}` must be six hex octets, for example 02:11:22:33:44:55"
            ))
        })?;
    }
    if bytes == [0; 6] {
        return Err(err("mac must be a unicast address, not 00:00:00:00:00:00"));
    }
    if bytes[0] & 0x01 != 0 {
        return Err(err(format!("mac `{value}` is a multicast address")));
    }
    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn parse_ipv4(value: &str) -> Result<Ipv4Net> {
    let net = Ipv4Net::from_str(value)
        .map_err(|_| err(format!("ipv4 `{value}` must be an address and prefix")))?;
    if net.prefix_len() < 31 {
        if net.addr() == net.network() {
            return Err(err(format!("ipv4 `{value}` is a network address")));
        }
        if net.addr() == net.broadcast() {
            return Err(err(format!("ipv4 `{value}` is a broadcast address")));
        }
    }
    Ok(net)
}

fn parse_gateway(value: &str, ipv4: Ipv4Net) -> Result<Ipv4Addr> {
    let gateway: Ipv4Addr = value
        .parse()
        .map_err(|_| err(format!("gateway `{value}` must be an IPv4 address")))?;
    if gateway == ipv4.addr() {
        return Err(err(format!(
            "gateway `{value}` is the same address as ipv4"
        )));
    }
    if !ipv4.contains(&gateway) {
        return Err(err(format!(
            "gateway `{value}` is not on the ipv4 subnet {ipv4}"
        )));
    }
    if ipv4.prefix_len() < 31 {
        if gateway == ipv4.network() {
            return Err(err(format!("gateway `{value}` is the network address")));
        }
        if gateway == ipv4.broadcast() {
            return Err(err(format!("gateway `{value}` is the broadcast address")));
        }
    }
    Ok(gateway)
}

fn parse_ipv6_token(value: &str) -> Result<Ipv6Addr> {
    let addr: Ipv6Addr = value.parse().map_err(|_| {
        err(format!(
            "ipv6_token `{value}` must be an interface identifier such as ::10"
        ))
    })?;
    let segments = addr.segments();
    if segments[0] != 0 || segments[1] != 0 || segments[2] != 0 || segments[3] != 0 {
        return Err(err(format!(
            "ipv6_token `{value}` must have the upper 64 bits clear"
        )));
    }
    if addr.is_unspecified() {
        return Err(err("ipv6_token must not be ::"));
    }
    Ok(addr)
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(err(format!("network option `{key}` must be true or false"))),
    }
}

fn parse_bounded(key: &str, value: &str, min: u32, max: u32) -> Result<u32> {
    let parsed: u32 = value.parse().map_err(|_| {
        err(format!(
            "network option `{key}` must be an integer from {min} to {max}"
        ))
    })?;
    if parsed < min || parsed > max {
        return Err(err(format!(
            "network option `{key}` must be an integer from {min} to {max}"
        )));
    }
    Ok(parsed)
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use netavark::network::types::PortMapping;

    use crate::test_util::{plugin_exec, sample_options};

    #[test]
    fn accepts_bounds_and_fills_defaults() {
        let mut map = sample_options();
        map.insert("vlan".into(), "1".into());
        let low = parse(&map).unwrap();
        assert_eq!(low.vlan, 1);
        map.insert("vlan".into(), "4094".into());
        assert_eq!(parse(&map).unwrap().vlan, 4094);

        map.insert("vlan".into(), "10".into());
        map.insert("ipv4".into(), "192.0.2.10/32".into());
        assert!(parse(&map).is_ok());
        map.insert("ipv4".into(), "192.0.2.0/31".into());
        map.insert("gateway".into(), "192.0.2.1".into());
        assert!(parse(&map).is_ok());
        map.insert("ipv4".into(), "192.0.2.1/31".into());
        map.insert("gateway".into(), "192.0.2.0".into());
        assert!(parse(&map).is_ok());

        let opts = parse(&sample_options()).unwrap();
        assert!(opts.trusted);
        assert!(!opts.spoofchk);
        assert!(!opts.no_ipv4_default_route);
        assert!(!opts.no_ipv6_default_route);
        let stored = canonical_map(&opts);
        assert_eq!(stored.get("trusted").unwrap(), "true");
        assert_eq!(stored.get("spoofchk").unwrap(), "false");
        assert!(!stored.contains_key("no_ipv4_default_route"));
        assert!(!stored.contains_key("no_ipv6_default_route"));
        assert_eq!(parse(&stored).unwrap(), opts);
    }

    #[test]
    fn rejects_bad_addresses_vlans_and_grammar() {
        let mut map = sample_options();
        map.insert("vlan".into(), "0".into());
        assert!(parse(&map).is_err());
        map.insert("vlan".into(), "4095".into());
        assert!(parse(&map).is_err());

        map.insert("vlan".into(), "10".into());
        map.insert("mac".into(), "00:00:00:00:00:00".into());
        assert!(parse(&map).is_err());
        map.insert("mac".into(), "01:11:22:33:44:55".into());
        assert!(parse(&map).is_err());
        map.insert("mac".into(), "ff:ff:ff:ff:ff:ff".into());
        assert!(parse(&map).is_err());

        map.insert("mac".into(), "02:11:22:33:44:55".into());
        map.insert("ipv4".into(), "192.0.2.0/24".into());
        assert!(parse(&map).is_err());
        map.insert("ipv4".into(), "192.0.2.255/24".into());
        assert!(parse(&map).is_err());

        map.insert("ipv4".into(), "192.0.2.10/24".into());
        map.insert("gateway".into(), "192.0.2.1".into());
        assert!(parse(&map).is_ok());
        map.insert("gateway".into(), "192.0.2.10".into());
        assert!(parse(&map).is_err());
        map.insert("gateway".into(), "192.0.2.0".into());
        assert!(parse(&map).is_err());
        map.insert("gateway".into(), "192.0.2.255".into());
        assert!(parse(&map).is_err());
        map.insert("gateway".into(), "198.51.100.1".into());
        assert!(parse(&map).is_err());

        map.insert("gateway".into(), "192.0.2.1".into());
        map.insert("redirect".into(), "tcp:443:3000".into());
        assert!(parse(&map).is_ok());
        map.insert("redirect".into(), "tcp:443:3000 ".into());
        assert!(parse(&map).is_err());
        map.insert("redirect".into(), "tcp:0:1".into());
        assert!(parse(&map).is_err());
        map.insert("redirect".into(), "udp:53:5353".into());
        let with_udp = parse(&map).unwrap();
        assert_eq!(with_udp.redirects.len(), 1);
        map.insert("redirect".into(), "inet:tcp:443:8200".into());
        let expanded = redirect::rules_for(&parse(&map).unwrap().redirects);
        assert_eq!(expanded.len(), 2);

        map.insert("redirect".into(), "tcp:443:3000".into());
        map.insert("trusted".into(), "True".into());
        assert!(parse(&map).is_err());
        map.insert("trusted".into(), "false".into());
        assert!(!parse(&map).unwrap().trusted);

        map.insert("trusted".into(), "true".into());
        map.insert("mtu".into(), "67".into());
        assert!(parse(&map).is_err());
        map.insert("mtu".into(), "68".into());
        assert!(parse(&map).is_ok());
        map.insert("mtu".into(), "65536".into());
        assert!(parse(&map).is_err());
        map.insert("mtu".into(), "65535".into());
        assert!(parse(&map).is_ok());

        map.remove("mtu");
        map.insert("metric".into(), "0".into());
        assert!(parse(&map).is_err());
        map.insert("metric".into(), "1".into());
        assert_eq!(parse(&map).unwrap().metric, Some(1));

        map.remove("metric");
        map.insert("ipv6_token".into(), "::10".into());
        assert!(parse(&map).is_ok());
        map.insert("ipv6_token".into(), "2001:db8::1".into());
        assert!(parse(&map).is_err());
        map.insert("ipv6_token".into(), "::".into());
        assert!(parse(&map).is_err());

        map.remove("ipv6_token");
        map.remove("parent");
        assert!(parse(&map).is_err());
        map.insert("parent".into(), "enp1s0f0".into());
        map.insert("interface_name".into(), "eth0".into());
        assert!(parse(&map)
            .unwrap_err()
            .to_string()
            .contains("interface_name"));

        map.remove("interface_name");
        map.insert("no_ipv4_default_route".into(), "false".into());
        map.insert("no_ipv6_default_route".into(), "false".into());
        let stored = canonical_map(&parse(&map).unwrap());
        assert!(!stored.contains_key("no_ipv4_default_route"));
        assert!(!stored.contains_key("no_ipv6_default_route"));

        map.insert("no_ipv4_default_route".into(), "true".into());
        map.insert("no_ipv6_default_route".into(), "true".into());
        let opts = parse(&map).unwrap();
        assert!(opts.no_ipv4_default_route);
        assert!(opts.no_ipv6_default_route);
        let stored = canonical_map(&opts);
        assert_eq!(stored.get("no_ipv4_default_route").unwrap(), "true");
        assert_eq!(stored.get("no_ipv6_default_route").unwrap(), "true");
        assert_eq!(parse(&stored).unwrap(), opts);

        map.insert("no_default_route".into(), "true".into());
        assert!(parse(&map)
            .unwrap_err()
            .to_string()
            .contains("unknown network option"));
    }

    #[test]
    fn request_checks_static_values_and_publishes() {
        let opts = parse(&sample_options()).unwrap();
        let mut exec = plugin_exec(crate::test_util::sample_network());
        assert_eq!(check_request(&opts, &exec).unwrap(), "eth0");

        exec.network_options.static_ips = Some(vec![IpAddr::V4(opts.ipv4.addr())]);
        assert!(check_request(&opts, &exec).is_ok());
        exec.network_options.static_ips = Some(vec![
            IpAddr::V4(opts.ipv4.addr()),
            "2001:db8::1".parse().unwrap(),
        ]);
        assert!(check_request(&opts, &exec).is_err());

        exec.network_options.static_ips = None;
        exec.network_options.static_mac = Some("02:11:22:33:44:55".into());
        assert!(check_request(&opts, &exec).is_ok());
        let mut lettered_map = sample_options();
        lettered_map.insert("mac".into(), "0A:11:22:33:44:55".into());
        let lettered = parse(&lettered_map).unwrap();
        exec.network_options.static_mac = Some("0a:11:22:33:44:55".into());
        assert!(check_request(&lettered, &exec).is_ok());
        exec.network_options.static_mac = Some("02:00:00:00:00:01".into());
        assert!(check_request(&opts, &exec).is_err());

        exec.network_options.static_mac = None;
        exec.port_mappings = Some(vec![PortMapping {
            container_port: 80,
            host_ip: "0.0.0.0".into(),
            host_port: 8080,
            protocol: "tcp".into(),
            range: 1,
        }]);
        let message = check_request(&opts, &exec).unwrap_err().to_string();
        assert!(message.contains("redirect"), "{message}");

        exec.port_mappings = None;
        exec.network_options.interface_name = "eth0/1".into();
        assert!(check_request(&opts, &exec).is_err());
        exec.network_options.interface_name = ".".into();
        assert!(check_request(&opts, &exec).is_err());
        exec.network_options.interface_name = "1234567890123456".into();
        assert!(check_request(&opts, &exec).is_err());
    }
}
