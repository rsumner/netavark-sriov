use crate::error::{err, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Ip,
    Ip6,
    Inet,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ip => "ip",
            Family::Ip6 => "ip6",
            Family::Inet => "inet",
        }
    }

    /// nft address families this redirect installs into. `inet` is both.
    pub fn tables(self) -> &'static [&'static str] {
        match self {
            Family::Ip => &["ip"],
            Family::Ip6 => &["ip6"],
            Family::Inet => &["ip", "ip6"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub family: Family,
    pub proto: Proto,
    pub dport: u16,
    pub toport: u16,
}

impl Redirect {
    pub fn canonical(&self) -> String {
        match self.family {
            Family::Ip => format!("{}:{}:{}", self.proto.as_str(), self.dport, self.toport),
            family => format!(
                "{}:{}:{}:{}",
                family.as_str(),
                self.proto.as_str(),
                self.dport,
                self.toport
            ),
        }
    }
}

/// One concrete nft rule. `inet` has already been expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcreteRule {
    pub family: String,
    pub proto: String,
    pub dport: u16,
    pub toport: u16,
}

pub fn parse_list(input: &str) -> Result<Vec<Redirect>> {
    if input.is_empty() {
        return Err(err("redirect is empty"));
    }
    if input.chars().any(char::is_whitespace) {
        return Err(err(
            "redirect items are comma-separated with no spaces, for example tcp:443:8443,udp:53:5353",
        ));
    }
    let mut rules = Vec::new();
    for item in input.split(',') {
        if item.is_empty() {
            return Err(err("redirect contains an empty item"));
        }
        rules.push(parse_one(item)?);
    }
    Ok(rules)
}

pub fn rules_for(redirects: &[Redirect]) -> Vec<ConcreteRule> {
    let mut rules = Vec::new();
    for redirect in redirects {
        for family in redirect.family.tables() {
            rules.push(ConcreteRule {
                family: (*family).to_string(),
                proto: redirect.proto.as_str().to_string(),
                dport: redirect.dport,
                toport: redirect.toport,
            });
        }
    }
    rules
}

pub fn canonical_list(redirects: &[Redirect]) -> String {
    redirects
        .iter()
        .map(Redirect::canonical)
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_one(item: &str) -> Result<Redirect> {
    let parts: Vec<&str> = item.split(':').collect();
    let (family, proto, dport, toport) = match parts.as_slice() {
        [proto, dport, toport] => (Family::Ip, *proto, *dport, *toport),
        [family, proto, dport, toport] => (parse_family(family)?, *proto, *dport, *toport),
        _ => {
            return Err(err(format!(
                "redirect `{item}` is not [family:]proto:dport:toport"
            )))
        }
    };
    Ok(Redirect {
        family,
        proto: parse_proto(proto)?,
        dport: parse_port(item, dport)?,
        toport: parse_port(item, toport)?,
    })
}

fn parse_family(value: &str) -> Result<Family> {
    match value {
        "ip" => Ok(Family::Ip),
        "ip6" => Ok(Family::Ip6),
        "inet" => Ok(Family::Inet),
        _ => Err(err(format!(
            "redirect family `{value}` must be ip, ip6, or inet"
        ))),
    }
}

fn parse_proto(value: &str) -> Result<Proto> {
    match value {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        _ => Err(err(format!(
            "redirect protocol `{value}` must be tcp or udp"
        ))),
    }
}

fn parse_port(item: &str, value: &str) -> Result<u16> {
    let port: u16 = value.parse().map_err(|_| {
        err(format!(
            "redirect `{item}` has port `{value}`, which must be 1-65535"
        ))
    })?;
    if port == 0 {
        return Err(err(format!(
            "redirect `{item}` has port 0, which must be 1-65535"
        )));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_examples_and_rejects_bad_grammar() {
        let rules =
            parse_list("tcp:443:3000,tcp:80:6052,inet:tcp:443:8200,ip6:udp:53:5353").unwrap();
        assert_eq!(
            rules,
            vec![
                Redirect {
                    family: Family::Ip,
                    proto: Proto::Tcp,
                    dport: 443,
                    toport: 3000
                },
                Redirect {
                    family: Family::Ip,
                    proto: Proto::Tcp,
                    dport: 80,
                    toport: 6052
                },
                Redirect {
                    family: Family::Inet,
                    proto: Proto::Tcp,
                    dport: 443,
                    toport: 8200
                },
                Redirect {
                    family: Family::Ip6,
                    proto: Proto::Udp,
                    dport: 53,
                    toport: 5353
                },
            ]
        );
        assert!(parse_list("tcp:443:3000 ").is_err());
        assert!(parse_list("tcp:0:80").is_err());
        assert!(parse_list("tcp:443:0").is_err());
        assert!(parse_list("sctp:1:2").is_err());
        assert!(parse_list("tcp:443").is_err());
        assert!(parse_list("").is_err());
        assert!(parse_list("tcp:443:3000,").is_err());
        assert!(parse_list("tcp:65536:1").is_err());
    }

    #[test]
    fn canonical_form_round_trips_and_omits_default_family() {
        let rules = parse_list("ip:tcp:443:8443,inet:udp:9:9").unwrap();
        let text = canonical_list(&rules);
        assert_eq!(text, "tcp:443:8443,inet:udp:9:9");
        assert_eq!(parse_list(&text).unwrap(), rules);
    }
}
