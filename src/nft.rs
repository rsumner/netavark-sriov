use serde_json::Value;

use crate::error::{err, Result};
use crate::redirect::ConcreteRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub family: String,
    pub table: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub handle: u64,
    pub comment: Option<String>,
    pub proto: Option<String>,
    pub dport: Option<u16>,
    pub toport: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ruleset {
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
}

pub fn comment(network_id: &str) -> String {
    format!("netavark-sriov:{network_id}")
}

pub fn add_rule_args(rule: &ConcreteRule, comment: &str) -> Vec<String> {
    vec![
        "add".to_string(),
        "rule".to_string(),
        rule.family.clone(),
        "nat".to_string(),
        "prerouting".to_string(),
        rule.proto.clone(),
        "dport".to_string(),
        rule.dport.to_string(),
        "redirect".to_string(),
        "to".to_string(),
        format!(":{}", rule.toport),
        "comment".to_string(),
        // nft joins argv with spaces and lexes the result. The quote characters
        // have to be in the argument: `netavark-sriov:<id>` is not an identifier.
        quote(comment),
    ]
}

/// Wrap `value` in nft double quotes.
///
/// The nft lexer has no string escapes: `"` ends the string and `\` is literal.
/// A network id is `[A-Za-z0-9_.-]`, so the comment's `:` is the only character
/// that quoting has to carry.
fn quote(value: &str) -> String {
    format!("\"{value}\"")
}

pub fn same_redirect(existing: &Rule, rule: &ConcreteRule, comment: &str) -> bool {
    existing.family == rule.family
        && existing.table == "nat"
        && existing.chain == "prerouting"
        && existing.comment.as_deref() == Some(comment)
        && existing.proto.as_deref() == Some(rule.proto.as_str())
        && existing.dport == Some(rule.dport)
        && existing.toport == Some(rule.toport)
}

pub fn chain_is_empty(ruleset: &Ruleset, family: &str, chain: &str) -> bool {
    !ruleset
        .rules
        .iter()
        .any(|rule| rule.family == family && rule.table == "nat" && rule.chain == chain)
}

pub fn table_is_empty(ruleset: &Ruleset, family: &str) -> bool {
    !ruleset
        .chains
        .iter()
        .any(|chain| chain.family == family && chain.table == "nat")
}

pub fn parse_ruleset(text: &str) -> Result<Ruleset> {
    let start = text
        .find('{')
        .ok_or_else(|| err("nft json has no object"))?;
    let value: Value = serde_json::from_str(&text[start..])?;
    let items = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| err("nft json has no nftables list"))?;
    let mut ruleset = Ruleset::default();
    for item in items {
        if let Some(chain) = item.get("chain") {
            ruleset.chains.push(Chain {
                family: json_string(chain, "family")?,
                table: json_string(chain, "table")?,
                name: json_string(chain, "name")?,
            });
        }
        if let Some(rule) = item.get("rule") {
            let mut parsed = Rule {
                family: json_string(rule, "family")?,
                table: json_string(rule, "table")?,
                chain: json_string(rule, "chain")?,
                handle: rule
                    .get("handle")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| err("nft rule has no handle"))?,
                comment: None,
                proto: None,
                dport: None,
                toport: None,
            };
            if let Some(exprs) = rule.get("expr").and_then(Value::as_array) {
                for expr in exprs {
                    examine_expr(&mut parsed, expr);
                }
            }
            // `nft -j list` puts `comment` on the rule, beside `expr`.
            if let Some(text) = rule.get("comment").and_then(Value::as_str) {
                parsed.comment = Some(text.to_string());
            }
            ruleset.rules.push(parsed);
        }
    }
    Ok(ruleset)
}

fn examine_expr(rule: &mut Rule, expr: &Value) {
    if let Some(port) = expr
        .get("redirect")
        .and_then(|redirect| json_u16(redirect.get("port")))
    {
        rule.toport = Some(port);
    }
    let Some(matched) = expr.get("match") else {
        return;
    };
    if matched.get("op").and_then(Value::as_str) != Some("==") {
        return;
    }
    let left = matched.get("left");
    let right = matched.get("right");
    if let Some(payload) = left.and_then(|value| value.get("payload")) {
        if payload.get("field").and_then(Value::as_str) == Some("dport") {
            if let Some(proto) = payload.get("protocol").and_then(Value::as_str) {
                rule.proto = Some(proto.to_string());
            }
            if let Some(port) = json_u16(right) {
                rule.dport = Some(port);
            }
        }
    }
    if rule.proto.is_none() {
        if let Some(meta) = left.and_then(|value| value.get("meta")) {
            if meta.get("key").and_then(Value::as_str) == Some("l4proto") {
                if let Some(proto) = right.and_then(Value::as_str) {
                    rule.proto = Some(proto.to_string());
                }
            }
        }
    }
}

fn json_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| err(format!("nft json is missing {key}")))
}

fn json_u16(value: Option<&Value>) -> Option<u16> {
    let value = value?;
    if let Some(number) = value.as_u64() {
        u16::try_from(number).ok()
    } else {
        value.as_str().and_then(|text| text.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redirect::{self, ConcreteRule};

    const FIXTURE: &str = r#"
warning: ignored
{"nftables": [
  {"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
  {"table": {"family": "ip", "name": "nat", "handle": 1}},
  {"chain": {"family": "ip", "table": "nat", "name": "prerouting", "handle": 1}},
  {"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 5, "comment": "netavark-sriov:net1", "expr": [
    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
    {"redirect": {"port": 8443}}
  ]}},
  {"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 6, "comment": "netavark-sriov:net1", "expr": [
    {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "udp"}},
    {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 53}},
    {"redirect": {"port": 5353}}
  ]}},
  {"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 7, "comment": "netavark-sriov:other", "expr": [
    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 80}},
    {"redirect": {"port": 8080}}
  ]}}
]}
"#;

    #[test]
    fn comment_and_inet_expansion() {
        assert_eq!(comment("abc"), "netavark-sriov:abc");
        let rules = redirect::rules_for(&redirect::parse_list("inet:tcp:443:8200").unwrap());
        assert_eq!(
            rules,
            vec![
                ConcreteRule {
                    family: "ip".into(),
                    proto: "tcp".into(),
                    dport: 443,
                    toport: 8200,
                },
                ConcreteRule {
                    family: "ip6".into(),
                    proto: "tcp".into(),
                    dport: 443,
                    toport: 8200,
                },
            ]
        );
        let args = add_rule_args(&rules[0], &comment("abc"));
        assert_eq!(
            args.last().map(String::as_str),
            Some("\"netavark-sriov:abc\"")
        );
        assert!(args.iter().any(|arg| arg == ":8200"));
        assert_eq!(args[2], "ip");
        assert_eq!(quote("netavark-sriov:abc"), "\"netavark-sriov:abc\"");
    }

    #[test]
    fn parses_handles_and_matches_the_whole_redirect() {
        let ruleset = parse_ruleset(FIXTURE).unwrap();
        assert_eq!(ruleset.rules.len(), 3);
        let wanted = ConcreteRule {
            family: "ip".into(),
            proto: "tcp".into(),
            dport: 443,
            toport: 8443,
        };
        let note = comment("net1");
        let matches: Vec<_> = ruleset
            .rules
            .iter()
            .filter(|rule| same_redirect(rule, &wanted, &note))
            .map(|rule| rule.handle)
            .collect();
        assert_eq!(matches, vec![5]);
        let ours: Vec<_> = ruleset
            .rules
            .iter()
            .filter(|rule| rule.comment.as_deref() == Some(note.as_str()))
            .map(|rule| rule.handle)
            .collect();
        assert_eq!(ours, vec![5, 6]);
        assert!(!chain_is_empty(&ruleset, "ip", "prerouting"));
        assert!(!table_is_empty(&ruleset, "ip"));
    }
}
