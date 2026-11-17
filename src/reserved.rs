use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::error::{err, Result};
use crate::names::{normalize_pci, validate_ifname, validate_module_name};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reserved {
    /// Lowercase PCI addresses the allocator must never use.
    pub pci: BTreeSet<String>,
    /// Optional per-parent VF driver, keyed by the parent netdev name.
    pub vf_driver: BTreeMap<String, String>,
}

pub fn load(path: &Path) -> Result<Reserved> {
    match fs::read_to_string(path) {
        Ok(text) => parse(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(err(format!(
            "reserved-device file {} is missing; refusing to allocate a virtual function",
            path.display()
        ))),
        Err(error) => Err(err(format!(
            "reading reserved-device file {}: {error}",
            path.display()
        ))),
    }
}

pub fn parse(text: &str) -> Result<Reserved> {
    let mut reserved = Reserved::default();
    for (index, line) in text.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Ok(pci) = normalize_pci(trimmed) {
            reserved.pci.insert(pci);
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() == 4 && parts[0] == "parent" && parts[2] == "vf_driver" {
            validate_ifname("parent", parts[1])
                .map_err(|error| err(format!("line {line_no}: {error}")))?;
            validate_module_name(parts[3])
                .map_err(|error| err(format!("line {line_no}: {error}")))?;
            if reserved
                .vf_driver
                .insert(parts[1].to_string(), parts[3].to_string())
                .is_some()
            {
                return Err(err(format!(
                    "line {line_no}: duplicate vf_driver for parent {}",
                    parts[1]
                )));
            }
            continue;
        }
        return Err(err(format!(
            "line {line_no}: unrecognized reserved-file entry `{trimmed}`"
        )));
    }
    Ok(reserved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_comments_pci_and_driver_override() {
        let text = "\n# skip me\n\n0000:0A:0B.1\nparent enp1s0f0 vf_driver iavf\n";
        let reserved = parse(text).unwrap();
        assert!(reserved.pci.contains("0000:0a:0b.1"));
        assert_eq!(reserved.pci.len(), 1);
        assert_eq!(reserved.vf_driver.get("enp1s0f0").unwrap(), "iavf");
    }

    #[test]
    fn empty_text_is_valid_and_bad_lines_are_not() {
        assert_eq!(
            parse("\n# only a comment\n\n").unwrap(),
            Reserved::default()
        );
        assert!(parse("02:00.0").is_err());
        assert!(
            parse("parent enp1s0f0 vf_driver iavf\nparent enp1s0f0 vf_driver ixgbevf\n").is_err()
        );
        assert!(parse("not a pci address").is_err());
    }

    #[test]
    fn missing_file_is_an_error_and_empty_file_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("sriov-reserved.conf");
        let error = load(&missing).unwrap_err().to_string();
        assert!(error.contains("missing"), "{error}");

        let path = dir.path().join("empty.conf");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"# nothing reserved\n").unwrap();
        assert_eq!(load(&path).unwrap(), Reserved::default());
    }
}
