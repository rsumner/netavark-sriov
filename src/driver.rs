use crate::error::{err, Result};
use crate::names::{validate_modalias, validate_module_name};
use crate::sysfs::Sysfs;

/// Resolve the VF driver. An override is returned without calling `resolve_alias`.
pub fn resolve(
    sysfs: &Sysfs,
    parent: &str,
    pci: &str,
    override_name: Option<&str>,
    resolve_alias: impl FnOnce(&str) -> Result<String>,
) -> Result<String> {
    if let Some(name) = override_name {
        validate_module_name(name)?;
        if name == "vfio-pci" {
            return Err(err(format!(
                "parent {parent} pci {pci} vf_driver is vfio-pci; choose a different module"
            )));
        }
        return Ok(name.to_string());
    }

    let alias = sysfs.modalias(pci)?;
    validate_modalias(&alias)?;
    let output = resolve_alias(&alias).map_err(|error| {
        resolution_error(parent, pci, &alias, &format!("modprobe -R failed: {error}"))
    })?;
    let names: Vec<&str> = output.split_whitespace().collect();
    if names.is_empty() {
        return Err(resolution_error(
            parent,
            pci,
            &alias,
            "modprobe -R returned no module",
        ));
    }
    if names.len() != 1 {
        return Err(resolution_error(
            parent,
            pci,
            &alias,
            "modprobe -R returned more than one module",
        ));
    }
    validate_module_name(names[0])?;
    if names[0] == "vfio-pci" {
        return Err(resolution_error(
            parent,
            pci,
            &alias,
            "modprobe -R returned vfio-pci",
        ));
    }
    Ok(names[0].to_string())
}

fn resolution_error(parent: &str, pci: &str, alias: &str, why: &str) -> crate::error::Error {
    err(format!(
        "cannot resolve VF driver for parent {parent} pci {pci} modalias {alias}: {why}; add a `parent {parent} vf_driver <module>` line to the reserved-device file"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Fixture;

    const ALIAS: &str = "pci:v00008086d0000154Csv00008086sd00000000bc02sc00i00";

    fn fixture() -> (Fixture, String) {
        let fix = Fixture::new();
        fix.add_parent("enp1s0f0", 1);
        let pci = "0000:00:01.0";
        fix.add_vf("enp1s0f0", 0, pci, None);
        fix.set_modalias(pci, ALIAS);
        (fix, pci.to_string())
    }

    #[test]
    fn modalias_selects_iavf_and_override_skips_modprobe() {
        let (fix, pci) = fixture();
        let sysfs = Sysfs::new(&fix.sysfs);
        let selected = resolve(&sysfs, "enp1s0f0", &pci, None, |alias| {
            assert_eq!(alias, ALIAS);
            Ok("iavf\n".to_string())
        })
        .unwrap();
        assert_eq!(selected, "iavf");

        let overridden = resolve(&sysfs, "enp1s0f0", &pci, Some("ixgbevf"), |_| {
            panic!("modprobe -R must not run when vf_driver is set");
        })
        .unwrap();
        assert_eq!(overridden, "ixgbevf");
    }

    #[test]
    fn empty_ambiguous_and_vfio_results_fail() {
        let (fix, pci) = fixture();
        let sysfs = Sysfs::new(&fix.sysfs);
        for (stdout, needle) in [
            ("\n", "no module"),
            ("iavf ixgbevf\n", "more than one"),
            ("vfio-pci\n", "vfio-pci"),
        ] {
            let message = resolve(&sysfs, "enp1s0f0", &pci, None, |_| Ok(stdout.to_string()))
                .unwrap_err()
                .to_string();
            assert!(message.contains("enp1s0f0"), "{message}");
            assert!(message.contains(&pci), "{message}");
            assert!(message.contains(ALIAS), "{message}");
            assert!(message.contains(needle), "{message}");
        }
    }
}
