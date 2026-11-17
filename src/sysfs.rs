use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{err, Result};
use crate::names::{normalize_pci, validate_ifname, validate_module_name};

/// A sysfs root. Production uses `/sys`. Tests point this at a temp directory.
pub struct Sysfs {
    root: PathBuf,
}

impl Sysfs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn sriov_numvfs(&self, parent: &str) -> Result<u32> {
        validate_ifname("parent", parent)?;
        let path = self
            .root
            .join("class/net")
            .join(parent)
            .join("device/sriov_numvfs");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(err(format!(
                    "parent {parent} does not exist or has no sriov_numvfs"
                )))
            }
            Err(error) => return Err(err(format!("reading {}: {error}", path.display()))),
        };
        text.trim()
            .parse::<u32>()
            .map_err(|_| err(format!("sriov_numvfs for parent {parent} is not a number")))
    }

    /// PCI address of `virtfn<index>`, taken from the symlink's final component.
    pub fn virtfn_pci(&self, parent: &str, index: u32) -> Result<String> {
        validate_ifname("parent", parent)?;
        let path = self
            .root
            .join("class/net")
            .join(parent)
            .join("device")
            .join(format!("virtfn{index}"));
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(err(format!("parent {parent} has no virtfn{index}")))
            }
            Err(error) => return Err(err(format!("reading {}: {error}", path.display()))),
        };
        if !meta.file_type().is_symlink() {
            return Err(err(format!("{} is not a symlink", path.display())));
        }
        let target = fs::read_link(&path)?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        normalize_pci(name).map_err(|error| {
            err(format!(
                "virtfn{index} on parent {parent} does not point at a PCI address: {error}"
            ))
        })
    }

    /// Driver currently bound to this PCI device. `None` when the symlink is absent.
    pub fn bound_driver(&self, pci: &str) -> Result<Option<String>> {
        let link = self.device(pci)?.join("driver");
        let meta = match fs::symlink_metadata(&link) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(err(format!("reading {}: {error}", link.display()))),
        };
        if !meta.file_type().is_symlink() {
            return Err(err(format!("{} is not a symlink", link.display())));
        }
        let target = fs::read_link(&link)?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string();
        validate_module_name(&name)?;
        Ok(Some(name))
    }

    /// `MODALIAS=` from the device `uevent` file.
    pub fn modalias(&self, pci: &str) -> Result<String> {
        let path = self.device(pci)?.join("uevent");
        let text = fs::read_to_string(&path)
            .map_err(|error| err(format!("reading {}: {error}", path.display())))?;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("MODALIAS=") {
                let alias = value.trim();
                if !alias.is_empty() {
                    return Ok(alias.to_string());
                }
            }
        }
        Err(err(format!("MODALIAS is missing from {}", path.display())))
    }

    pub fn netdevs(&self, pci: &str) -> Result<Vec<String>> {
        let dir = self.device(pci)?.join("net");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(err(format!("reading {}: {error}", dir.display()))),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Interface index of one netdev. `Ok(None)` when the directory was renamed
    /// or removed between the listing and this read.
    pub fn ifindex(&self, pci: &str, name: &str) -> Result<Option<u32>> {
        validate_ifname("netdev", name)?;
        let path = self.device(pci)?.join("net").join(name).join("ifindex");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(err(format!("reading {}: {error}", path.display()))),
        };
        let index = text.trim().parse::<u32>().map_err(|_| {
            err(format!(
                "ifindex for netdev {name} on {pci} is not a number"
            ))
        })?;
        Ok(Some(index))
    }

    pub fn driver_loaded(&self, name: &str) -> Result<bool> {
        validate_module_name(name)?;
        Ok(self.root.join("bus/pci/drivers").join(name).is_dir())
    }

    pub fn set_driver_override(&self, pci: &str, driver: &str) -> Result<()> {
        validate_module_name(driver)?;
        self.write_device(pci, "driver_override", &format!("{driver}\n"))
    }

    pub fn clear_driver_override(&self, pci: &str) -> Result<()> {
        self.write_device(pci, "driver_override", "\n")
    }

    pub fn bind(&self, driver: &str, pci: &str) -> Result<()> {
        validate_module_name(driver)?;
        let pci = normalize_pci(pci)?;
        let path = self.root.join("bus/pci/drivers").join(driver).join("bind");
        write_text(&path, &format!("{pci}\n"))
    }

    pub fn unbind(&self, driver: &str, pci: &str) -> Result<()> {
        validate_module_name(driver)?;
        let pci = normalize_pci(pci)?;
        let path = self
            .root
            .join("bus/pci/drivers")
            .join(driver)
            .join("unbind");
        write_text(&path, &format!("{pci}\n"))
    }

    pub fn drivers_probe(&self, pci: &str) -> Result<()> {
        let pci = normalize_pci(pci)?;
        write_text(
            &self.root.join("bus/pci/drivers_probe"),
            &format!("{pci}\n"),
        )
    }

    fn device(&self, pci: &str) -> Result<PathBuf> {
        let pci = normalize_pci(pci)?;
        Ok(self.root.join("bus/pci/devices").join(pci))
    }

    fn write_device(&self, pci: &str, name: &str, text: &str) -> Result<()> {
        write_text(&self.device(pci)?.join(name), text)
    }
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| err(format!("opening {}: {error}", path.display())))?;
    file.write_all(text.as_bytes())
        .map_err(|error| err(format!("writing {}: {error}", path.display())))?;
    Ok(())
}
