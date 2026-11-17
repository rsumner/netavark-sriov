use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use netavark::network::types::{Network, NetworkPluginExec, PerNetworkOptions};

use crate::names::normalize_pci;

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub sysfs: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let sysfs = dir.path().join("sys");
        fs::create_dir_all(&sysfs).expect("sysfs root");
        Self { dir, sysfs }
    }

    pub fn add_parent(&self, name: &str, numvfs: u32) {
        let device = self.sysfs.join("class/net").join(name).join("device");
        fs::create_dir_all(&device).unwrap();
        fs::write(device.join("sriov_numvfs"), format!("{numvfs}\n")).unwrap();
    }

    pub fn add_vf(&self, parent: &str, index: u32, pci: &str, driver: Option<&str>) {
        let pci = normalize_pci(pci).expect("pci");
        let device = self.sysfs.join("class/net").join(parent).join("device");
        fs::create_dir_all(&device).unwrap();
        symlink(format!("../{pci}"), device.join(format!("virtfn{index}"))).unwrap();
        let pci_dir = self.sysfs.join("bus/pci/devices").join(&pci);
        fs::create_dir_all(&pci_dir).unwrap();
        if let Some(driver) = driver {
            let driver_dir = self.sysfs.join("bus/pci/drivers").join(driver);
            fs::create_dir_all(&driver_dir).unwrap();
            symlink(
                format!("../../../bus/pci/drivers/{driver}"),
                pci_dir.join("driver"),
            )
            .unwrap();
        }
    }

    pub fn add_netdev(&self, pci: &str, name: &str) {
        let pci = normalize_pci(pci).expect("pci");
        fs::create_dir_all(
            self.sysfs
                .join("bus/pci/devices")
                .join(pci)
                .join("net")
                .join(name),
        )
        .unwrap();
    }

    pub fn set_modalias(&self, pci: &str, alias: &str) {
        let pci = normalize_pci(pci).expect("pci");
        let path = self.sysfs.join("bus/pci/devices").join(pci).join("uevent");
        fs::write(path, format!("MODALIAS={alias}\n")).unwrap();
    }
}

pub fn sample_options() -> HashMap<String, String> {
    HashMap::from([
        ("parent".to_string(), "enp1s0f0".to_string()),
        ("vlan".to_string(), "10".to_string()),
        ("mac".to_string(), "02:11:22:33:44:55".to_string()),
        ("ipv4".to_string(), "192.0.2.10/24".to_string()),
    ])
}

pub fn sample_network() -> Network {
    Network {
        created: None,
        dns_enabled: true,
        driver: "sriov".to_string(),
        id: "net1".to_string(),
        internal: false,
        ipv6_enabled: true,
        name: "demo".to_string(),
        network_interface: None,
        options: Some(sample_options()),
        ipam_options: None,
        subnets: None,
        routes: None,
        network_dns_servers: None,
        labels: None,
    }
}

pub fn plugin_exec(network: Network) -> NetworkPluginExec {
    NetworkPluginExec {
        container_id: "container1".to_string(),
        container_name: "container1".to_string(),
        port_mappings: None,
        network,
        network_options: PerNetworkOptions {
            aliases: None,
            interface_name: "eth0".to_string(),
            static_ips: None,
            static_mac: None,
            options: None,
        },
    }
}
