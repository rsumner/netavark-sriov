use std::collections::BTreeSet;

use crate::error::{err, Result};
use crate::state::State;
use crate::sysfs::Sysfs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub index: u32,
    pub pci: String,
}

/// Lowest free VF on `parent`. A VF is free when it is unreserved, unbound, and absent from state.
pub fn choose(
    sysfs: &Sysfs,
    parent: &str,
    network_id: &str,
    reserved_pci: &BTreeSet<String>,
    states: &[State],
) -> Result<Choice> {
    if states.iter().any(|state| state.network_id == network_id) {
        return Err(err(format!(
            "network {network_id} already has a virtual function"
        )));
    }

    let numvfs = sysfs.sriov_numvfs(parent)?;
    let state_on_parent = states.iter().filter(|state| state.parent == parent).count();
    let mut reserved_count = 0u32;
    let mut vfio_count = 0u32;
    let mut chosen = None;

    for index in 0..numvfs {
        let pci = sysfs.virtfn_pci(parent, index)?;
        let mut free = true;
        if reserved_pci.contains(&pci) {
            reserved_count += 1;
            free = false;
        }
        if let Some(driver) = sysfs.bound_driver(&pci)? {
            if driver == "vfio-pci" {
                vfio_count += 1;
            }
            free = false;
        }
        if states.iter().any(|state| state.pci == pci) {
            free = false;
        }
        if free && chosen.is_none() {
            chosen = Some(Choice { index, pci });
        }
    }

    chosen.ok_or_else(|| {
        err(format!(
            "no free virtual function on {parent}: sriov_numvfs={numvfs}, reserved={reserved_count}, vfio-pci={vfio_count}, state files on this parent={state_on_parent}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{self, State};
    use crate::test_util::Fixture;

    fn state_for(id: &str, parent: &str, index: u32, pci: &str) -> State {
        State {
            network_id: id.to_string(),
            network_name: id.to_string(),
            parent: parent.to_string(),
            vf_index: index,
            pci: pci.to_string(),
            netns_dev: "1:1".to_string(),
            interface_name: "eth0".to_string(),
            mac: "02:11:22:33:44:55".to_string(),
            vlan: 10,
            vf_driver: "iavf".to_string(),
        }
    }

    #[test]
    fn lowest_free_index_skips_reserved_bound_and_recorded() {
        let fix = Fixture::new();
        fix.add_parent("enp1s0f0", 4);
        fix.add_vf("enp1s0f0", 0, "0000:00:01.0", None);
        fix.add_vf("enp1s0f0", 1, "0000:00:01.1", Some("vfio-pci"));
        fix.add_vf("enp1s0f0", 2, "0000:00:01.2", Some("iavf"));
        fix.add_vf("enp1s0f0", 3, "0000:00:01.3", None);
        // A netdev without a driver symlink does not by itself consume the VF.
        fix.add_netdev("0000:00:01.3", "enp1s0f0v3");

        let sysfs = Sysfs::new(&fix.sysfs);
        let mut reserved = BTreeSet::new();
        reserved.insert("0000:00:01.0".to_string());
        let choice = choose(&sysfs, "enp1s0f0", "net-a", &reserved, &[]).unwrap();
        assert_eq!(choice.index, 3);
        assert_eq!(choice.pci, "0000:00:01.3");

        let run = fix.dir.path().join("run");
        state::write_atomic(&run, &state_for("net-a", "enp1s0f0", 3, "0000:00:01.3")).unwrap();
        let states = state::load_all(&run).unwrap();
        let exhausted = choose(&sysfs, "enp1s0f0", "net-b", &reserved, &states)
            .unwrap_err()
            .to_string();
        assert!(exhausted.contains("sriov_numvfs=4"), "{exhausted}");
        assert!(exhausted.contains("reserved=1"), "{exhausted}");
        assert!(exhausted.contains("vfio-pci=1"), "{exhausted}");
        assert!(
            exhausted.contains("state files on this parent=1"),
            "{exhausted}"
        );
        let again = choose(&sysfs, "enp1s0f0", "net-a", &reserved, &states)
            .unwrap_err()
            .to_string();
        assert!(again.contains("already"), "{again}");
    }

    #[test]
    fn two_networks_take_two_functions() {
        let fix = Fixture::new();
        fix.add_parent("enp1s0f0", 2);
        fix.add_vf("enp1s0f0", 0, "0000:00:02.0", None);
        fix.add_vf("enp1s0f0", 1, "0000:00:02.1", None);
        let sysfs = Sysfs::new(&fix.sysfs);
        let reserved = BTreeSet::new();
        let first = choose(&sysfs, "enp1s0f0", "net-a", &reserved, &[]).unwrap();
        assert_eq!(first.index, 0);

        let run = fix.dir.path().join("run");
        state::write_atomic(&run, &state_for("net-a", "enp1s0f0", 0, &first.pci)).unwrap();
        let states = state::load_all(&run).unwrap();
        let second = choose(&sysfs, "enp1s0f0", "net-b", &reserved, &states).unwrap();
        assert_eq!(second.index, 1);
        assert!(choose(&sysfs, "enp1s0f0", "net-a", &reserved, &states).is_err());
    }

    #[test]
    fn reserved_and_vfio_are_counted_even_when_they_are_the_same_function() {
        let fix = Fixture::new();
        fix.add_parent("enp1s0f0", 2);
        fix.add_vf("enp1s0f0", 0, "0000:0A:00.0", Some("vfio-pci"));
        fix.add_vf("enp1s0f0", 1, "0000:0a:00.1", None);
        let sysfs = Sysfs::new(&fix.sysfs);
        let mut reserved = BTreeSet::new();
        reserved.insert("0000:0a:00.0".to_string());
        let choice = choose(&sysfs, "enp1s0f0", "net-a", &reserved, &[]).unwrap();
        assert_eq!(choice.index, 1);

        let run = fix.dir.path().join("run");
        state::write_atomic(&run, &state_for("net-a", "enp1s0f0", 1, "0000:0a:00.1")).unwrap();
        let states = state::load_all(&run).unwrap();
        let message = choose(&sysfs, "enp1s0f0", "net-b", &reserved, &states)
            .unwrap_err()
            .to_string();
        assert!(message.contains("sriov_numvfs=2"), "{message}");
        assert!(message.contains("reserved=1"), "{message}");
        assert!(message.contains("vfio-pci=1"), "{message}");
        assert!(
            message.contains("state files on this parent=1"),
            "{message}"
        );
    }
}
