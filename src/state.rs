use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};

use crate::error::{err, Result};
use crate::names::{normalize_pci, validate_network_id};

/// One attached network. The file name is `<network_id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub network_id: String,
    pub network_name: String,
    pub parent: String,
    pub vf_index: u32,
    pub pci: String,
    pub netns_dev: String,
    pub interface_name: String,
    pub mac: String,
    pub vlan: u16,
    pub vf_driver: String,
}

pub fn lock(dir: &Path) -> Result<Flock<File>> {
    fs::create_dir_all(dir)?;
    set_mode(dir, 0o750)?;
    let path = dir.join("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o640)
        .open(&path)?;
    set_mode(&path, 0o640)?;
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, errno)| err(format!("locking {}: {errno}", path.display())))
}

/// `st_dev:st_ino` of the namespace path. Hard links compare equal.
pub fn identity(path: &Path) -> Result<String> {
    let meta =
        fs::metadata(path).map_err(|error| err(format!("stat {}: {error}", path.display())))?;
    // `dev` and `ino` are st_dev and st_ino.
    Ok(format!("{}:{}", meta.dev(), meta.ino()))
}

pub fn load(dir: &Path, id: &str) -> Result<Option<State>> {
    validate_network_id(id)?;
    let path = file_path(dir, id);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(err(format!("reading {}: {error}", path.display()))),
    }
}

pub fn load_all(dir: &Path) -> Result<Vec<State>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(err(format!("reading {}: {error}", dir.display()))),
    };
    let mut states = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        let id = name.trim_end_matches(".json");
        match load(dir, id)? {
            Some(state) => states.push(state),
            None => {
                return Err(err(format!(
                    "state file {} disappeared while it was being read",
                    entry.path().display()
                )))
            }
        }
    }
    Ok(states)
}

pub fn write_atomic(dir: &Path, state: &State) -> Result<()> {
    validate_network_id(&state.network_id)?;
    let pci = normalize_pci(&state.pci)?;
    if pci != state.pci {
        return Err(err(format!(
            "state pci {} is not canonical; expected {pci}",
            state.pci
        )));
    }
    fs::create_dir_all(dir)?;
    set_mode(dir, 0o750)?;
    let final_path = file_path(dir, &state.network_id);
    let temp_path = dir.join(format!(".{}.{}.tmp", state.network_id, std::process::id()));
    let _ = fs::remove_file(&temp_path);
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        set_mode(&temp_path, 0o600)?;
        file.write_all(&serde_json::to_vec_pretty(state)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, &final_path)?;
        // If the directory cannot be synced, the rename may still be visible.
        // Remove it so a failed setup does not keep a state file for a VF it
        // is about to roll back.
        if let Err(error) = File::open(dir).and_then(|directory| directory.sync_all()) {
            let _ = fs::remove_file(&final_path);
            return Err(error.into());
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

pub fn remove(dir: &Path, id: &str) -> Result<()> {
    validate_network_id(id)?;
    let path = file_path(dir, id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(err(format!("removing {}: {error}", path.display()))),
    }
}

fn file_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        State {
            network_id: "net1".to_string(),
            network_name: "demo".to_string(),
            parent: "enp1s0f0".to_string(),
            vf_index: 1,
            pci: "0000:00:01.1".to_string(),
            netns_dev: "0:0".to_string(),
            interface_name: "eth0".to_string(),
            mac: "02:11:22:33:44:55".to_string(),
            vlan: 10,
            vf_driver: "iavf".to_string(),
        }
    }

    #[test]
    fn write_is_private_atomic_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("run");
        let mut state = sample();
        write_atomic(&state_dir, &state).unwrap();
        let path = state_dir.join("net1.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(&state_dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o750);
        for entry in fs::read_dir(&state_dir).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            assert!(!name.starts_with('.'), "{name}");
        }

        state.vlan = 11;
        write_atomic(&state_dir, &state).unwrap();
        assert_eq!(load(&state_dir, "net1").unwrap().unwrap().vlan, 11);
        remove(&state_dir, "missing").unwrap();
        remove(&state_dir, "net1").unwrap();
        assert!(load(&state_dir, "net1").unwrap().is_none());
    }

    #[test]
    fn identity_follows_device_and_inode() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("ns");
        let linked = dir.path().join("ns-link");
        let other = dir.path().join("other");
        File::create(&first).unwrap();
        fs::hard_link(&first, &linked).unwrap();
        File::create(&other).unwrap();
        assert_eq!(identity(&first).unwrap(), identity(&linked).unwrap());
        assert_ne!(identity(&first).unwrap(), identity(&other).unwrap());
    }

    #[test]
    fn corrupt_state_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bad.json"), b"{").unwrap();
        assert!(load_all(dir.path()).is_err());
    }
}
