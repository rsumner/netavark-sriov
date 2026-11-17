use std::collections::HashMap;
use std::fs::{self, File};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use netavark::network::types::{NetAddress, NetInterface, Network, NetworkPluginExec, StatusBlock};

use crate::alloc::{self, Choice};
use crate::cmd;
use crate::driver;
use crate::error::{err, Result};
use crate::names::validate_network_id;
use crate::nft;
use crate::options::{self, Options};
use crate::reserved;
use crate::state::{self, State};
use crate::sysfs::Sysfs;

pub struct Layout {
    pub sysfs: PathBuf,
    pub state_dir: PathBuf,
    pub reserved_file: PathBuf,
    pub ip: PathBuf,
    pub nft: PathBuf,
    pub arping: PathBuf,
    pub modprobe: PathBuf,
}

impl Layout {
    pub fn system() -> Self {
        Self {
            sysfs: PathBuf::from("/sys"),
            state_dir: PathBuf::from("/run/netavark-sriov"),
            reserved_file: PathBuf::from("/etc/netavark/sriov-reserved.conf"),
            ip: PathBuf::from("/sbin/ip"),
            nft: PathBuf::from("/usr/sbin/nft"),
            arping: PathBuf::from("/usr/sbin/arping"),
            modprobe: PathBuf::from("/sbin/modprobe"),
        }
    }
}

pub fn create_network(layout: &Layout, mut network: Network) -> Result<Network> {
    validate_network_id(&network.id)?;
    let parsed = options::parse(
        network
            .options
            .as_ref()
            .ok_or_else(|| err("network options are required"))?,
    )?;
    force_ipam_none(&mut network)?;
    if network
        .subnets
        .as_ref()
        .is_some_and(|subnets| !subnets.is_empty())
    {
        return Err(err(
            "Subnet and Gateway are Podman IPAM fields; set the ipv4 and gateway options instead",
        ));
    }
    let numvfs = Sysfs::new(&layout.sysfs).sriov_numvfs(&parsed.parent)?;
    if numvfs == 0 {
        return Err(err(format!(
            "parent {} has sriov_numvfs=0; create the virtual functions before defining this network",
            parsed.parent
        )));
    }
    network.subnets = None;
    network.dns_enabled = false;
    network.ipv6_enabled = false;
    network.options = Some(options::canonical_map(&parsed));
    Ok(network)
}

pub fn setup_network(
    layout: &Layout,
    netns: &Path,
    exec: &NetworkPluginExec,
) -> Result<StatusBlock> {
    let _lock = state::lock(&layout.state_dir)?;
    validate_network_id(&exec.network.id)?;
    let opts = options::parse(
        exec.network
            .options
            .as_ref()
            .ok_or_else(|| err("network options are required"))?,
    )?;
    let iface = options::check_request(&opts, exec)?;
    let ns_id = state::identity(netns)?;
    let existing = state::load(&layout.state_dir, &exec.network.id)?;
    if let Some(state) = &existing {
        if state.netns_dev != ns_id {
            return Err(err(format!(
                "network {} is already attached to a pod; another container must join that pod instead of attaching this network again",
                exec.network.name
            )));
        }
    }
    require_tool(&layout.ip)?;
    require_tool(&layout.nft)?;
    require_tool(&layout.modprobe)?;
    if let Some(state) = existing {
        if state.parent != opts.parent
            || state.mac != opts.mac
            || state.vlan != opts.vlan
            || state.interface_name != iface
        {
            return Err(err(format!(
                "network {} is already attached on {} but the request does not match the recorded virtual function; tear it down before attaching it again",
                exec.network.name, state.pci
            )));
        }
        if !still_configured(layout, netns, &opts, &state)? {
            return Err(err(format!(
                "network {} is recorded on {} but the virtual function is not configured; tear the network down before attaching it again",
                exec.network.name, state.pci
            )));
        }
        return Ok(status_block(&opts, &iface));
    }
    if opts.gateway.is_some() {
        require_tool(&layout.arping)?;
    }

    let reserved_file = reserved::load(&layout.reserved_file)?;
    let states = state::load_all(&layout.state_dir)?;
    let sysfs = Sysfs::new(&layout.sysfs);
    let choice = alloc::choose(
        &sysfs,
        &opts.parent,
        &exec.network.id,
        &reserved_file.pci,
        &states,
    )?;
    // Resolve before programming so a modprobe failure leaves the VF untouched.
    // The MAC is still applied while the driver is unbound, and before driver_override.
    let driver_name = driver::resolve(
        &sysfs,
        &opts.parent,
        &choice.pci,
        reserved_file
            .vf_driver
            .get(&opts.parent)
            .map(String::as_str),
        |alias| cmd::must(&layout.modprobe, &["-R", alias]),
    )?;

    let mut progress = Progress {
        parent: opts.parent.clone(),
        index: choice.index,
        pci: choice.pci.clone(),
        ..Progress::default()
    };
    let job = Attach {
        layout,
        sysfs: &sysfs,
        netns,
        exec,
        opts: &opts,
        iface: &iface,
        ns_id: &ns_id,
        choice: &choice,
        driver_name: &driver_name,
    };
    match configure(&job, &mut progress) {
        Ok(status) => Ok(status),
        Err(error) => {
            if let Err(rollback_error) =
                rollback(layout, &sysfs, netns, &exec.network.id, &progress)
            {
                return Err(err(format!(
                    "{error}; rollback also failed: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

pub fn teardown_network(layout: &Layout, netns: &Path, exec: &NetworkPluginExec) -> Result<()> {
    let _lock = state::lock(&layout.state_dir)?;
    validate_network_id(&exec.network.id)?;
    let Some(state) = state::load(&layout.state_dir, &exec.network.id)? else {
        return Ok(());
    };
    require_tool(&layout.ip)?;
    require_tool(&layout.nft)?;
    let sysfs = Sysfs::new(&layout.sysfs);
    let mut errors = Vec::new();

    match File::open(netns) {
        Ok(_) => {
            if let Err(error) = delete_redirects(layout, netns, &exec.network.id) {
                errors.push(error.to_string());
            }
            match interface_in_netns(layout, netns, &state.interface_name) {
                Ok(true) => {
                    if let Err(error) = move_to_host(layout, netns, &state.interface_name) {
                        errors.push(error.to_string());
                    }
                }
                Ok(false) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "opening network namespace {}: {error}",
            netns.display()
        )),
    }

    if let Err(error) = unbind_current(&sysfs, &state.pci) {
        errors.push(error.to_string());
    }
    if let Err(error) = sysfs.clear_driver_override(&state.pci) {
        errors.push(error.to_string());
    }
    if let Err(error) = reset_vf(layout, &state.parent, state.vf_index) {
        errors.push(error.to_string());
    }
    if !errors.is_empty() {
        // Keep the state file so a retry can still find the VF index and MAC.
        return Err(err(errors.join("; ")));
    }
    state::remove(&layout.state_dir, &state.network_id)?;
    log::info!(
        "teardown network {} parent {} vf_index {} pci {} interface {}",
        state.network_name,
        state.parent,
        state.vf_index,
        state.pci,
        state.interface_name
    );
    Ok(())
}

#[derive(Debug, Default)]
struct Progress {
    parent: String,
    index: u32,
    pci: String,
    programmed: bool,
    override_written: bool,
    bound: bool,
    in_ns: Option<String>,
    rules: bool,
}

#[derive(Clone, Copy)]
struct Attach<'a> {
    layout: &'a Layout,
    sysfs: &'a Sysfs,
    netns: &'a Path,
    exec: &'a NetworkPluginExec,
    opts: &'a Options,
    iface: &'a str,
    ns_id: &'a str,
    choice: &'a Choice,
    driver_name: &'a str,
}

fn configure(job: &Attach<'_>, progress: &mut Progress) -> Result<StatusBlock> {
    let Attach {
        layout,
        sysfs,
        netns,
        exec,
        opts,
        iface,
        ns_id,
        choice,
        driver_name,
    } = *job;
    // Set the flag first so a partial `ip link set vf` is still reset.
    progress.programmed = true;
    program_vf(layout, opts, choice.index)?;

    if !sysfs.driver_loaded(driver_name)? {
        cmd::must(&layout.modprobe, &[driver_name])?;
    }
    progress.override_written = true;
    sysfs.set_driver_override(&choice.pci, driver_name)?;
    progress.bound = true;
    if sysfs.driver_loaded(driver_name)? {
        sysfs.bind(driver_name, &choice.pci)?;
    } else {
        sysfs.drivers_probe(&choice.pci)?;
    }
    // The name from this wait can already be stale: udev renames eth0 after
    // registration. The move reads sysfs again and retries that race.
    wait_netdev(sysfs, &choice.pci)?;
    let ns = netns_arg(netns)?;
    let kernel_name = move_into_netns(layout, sysfs, &choice.pci, ns)?;
    progress.in_ns = Some(kernel_name.clone());

    // Rename can fail while the device is up.
    cmd::must_in_netns(&layout.ip, &["link", "set", &kernel_name, "down"], netns)?;
    cmd::must_in_netns(
        &layout.ip,
        &["link", "set", &kernel_name, "name", iface],
        netns,
    )?;
    progress.in_ns = Some(iface.to_string());

    if let Some(mtu) = opts.mtu {
        let mtu = mtu.to_string();
        cmd::must_in_netns(&layout.ip, &["link", "set", iface, "mtu", &mtu], netns)?;
    }
    cmd::write_ipv6_sysctls(netns, iface, opts.no_ipv6_default_route)?;
    if let Some(token) = opts.ipv6_token {
        let token = token.to_string();
        cmd::must_in_netns(&layout.ip, &["token", "set", &token, "dev", iface], netns)?;
    }
    let address = opts.ipv4.to_string();
    cmd::must_in_netns(&layout.ip, &["addr", "add", &address, "dev", iface], netns)?;
    cmd::must_in_netns(&layout.ip, &["link", "set", iface, "up"], netns)?;
    cmd::must_in_netns(&layout.ip, &["link", "set", "lo", "up"], netns)?;

    let show = cmd::must_in_netns(&layout.ip, &["-json", "addr", "show", "dev", iface], netns)?;
    let observed = cmd::parse_ip_addr_json(&show)?;
    if !observed.mac.eq_ignore_ascii_case(&opts.mac) {
        return Err(err(format!(
            "interface {iface} has mac {}, expected {}",
            observed.mac, opts.mac
        )));
    }
    match observed.ipv4 {
        Some((addr, prefix)) if addr == opts.ipv4.addr() && prefix == opts.ipv4.prefix_len() => {}
        other => {
            return Err(err(format!(
                "interface {iface} has ipv4 {other:?}, expected {}",
                opts.ipv4
            )))
        }
    }

    if let Some(gateway) = opts.gateway.filter(|_| !opts.no_ipv4_default_route) {
        let gateway = gateway.to_string();
        if let Some(metric) = opts.metric {
            let metric = metric.to_string();
            cmd::must_in_netns(
                &layout.ip,
                &[
                    "route", "add", "default", "via", &gateway, "dev", iface, "metric", &metric,
                ],
                netns,
            )?;
        } else {
            cmd::must_in_netns(
                &layout.ip,
                &["route", "add", "default", "via", &gateway, "dev", iface],
                netns,
            )?;
        }
    }

    if !opts.redirects.is_empty() {
        progress.rules = true;
        install_redirects(layout, netns, &exec.network.id, opts)?;
    }
    if let Some(gateway) = opts.gateway {
        let source = opts.ipv4.addr().to_string();
        let gateway = gateway.to_string();
        // -I pins the announcement to this function when the namespace has two.
        // -f returns on the first reply; the command timeout stops a silent peer from hanging Podman.
        cmd::must_in_netns(
            &layout.arping,
            &[
                "-f", "-q", "-b", "-U", "-c", "2", "-I", iface, "-s", &source, &gateway,
            ],
            netns,
        )?;
    }

    let recorded = State {
        network_id: exec.network.id.clone(),
        network_name: exec.network.name.clone(),
        parent: opts.parent.clone(),
        vf_index: choice.index,
        pci: choice.pci.clone(),
        netns_dev: ns_id.to_string(),
        interface_name: iface.to_string(),
        mac: opts.mac.clone(),
        vlan: opts.vlan,
        vf_driver: driver_name.to_string(),
    };
    state::write_atomic(&layout.state_dir, &recorded)?;
    log::info!(
        "network {} parent {} vf_index {} pci {} interface {}",
        exec.network.name,
        opts.parent,
        choice.index,
        choice.pci,
        iface
    );
    Ok(status_block(opts, iface))
}

fn rollback(
    layout: &Layout,
    sysfs: &Sysfs,
    netns: &Path,
    network_id: &str,
    progress: &Progress,
) -> Result<()> {
    let mut errors = Vec::new();
    if progress.rules {
        if let Err(error) = delete_redirects(layout, netns, network_id) {
            errors.push(error.to_string());
        }
    }
    if let Some(name) = &progress.in_ns {
        if let Err(error) = move_to_host(layout, netns, name) {
            errors.push(error.to_string());
        }
    }
    if progress.bound || progress.override_written {
        if let Err(error) = unbind_current(sysfs, &progress.pci) {
            errors.push(error.to_string());
        }
    }
    if progress.override_written {
        if let Err(error) = sysfs.clear_driver_override(&progress.pci) {
            errors.push(error.to_string());
        }
    }
    if progress.programmed {
        if let Err(error) = reset_vf(layout, &progress.parent, progress.index) {
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(err(errors.join("; ")))
    }
}

fn program_vf(layout: &Layout, opts: &Options, index: u32) -> Result<()> {
    let index = index.to_string();
    let vlan = opts.vlan.to_string();
    cmd::must(
        &layout.ip,
        &[
            "link",
            "set",
            &opts.parent,
            "vf",
            &index,
            "mac",
            &opts.mac,
            "vlan",
            &vlan,
            "trust",
            on_off(opts.trusted),
            "spoofchk",
            on_off(opts.spoofchk),
        ],
    )?;
    Ok(())
}

fn reset_vf(layout: &Layout, parent: &str, index: u32) -> Result<()> {
    // Intel ice treats mac 00:00:00:00:00:00 as clearing the administrative MAC
    // (pf_set_mac = false) and still rejects a multicast address. vlan 0 disables
    // VLAN filtering. ixgbe accepts the same zero address.
    let index = index.to_string();
    cmd::must(
        &layout.ip,
        &[
            "link",
            "set",
            parent,
            "vf",
            &index,
            "mac",
            "00:00:00:00:00:00",
            "vlan",
            "0",
            "trust",
            "off",
            "spoofchk",
            "on",
        ],
    )?;
    Ok(())
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

const MOVE_RETRY: Duration = Duration::from_secs(1);
const MOVE_BACKOFF: Duration = Duration::from_millis(20);

/// Move the VF netdev into `netns`.
///
/// `ip link set NAME netns` resolves NAME once. While udev renames eth0 to a
/// path name, sysfs can already show the new name and `ip` still misses it, or
/// a poll can capture eth0 and lose it before `ip` runs. Retry that miss for a
/// short time. A rename keeps the ifindex, so a changed ifindex is a different
/// device and stops the retry.
fn move_into_netns(layout: &Layout, sysfs: &Sysfs, pci: &str, netns: &str) -> Result<String> {
    let started = Instant::now();
    let mut pinned: Option<u32> = None;
    let mut reported = false;
    let mut last_missing: Option<crate::error::Error> = None;
    loop {
        let name = match sysfs.netdevs(pci)?.as_slice() {
            [one] => one.clone(),
            [] => {
                if !pause_for_rename(started) {
                    return Err(last_missing.unwrap_or_else(|| {
                        err(format!(
                            "pci {pci} lost its netdev before it could be moved into the container namespace"
                        ))
                    }));
                }
                continue;
            }
            many => {
                return Err(err(format!(
                    "pci {pci} exposed more than one netdev: {}",
                    many.join(", ")
                )))
            }
        };
        let Some(ifindex) = sysfs.ifindex(pci, &name)? else {
            if !pause_for_rename(started) {
                return Err(last_missing
                    .unwrap_or_else(|| err(format!("netdev {name} on {pci} has no ifindex"))));
            }
            continue;
        };
        if let Some(expected) = pinned {
            if ifindex != expected {
                return Err(err(format!(
                    "pci {pci} ifindex changed from {expected} to {ifindex} while moving the virtual function"
                )));
            }
        } else {
            pinned = Some(ifindex);
        }
        let args = ["link", "set", name.as_str(), "netns", netns];
        let output = cmd::run(&layout.ip, &args)?;
        if output.status == 0 {
            return Ok(name);
        }
        if !device_missing(&output) {
            return Err(cmd::command_error(&layout.ip, &args, &output));
        }
        if !reported {
            log::info!("pci {pci} interface {name} is not visible to ip yet; retrying the move");
            reported = true;
        }
        last_missing = Some(cmd::command_error(&layout.ip, &args, &output));
        if !pause_for_rename(started) {
            return Err(last_missing.unwrap());
        }
    }
}

fn pause_for_rename(started: Instant) -> bool {
    if started.elapsed() >= MOVE_RETRY {
        false
    } else {
        thread::sleep(MOVE_BACKOFF);
        true
    }
}

fn device_missing(output: &cmd::Output) -> bool {
    let detail = format!("{}{}", output.stderr, output.stdout).to_ascii_lowercase();
    detail.contains("cannot find device")
}

fn wait_netdev(sysfs: &Sysfs, pci: &str) -> Result<String> {
    let started = Instant::now();
    loop {
        match sysfs.netdevs(pci)?.as_slice() {
            [one] => return Ok(one.clone()),
            [] if started.elapsed() < Duration::from_secs(10) => {
                thread::sleep(Duration::from_millis(50));
            }
            [] => return Err(err(format!("timed out waiting for a netdev on {pci}"))),
            many => {
                return Err(err(format!(
                    "pci {pci} exposed more than one netdev: {}",
                    many.join(", ")
                )))
            }
        }
    }
}

fn still_configured(layout: &Layout, netns: &Path, opts: &Options, state: &State) -> Result<bool> {
    let sysfs = Sysfs::new(&layout.sysfs);
    match sysfs.bound_driver(&state.pci)? {
        Some(driver) if driver == state.vf_driver => {}
        _ => return Ok(false),
    }
    let output = cmd::run_in_netns(
        &layout.ip,
        &["-json", "addr", "show", "dev", &state.interface_name],
        netns,
    )?;
    if output.status != 0 {
        return Ok(false);
    }
    let observed = cmd::parse_ip_addr_json(&output.stdout)?;
    let mac_ok = observed.mac.eq_ignore_ascii_case(&opts.mac);
    let ip_ok = matches!(
        observed.ipv4,
        Some((addr, prefix)) if addr == opts.ipv4.addr() && prefix == opts.ipv4.prefix_len()
    );
    Ok(mac_ok && ip_ok)
}

fn move_to_host(layout: &Layout, netns: &Path, iface: &str) -> Result<()> {
    let host = format!("/proc/{}/ns/net", std::process::id());
    // Bringing the link down is best-effort. The move is the step that has to succeed.
    let _ = cmd::run_in_netns(&layout.ip, &["link", "set", iface, "down"], netns)?;
    cmd::must_in_netns(&layout.ip, &["link", "set", iface, "netns", &host], netns)?;
    Ok(())
}

fn unbind_current(sysfs: &Sysfs, pci: &str) -> Result<()> {
    if let Some(driver) = sysfs.bound_driver(pci)? {
        sysfs.unbind(&driver, pci)?;
    }
    Ok(())
}

fn interface_in_netns(layout: &Layout, netns: &Path, name: &str) -> Result<bool> {
    let args = ["link", "show", "dev", name];
    let output = cmd::run_in_netns(&layout.ip, &args, netns)?;
    if output.status == 0 {
        return Ok(true);
    }
    let detail = format!("{}{}", output.stderr, output.stdout).to_ascii_lowercase();
    if detail.contains("does not exist") || detail.contains("cannot find device") {
        return Ok(false);
    }
    Err(cmd::command_error(&layout.ip, &args, &output))
}

fn install_redirects(
    layout: &Layout,
    netns: &Path,
    network_id: &str,
    opts: &Options,
) -> Result<()> {
    let note = nft::comment(network_id);
    for rule in crate::redirect::rules_for(&opts.redirects) {
        ensure_nat(layout, netns, &rule.family)?;
        let ruleset = list_nat(layout, netns, &rule.family)?.ok_or_else(|| {
            err(format!(
                "table {} nat is missing after it was created",
                rule.family
            ))
        })?;
        if ruleset
            .rules
            .iter()
            .any(|existing| nft::same_redirect(existing, &rule, &note))
        {
            continue;
        }
        let args = nft::add_rule_args(&rule, &note);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        cmd::must_in_netns(&layout.nft, &refs, netns)?;
    }
    Ok(())
}

fn delete_redirects(layout: &Layout, netns: &Path, network_id: &str) -> Result<()> {
    let note = nft::comment(network_id);
    for family in ["ip", "ip6"] {
        let Some(ruleset) = list_nat(layout, netns, family)? else {
            continue;
        };
        let victims: Vec<(String, u64)> = ruleset
            .rules
            .iter()
            .filter(|rule| rule.comment.as_deref() == Some(note.as_str()))
            .map(|rule| (rule.chain.clone(), rule.handle))
            .collect();
        for (chain, handle) in victims {
            let handle = handle.to_string();
            cmd::must_in_netns(
                &layout.nft,
                &["delete", "rule", family, "nat", &chain, "handle", &handle],
                netns,
            )?;
        }
        let Some(ruleset) = list_nat(layout, netns, family)? else {
            continue;
        };
        let has_prerouting = ruleset
            .chains
            .iter()
            .any(|chain| chain.family == family && chain.name == "prerouting");
        if has_prerouting && nft::chain_is_empty(&ruleset, family, "prerouting") {
            cmd::must_in_netns(
                &layout.nft,
                &["delete", "chain", family, "nat", "prerouting"],
                netns,
            )?;
        }
        let Some(ruleset) = list_nat(layout, netns, family)? else {
            continue;
        };
        if nft::table_is_empty(&ruleset, family) {
            cmd::must_in_netns(&layout.nft, &["delete", "table", family, "nat"], netns)?;
        }
    }
    Ok(())
}

fn ensure_nat(layout: &Layout, netns: &Path, family: &str) -> Result<()> {
    if list_nat(layout, netns, family)?.is_none() {
        cmd::must_in_netns(&layout.nft, &["add", "table", family, "nat"], netns)?;
    }
    let ruleset = list_nat(layout, netns, family)?.ok_or_else(|| {
        err(format!(
            "table {family} nat is missing after it was created"
        ))
    })?;
    let present = ruleset
        .chains
        .iter()
        .any(|chain| chain.family == family && chain.name == "prerouting");
    if !present {
        cmd::must_in_netns(
            &layout.nft,
            &[
                "add",
                "chain",
                family,
                "nat",
                "prerouting",
                "{ type nat hook prerouting priority -100 ; policy accept ; }",
            ],
            netns,
        )?;
    }
    Ok(())
}

fn list_nat(layout: &Layout, netns: &Path, family: &str) -> Result<Option<nft::Ruleset>> {
    let args = ["-j", "list", "table", family, "nat"];
    let output = cmd::run_in_netns(&layout.nft, &args, netns)?;
    if output.status != 0 {
        let blob = format!("{}{}", output.stderr, output.stdout);
        if blob.contains("does not exist") || blob.contains("No such file or directory") {
            return Ok(None);
        }
        return Err(cmd::command_error(&layout.nft, &args, &output));
    }
    Ok(Some(nft::parse_ruleset(&output.stdout)?))
}

fn force_ipam_none(network: &mut Network) -> Result<()> {
    let mut ipam = network.ipam_options.take().unwrap_or_default();
    if let Some(driver) = ipam.get("driver") {
        if driver != "none" {
            return Err(err(format!(
                "ipam driver `{driver}` is not supported; set IPAMDriver=none and pass the address as the ipv4 option"
            )));
        }
    }
    ipam.insert("driver".to_string(), "none".to_string());
    network.ipam_options = Some(ipam);
    Ok(())
}

fn require_tool(path: &Path) -> Result<()> {
    let meta = fs::metadata(path).map_err(|error| err(format!("{}: {error}", path.display())))?;
    if !meta.is_file() {
        return Err(err(format!("{} is not a file", path.display())));
    }
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(err(format!("{} is not executable", path.display())));
    }
    Ok(())
}

fn netns_arg(netns: &Path) -> Result<&str> {
    netns.to_str().ok_or_else(|| {
        err(format!(
            "network namespace path {} is not utf-8",
            netns.display()
        ))
    })
}

fn status_block(opts: &Options, iface: &str) -> StatusBlock {
    let mut interfaces = HashMap::new();
    interfaces.insert(
        iface.to_string(),
        NetInterface {
            mac_address: opts.mac.clone(),
            subnets: Some(vec![NetAddress {
                gateway: opts.gateway.map(IpAddr::V4),
                ipnet: IpNet::V4(opts.ipv4),
            }]),
        },
    );
    StatusBlock {
        dns_search_domains: Some(Vec::new()),
        dns_server_ips: Some(Vec::new()),
        interfaces: Some(interfaces),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use ipnet::IpNet;
    use netavark::network::types::Subnet;

    use crate::test_util::{self, Fixture};

    fn layout_for(sysfs: &Path, state_dir: &Path, reserved_file: &Path) -> Layout {
        let system = Layout::system();
        Layout {
            sysfs: sysfs.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            reserved_file: reserved_file.to_path_buf(),
            ip: system.ip,
            nft: system.nft,
            arping: system.arping,
            modprobe: system.modprobe,
        }
    }

    #[test]
    fn create_fills_defaults_without_allocating() {
        let fix = Fixture::new();
        fix.add_parent("enp1s0f0", 4);
        let reserved = fix.dir.path().join("missing.conf");
        let layout = layout_for(&fix.sysfs, &fix.dir.path().join("run"), &reserved);
        let network = create_network(&layout, test_util::sample_network()).unwrap();
        assert_eq!(network.name, "demo");
        assert_eq!(network.id, "net1");
        assert_eq!(network.driver, "sriov");
        assert!(!network.dns_enabled);
        assert!(!network.ipv6_enabled);
        assert!(network.subnets.is_none());
        let ipam = network.ipam_options.unwrap();
        assert_eq!(ipam.get("driver").unwrap(), "none");
        let options = network.options.unwrap();
        assert_eq!(options.get("trusted").unwrap(), "true");
        assert_eq!(options.get("spoofchk").unwrap(), "false");
        assert!(!reserved.exists());
    }

    #[test]
    fn create_rejects_ipam_subnets_and_a_missing_parent() {
        let fix = Fixture::new();
        fix.add_parent("enp1s0f0", 4);
        let layout = layout_for(
            &fix.sysfs,
            &fix.dir.path().join("run"),
            &fix.dir.path().join("reserved.conf"),
        );
        let mut network = test_util::sample_network();
        network.subnets = Some(vec![Subnet {
            gateway: None,
            lease_range: None,
            subnet: "192.0.2.0/24".parse::<IpNet>().unwrap(),
        }]);
        assert!(create_network(&layout, network).is_err());

        let mut network = test_util::sample_network();
        network.ipam_options = Some(HashMap::from([(
            "driver".to_string(),
            "host-local".to_string(),
        )]));
        assert!(create_network(&layout, network).is_err());

        fix.add_parent("idle0", 0);
        let mut network = test_util::sample_network();
        network
            .options
            .as_mut()
            .unwrap()
            .insert("parent".into(), "idle0".into());
        let message = create_network(&layout, network).unwrap_err().to_string();
        assert!(message.contains("sriov_numvfs=0"), "{message}");

        let mut network = test_util::sample_network();
        network
            .options
            .as_mut()
            .unwrap()
            .insert("parent".into(), "missing0".into());
        let message = create_network(&layout, network).unwrap_err().to_string();
        assert!(message.contains("does not exist"), "{message}");
    }

    #[test]
    fn setup_refuses_to_allocate_without_the_reserved_file() {
        let dir = tempfile::tempdir().unwrap();
        let ns = dir.path().join("ns");
        File::create(&ns).unwrap();
        let layout = layout_for(
            &dir.path().join("sys"),
            &dir.path().join("run"),
            &dir.path().join("missing.conf"),
        );
        let exec = test_util::plugin_exec(test_util::sample_network());
        let message = setup_network(&layout, &ns, &exec).unwrap_err().to_string();
        assert!(message.contains("missing"), "{message}");
    }

    #[test]
    fn teardown_of_a_missing_state_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = layout_for(
            &dir.path().join("sys"),
            &dir.path().join("run"),
            &dir.path().join("reserved.conf"),
        );
        layout.ip = PathBuf::from("/no/such/ip");
        layout.nft = PathBuf::from("/no/such/nft");
        let exec = test_util::plugin_exec(test_util::sample_network());
        teardown_network(&layout, Path::new("/no/such/ns"), &exec).unwrap();
    }

    fn write_script(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn netdev_with_ifindex(sysfs: &Path, pci: &str, name: &str, ifindex: u32) -> PathBuf {
        let dir = sysfs
            .join("bus/pci/devices")
            .join(pci)
            .join("net")
            .join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ifindex"), format!("{ifindex}\n")).unwrap();
        dir.parent().unwrap().to_path_buf()
    }

    #[test]
    fn move_retries_when_the_netdev_is_renamed() {
        let fix = Fixture::new();
        let pci = "0000:00:01.0";
        let net_dir = netdev_with_ifindex(&fix.sysfs, pci, "eth0", 7);
        let log = fix.dir.path().join("ip.log");
        let mark = fix.dir.path().join("renamed");
        let script = fix.dir.path().join("ip");
        write_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ ! -f '{}' ]; then\n  : > '{}'\n  mv '{}/eth0' '{}/enp2s0f0v1'\n  echo 'Cannot find device \"eth0\"' >&2\n  exit 1\nfi\nexit 0\n",
                log.display(),
                mark.display(),
                mark.display(),
                net_dir.display(),
                net_dir.display()
            ),
        );
        let mut layout = Layout::system();
        layout.ip = script;
        let name =
            super::move_into_netns(&layout, &Sysfs::new(&fix.sysfs), pci, "/run/netns/example")
                .unwrap();
        assert_eq!(name, "enp2s0f0v1");
        let calls = fs::read_to_string(&log).unwrap();
        assert!(calls.contains("link set eth0 netns"), "{calls}");
        assert!(calls.contains("link set enp2s0f0v1 netns"), "{calls}");
    }

    #[test]
    fn move_does_not_retry_a_different_ip_error() {
        let fix = Fixture::new();
        let pci = "0000:00:01.0";
        netdev_with_ifindex(&fix.sysfs, pci, "eth0", 7);
        let log = fix.dir.path().join("ip.log");
        let script = fix.dir.path().join("ip");
        write_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\necho 'RTNETLINK answers: Operation not permitted' >&2\nexit 2\n",
                log.display()
            ),
        );
        let mut layout = Layout::system();
        layout.ip = script;
        let message =
            super::move_into_netns(&layout, &Sysfs::new(&fix.sysfs), pci, "/run/netns/example")
                .unwrap_err()
                .to_string();
        assert!(message.contains("Operation not permitted"), "{message}");
        let calls = fs::read_to_string(&log).unwrap();
        assert_eq!(calls.lines().count(), 1, "{calls}");
    }

    #[test]
    fn move_stops_when_the_ifindex_changes() {
        let fix = Fixture::new();
        let pci = "0000:00:01.0";
        let net_dir = netdev_with_ifindex(&fix.sysfs, pci, "eth0", 7);
        let log = fix.dir.path().join("ip.log");
        let script = fix.dir.path().join("ip");
        write_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\necho 9 > '{}/eth0/ifindex'\necho 'Cannot find device \"eth0\"' >&2\nexit 1\n",
                log.display(),
                net_dir.display()
            ),
        );
        let mut layout = Layout::system();
        layout.ip = script;
        let message =
            super::move_into_netns(&layout, &Sysfs::new(&fix.sysfs), pci, "/run/netns/example")
                .unwrap_err()
                .to_string();
        assert!(message.contains("ifindex changed from 7 to 9"), "{message}");
        let calls = fs::read_to_string(&log).unwrap();
        assert_eq!(calls.lines().count(), 1, "{calls}");
    }
}
