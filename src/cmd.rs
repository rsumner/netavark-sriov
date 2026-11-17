use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sched::CloneFlags;
use nix::sys::wait::WaitStatus;
use nix::unistd::{fork, ForkResult};

use crate::error::{err, Result};
use crate::names::validate_ifname;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAddr {
    pub mac: String,
    pub ipv4: Option<(Ipv4Addr, u8)>,
}

pub fn run(bin: &Path, args: &[&str]) -> Result<Output> {
    let mut command = Command::new(bin);
    command.args(args);
    command.stdin(Stdio::null());
    finish(command, bin)
}

pub fn must(bin: &Path, args: &[&str]) -> Result<String> {
    let output = run(bin, args)?;
    if output.status != 0 {
        return Err(command_error(bin, args, &output));
    }
    Ok(output.stdout)
}

pub fn run_in_netns(bin: &Path, args: &[&str], netns: &Path) -> Result<Output> {
    let file = File::open(netns).map_err(|error| {
        err(format!(
            "opening network namespace {}: {error}",
            netns.display()
        ))
    })?;
    let fd = file.as_raw_fd();
    let mut command = Command::new(bin);
    command.args(args);
    command.stdin(Stdio::null());
    // SAFETY: the closure runs in the forked child, before exec, and only
    // calls setns. The parent keeps `file` open until spawn returns, so the
    // descriptor number is still open in the child. The closure does not allocate.
    unsafe {
        command.pre_exec(move || {
            // `fd` is the namespace file duplicated into the child by fork.
            let borrowed = BorrowedFd::borrow_raw(fd);
            nix::sched::setns(borrowed, CloneFlags::CLONE_NEWNET).map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let output = finish(command, bin);
    drop(file);
    output
}

pub fn must_in_netns(bin: &Path, args: &[&str], netns: &Path) -> Result<String> {
    let output = run_in_netns(bin, args, netns)?;
    if output.status != 0 {
        return Err(command_error(bin, args, &output));
    }
    Ok(output.stdout)
}

/// Write IPv6 sysctls from inside the container namespace.
///
/// Always sets `accept_ra=2` and `autoconf=1`. When `no_ipv6_default_route`
/// is true, also sets `accept_ra_defrtr=0`.
///
/// The child must not allocate. Callers join any command-reader threads first,
/// which `run` does, so this process is single-threaded at the fork.
pub fn write_ipv6_sysctls(netns: &Path, ifname: &str, no_ipv6_default_route: bool) -> Result<()> {
    validate_ifname("interface_name", ifname)?;
    write_sysctl(netns, ifname, "accept_ra", "2")?;
    write_sysctl(netns, ifname, "autoconf", "1")?;
    if no_ipv6_default_route {
        write_sysctl(netns, ifname, "accept_ra_defrtr", "0")?;
    }
    Ok(())
}

pub fn parse_ip_addr_json(text: &str) -> Result<ObservedAddr> {
    let start = text
        .find(['{', '['])
        .ok_or_else(|| err("ip address json is empty"))?;
    let value: serde_json::Value = serde_json::from_str(&text[start..])?;
    let entry = if let Some(items) = value.as_array() {
        items
            .first()
            .cloned()
            .ok_or_else(|| err("ip address json has no interface"))?
    } else {
        value
    };
    let mac = entry
        .get("address")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut ipv4 = None;
    if let Some(infos) = entry.get("addr_info").and_then(|value| value.as_array()) {
        for info in infos {
            if info.get("family").and_then(|value| value.as_str()) != Some("inet") {
                continue;
            }
            let Some(local) = info.get("local").and_then(|value| value.as_str()) else {
                continue;
            };
            let Some(prefix) = info.get("prefixlen").and_then(|value| value.as_u64()) else {
                continue;
            };
            if prefix > 32 {
                continue;
            }
            if let Ok(addr) = local.parse::<Ipv4Addr>() {
                ipv4 = Some((addr, prefix as u8));
                break;
            }
        }
    }
    Ok(ObservedAddr { mac, ipv4 })
}

pub fn command_error(bin: &Path, args: &[&str], output: &Output) -> crate::error::Error {
    let detail = if output.stderr.trim().is_empty() {
        clip(&output.stdout)
    } else {
        clip(&output.stderr)
    };
    err(format!(
        "{} {} exited {}: {detail}",
        bin.display(),
        args.join(" "),
        output.status
    ))
}

fn finish(mut command: Command, bin: &Path) -> Result<Output> {
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| err(format!("spawning {}: {error}", bin.display())))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_thread = thread::spawn(move || read_pipe(stdout));
    let stderr_thread = thread::spawn(move || read_pipe(stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(err(format!(
                    "{} timed out after {} seconds",
                    bin.display(),
                    COMMAND_TIMEOUT.as_secs()
                )));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(err(format!("waiting for {}: {error}", bin.display())));
            }
        }
    };
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    Ok(Output {
        status: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

fn read_pipe<R: Read>(pipe: Option<R>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    String::from_utf8_lossy(&buffer).into_owned()
}

fn write_sysctl(netns: &Path, ifname: &str, key: &str, value: &str) -> Result<()> {
    let file = File::open(netns).map_err(|error| {
        err(format!(
            "opening network namespace {}: {error}",
            netns.display()
        ))
    })?;
    let fd = file.as_raw_fd();
    let path = std::ffi::CString::new(format!("/proc/sys/net/ipv6/conf/{ifname}/{key}"))
        .map_err(|_| err(format!("sysctl path for {ifname} is not a C string")))?;
    let payload = format!("{value}\n").into_bytes();
    // SAFETY: the child only calls setns, open, write, close, and _exit.
    // It does not allocate, lock, or return into the parent. Reader threads
    // from earlier commands have already been joined.
    let forked = unsafe { fork() }.map_err(|error| err(format!("fork: {error}")))?;
    match forked {
        ForkResult::Child => {
            let code = sysctl_child(fd, &path, &payload);
            unsafe { libc::_exit(code) };
        }
        ForkResult::Parent { child } => {
            drop(file);
            match nix::sys::wait::waitpid(child, None) {
                Ok(WaitStatus::Exited(_, 0)) => Ok(()),
                Ok(WaitStatus::Exited(_, 111)) => Err(err(format!(
                    "setns into the container network namespace failed while writing {key} for {ifname}"
                ))),
                Ok(WaitStatus::Exited(_, 112)) => Err(err(format!(
                    "opening net.ipv6.conf.{ifname}.{key} failed"
                ))),
                Ok(WaitStatus::Exited(_, 113)) => Err(err(format!(
                    "writing net.ipv6.conf.{ifname}.{key} failed"
                ))),
                Ok(other) => Err(err(format!(
                    "sysctl helper for {ifname}.{key} ended with {other:?}"
                ))),
                Err(error) => Err(err(format!("waitpid: {error}"))),
            }
        }
    }
}

fn sysctl_child(fd: std::os::fd::RawFd, path: &std::ffi::CStr, payload: &[u8]) -> i32 {
    if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 {
        return 111;
    }
    let file = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if file < 0 {
        return 112;
    }
    let wrote = unsafe { libc::write(file, payload.as_ptr().cast(), payload.len()) };
    unsafe { libc::close(file) };
    if wrote < 0 || wrote as usize != payload.len() {
        return 113;
    }
    0
}

fn clip(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= 2000 {
        trimmed.to_string()
    } else {
        trimmed.chars().take(2000).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_addr_json_after_a_prefix() {
        let text = r#"
Error: ignored warning
[{"ifname":"eth0","address":"02:11:22:33:44:55","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]}]
"#;
        let observed = parse_ip_addr_json(text).unwrap();
        assert_eq!(observed.mac, "02:11:22:33:44:55");
        assert_eq!(observed.ipv4, Some(("192.0.2.10".parse().unwrap(), 24)));
    }
}
