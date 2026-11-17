use crate::error::{err, Result};

/// A netdev name Podman or the kernel will accept as a single path component.
pub fn validate_ifname(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        return Err(err(format!("{kind} `{name}` must be 1 to 15 bytes")));
    }
    if name == "." || name == ".." || name.starts_with('-') {
        return Err(err(format!("{kind} `{name}` is not allowed")));
    }
    let ok = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    if !ok {
        return Err(err(format!(
            "{kind} `{name}` must not contain '/', whitespace, or other unsupported characters"
        )));
    }
    Ok(())
}

pub fn validate_module_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if !ok {
        return Err(err(format!("driver name `{name}` is not a module name")));
    }
    Ok(())
}

/// Canonical PCI address: lowercase, domain present, function 0–7.
pub fn normalize_pci(addr: &str) -> Result<String> {
    let bytes = addr.as_bytes();
    let shape = bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes[..4].iter().all(u8::is_ascii_hexdigit)
        && bytes[5..7].iter().all(u8::is_ascii_hexdigit)
        && bytes[8..10].iter().all(u8::is_ascii_hexdigit)
        && bytes[11].is_ascii_digit()
        && bytes[11] <= b'7';
    if !shape {
        return Err(err(format!(
            "PCI address `{addr}` must look like 0000:00:00.0"
        )));
    }
    Ok(addr.to_ascii_lowercase())
}

pub fn validate_network_id(id: &str) -> Result<()> {
    let bytes = id.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if !ok || id == "." || id == ".." {
        return Err(err(format!(
            "network id `{id}` cannot be used as a file name"
        )));
    }
    Ok(())
}

pub fn validate_modalias(alias: &str) -> Result<()> {
    if alias.is_empty() || alias.len() > 512 || alias.starts_with('-') {
        return Err(err(format!("modalias `{alias}` is not usable")));
    }
    let ok = alias.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'-' | b'+' | b'=')
    });
    if !ok {
        return Err(err(
            "modalias contains characters that cannot be passed to modprobe",
        ));
    }
    Ok(())
}
