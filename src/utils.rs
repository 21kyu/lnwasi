use std::net::IpAddr;

use anyhow::{bail, Result};

pub fn align_of(len: usize, align_to: usize) -> usize {
    (len + align_to - 1) & !(align_to - 1)
}

pub fn zero_terminated(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

pub fn vec_to_addr(vec: Vec<u8>) -> Result<IpAddr> {
    // TODO: use IpAddr::parse_ascii when to be stable
    if let Ok(buf) = vec.clone().try_into() {
        let buf: [u8; 4] = buf;
        Ok(IpAddr::from(buf))
    } else if let Ok(buf) = vec.clone().try_into() {
        let buf: [u8; 16] = buf;
        Ok(IpAddr::from(buf))
    } else {
        bail!("invalid address length: {}", vec.len())
    }
}

#[macro_export]
macro_rules! test_setup {
    () => {
        if !nix::unistd::geteuid().is_root() {
            eprintln!("Test skipped, must be run as root");
            return;
        }
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    };
}
