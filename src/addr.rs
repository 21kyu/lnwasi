use std::net::IpAddr;

use anyhow::{Ok, Result};
use ipnet::IpNet;

use crate::{
    message::{AddressMessage, NetlinkRouteAttr},
    request::{NetlinkRequest, NetlinkRequestData},
    utils::{vec_to_addr, zero_terminated},
};

pub enum AddrCmd {
    Add,
    Replace,
    Del,
}

pub enum AddrFamily {
    All = 0,
    V4 = 2,
    V6 = 10,
}

#[derive(Default, Debug)]
pub struct Address {
    pub index: i32,
    pub address: IpNet,
    pub label: String,
    pub flags: u8,
    pub scope: u8,
    pub broadcast: Option<IpAddr>,
    pub peer: Option<IpNet>,
    pub preferred_lifetime: i32,
    pub valid_lifetime: i32,
}

impl Address {
    pub fn new(address: IpNet) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }
}

pub fn addr_deserialize(buf: &[u8]) -> Result<Address> {
    let if_addr_msg = AddressMessage::deserialize(buf)?;
    let rt_attrs = NetlinkRouteAttr::from(&buf[if_addr_msg.len()..])?;

    let mut addr = Address {
        index: if_addr_msg.index,
        scope: if_addr_msg.scope,
        ..Default::default()
    };

    for attr in rt_attrs {
        match attr.rt_attr.rta_type {
            libc::IFA_ADDRESS => {
                addr.address = IpNet::new(vec_to_addr(attr.value)?, if_addr_msg.prefix_len)?;
            }
            libc::IFA_LOCAL => {
                // TODO
            }
            libc::IFA_BROADCAST => {
                // TODO
            }
            libc::IFA_LABEL => {
                // TODO
            }
            libc::IFA_CACHEINFO => {
                // TODO
            }
            _ => {}
        }
    }

    Ok(addr)
}

pub fn addr_handle(cmd: AddrCmd, index: i32, addr: &Address) -> Result<NetlinkRequest> {
    let (proto, flags) = match cmd {
        AddrCmd::Add => (
            libc::RTM_NEWADDR,
            libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
        ),
        AddrCmd::Replace => (
            libc::RTM_NEWADDR,
            libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK,
        ),
        AddrCmd::Del => (libc::RTM_DELADDR, libc::NLM_F_ACK),
    };

    let mut req = NetlinkRequest::new(proto, flags);

    let (family, local_addr_data) = match addr.address {
        IpNet::V4(ip) => (libc::AF_INET, ip.addr().octets().to_vec()),
        IpNet::V6(ip) => (libc::AF_INET6, ip.addr().octets().to_vec()),
    };

    let peer_addr_data = match addr.peer {
        Some(IpNet::V4(ip)) if family == libc::AF_INET6 => {
            ip.addr().to_ipv6_mapped().octets().to_vec()
        }
        Some(IpNet::V6(ip)) if family == libc::AF_INET => match ip.addr().to_ipv4() {
            Some(ipv4) => ipv4.octets().to_vec(),
            None => vec![],
        },
        Some(IpNet::V4(ip)) => ip.addr().octets().to_vec(),
        Some(IpNet::V6(ip)) => ip.addr().octets().to_vec(),
        None => local_addr_data.clone(),
    };

    let msg = Box::new(AddressMessage {
        family: family as u8,
        prefix_len: addr.address.prefix_len(),
        flags: addr.flags,
        scope: addr.scope,
        index,
    });

    let local_data = Box::new(NetlinkRouteAttr::new(libc::IFA_LOCAL, local_addr_data));
    let address_data = Box::new(NetlinkRouteAttr::new(libc::IFA_ADDRESS, peer_addr_data));

    req.add_data(msg);
    req.add_data(local_data);
    req.add_data(address_data);

    if family == libc::AF_INET {
        let broadcast = match addr.broadcast {
            Some(IpAddr::V4(br)) => br.octets().to_vec(),
            Some(IpAddr::V6(br)) => br.octets().to_vec(),
            None => match addr.address.broadcast() {
                IpAddr::V4(br) => br.octets().to_vec(),
                IpAddr::V6(br) => br.octets().to_vec(),
            },
        };

        let broadcast_data = Box::new(NetlinkRouteAttr::new(libc::IFA_BROADCAST, broadcast));
        req.add_data(broadcast_data);

        if !addr.label.is_empty() {
            let label_data = Box::new(NetlinkRouteAttr::new(
                libc::IFA_LABEL,
                zero_terminated(&addr.label),
            ));
            req.add_data(label_data);
        }

        // TODO: add support for IFA_CACHEINFO
    }

    Ok(req)
}

pub fn addr_list(family: AddrFamily) -> Result<NetlinkRequest> {
    let mut req = NetlinkRequest::new(libc::RTM_GETADDR, libc::NLM_F_DUMP);
    let msg = Box::new(AddressMessage::new(family as i32));
    req.add_data(msg);

    Ok(req)
}
