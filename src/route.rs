use std::net::IpAddr;

use anyhow::{bail, Ok, Result};
use ipnet::IpNet;

use crate::{
    message::{NetlinkRouteAttr, RouteMessage},
    request::{NetlinkRequest, NetlinkRequestData},
    utils::vec_to_addr,
};

#[derive(PartialEq)]
pub enum RtCmd {
    Add,
    Append,
    Replace,
    Del,
    Show,
}

pub enum RtFilter {
    Oif,
    None,
}

#[derive(Default, Debug)]
pub struct Route {
    pub oif_index: i32,
    pub iif_index: i32,
    pub family: u8,
    pub dst: Option<IpNet>,
    pub src: Option<IpAddr>,
    pub gw: Option<IpAddr>,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub rtm_type: u8,
    pub flags: u32,
}

pub fn route_deserialize(buf: &[u8]) -> Result<Route> {
    let if_route_msg = RouteMessage::deserialize(buf)?;
    let rt_attrs = NetlinkRouteAttr::from(&buf[if_route_msg.len()..])?;

    let mut route = Route {
        family: if_route_msg.family,
        tos: if_route_msg.tos,
        table: if_route_msg.table,
        protocol: if_route_msg.protocol,
        scope: if_route_msg.scope,
        rtm_type: if_route_msg.rtm_type,
        ..Default::default()
    };

    for attr in rt_attrs {
        match attr.rt_attr.rta_type {
            libc::RTA_GATEWAY => {
                route.gw = Some(vec_to_addr(attr.value)?);
            }
            libc::RTA_PREFSRC => {
                route.src = Some(vec_to_addr(attr.value)?);
            }
            libc::RTA_DST => {
                route.dst = Some(IpNet::new(vec_to_addr(attr.value)?, if_route_msg.dst_len)?);
            }
            libc::RTA_OIF => {
                route.oif_index = i32::from_ne_bytes(attr.value[..4].try_into()?);
            }
            libc::RTA_IIF => {
                route.iif_index = i32::from_ne_bytes(attr.value[..4].try_into()?);
            }
            // TODO: more types
            _ => {}
        }
    }

    Ok(route)
}

pub fn route_handle(cmd: RtCmd, route: &Route) -> Result<NetlinkRequest> {
    let (proto, flags) = match cmd {
        RtCmd::Add => (
            libc::RTM_NEWROUTE,
            libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
        ),
        RtCmd::Append => (
            libc::RTM_NEWROUTE,
            libc::NLM_F_CREATE | libc::NLM_F_APPEND | libc::NLM_F_ACK,
        ),
        RtCmd::Replace => (
            libc::RTM_NEWROUTE,
            libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK,
        ),
        RtCmd::Del => (libc::RTM_DELROUTE, libc::NLM_F_ACK),
        RtCmd::Show => (libc::RTM_GETROUTE, libc::NLM_F_DUMP),
    };

    let mut req = NetlinkRequest::new(proto, flags);

    let mut msg = match proto {
        libc::RTM_DELROUTE => Box::new(RouteMessage::new_rt_del_msg()),
        _ if cmd == RtCmd::Show => Box::new(RouteMessage::new_rt_list_msg(route.family)),
        _ => Box::new(RouteMessage::new_rt_msg()),
    };

    let mut attrs = vec![];

    if proto != libc::RTM_GETROUTE || route.oif_index > 0 {
        let mut b = [0; 4];
        b.copy_from_slice(&route.oif_index.to_ne_bytes());
        attrs.push(Box::new(NetlinkRouteAttr::new(libc::RTA_OIF, b.to_vec())));
    }

    if let Some(dst) = route.dst {
        let (family, dst_data) = match dst {
            IpNet::V4(ip) => (libc::AF_INET, ip.addr().octets().to_vec()),
            IpNet::V6(ip) => (libc::AF_INET6, ip.addr().octets().to_vec()),
        };
        msg.family = family as u8;
        msg.dst_len = dst.prefix_len();

        attrs.push(Box::new(NetlinkRouteAttr::new(libc::RTA_DST, dst_data)));
    }

    if let Some(src) = route.src {
        let (family, src_data) = match src {
            IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
            IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
        };

        if msg.family == 0 {
            msg.family = family as u8;
        } else if msg.family != family as u8 {
            bail!("src and dst address family mismatch");
        }

        attrs.push(Box::new(NetlinkRouteAttr::new(libc::RTA_PREFSRC, src_data)));
    }

    if let Some(gw) = route.gw {
        let (family, gw_data) = match gw {
            IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
            IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
        };

        if msg.family == 0 {
            msg.family = family as u8;
        } else if msg.family != family as u8 {
            bail!("gw, src and dst address family mismatch");
        }

        attrs.push(Box::new(NetlinkRouteAttr::new(libc::RTA_GATEWAY, gw_data)));
    }

    // TODO: more attributes to be added

    msg.flags = route.flags;
    msg.scope = route.scope;

    req.add_data(msg);

    for attr in attrs {
        req.add_data(attr);
    }

    Ok(req)
}

pub fn route_get(dst: &IpAddr) -> Result<NetlinkRequest> {
    let mut req = NetlinkRequest::new(libc::RTM_GETROUTE, libc::NLM_F_REQUEST);
    let (family, dst_data, bit_len) = match dst {
        IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec(), 32),
        IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec(), 128),
    };

    let mut msg = Box::new(RouteMessage {
        ..Default::default()
    });

    msg.family = family as u8;
    msg.dst_len = bit_len;
    msg.flags = libc::RTM_F_LOOKUP_TABLE;

    let rta_dst = Box::new(NetlinkRouteAttr::new(libc::RTA_DST, dst_data));

    req.add_data(msg);
    req.add_data(rta_dst);

    Ok(req)
}
