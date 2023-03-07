use std::net::IpAddr;

use anyhow::{bail, Result};

use crate::{
    addr::{self, AddrCmd, AddrFamily, Address},
    consts,
    link::{self, Link, LinkAttrs},
    request::NetlinkRequest,
    route::{self, Route, RtCmd, RtFilter},
    socket::NetlinkSocket,
};

pub struct SocketHandle {
    pub seq: u32,
    pub socket: NetlinkSocket,
}

impl SocketHandle {
    pub fn new(protocol: i32) -> Result<Self> {
        Ok(Self {
            seq: 0,
            socket: NetlinkSocket::new(protocol, 0, 0)?,
        })
    }

    pub fn link_new(&mut self, link: &(impl Link + ?Sized), flags: i32) -> Result<()> {
        let mut req = link::link_new(link, flags)?;
        let _ = self.execute(&mut req, 0)?;

        if link.attrs().master_index != 0 {
            let index = self.ensure_index(link.attrs())?;
            let mut req = link::link_set_master(index, link.attrs().master_index)?;
            let _ = self.execute(&mut req, 0)?;
        }

        Ok(())
    }

    pub fn link_del(&mut self, attrs: &LinkAttrs) -> Result<()> {
        let index = self.ensure_index(attrs)?;
        let mut req = link::link_del(index)?;
        let _ = self.execute(&mut req, 0)?;
        Ok(())
    }

    pub fn link_get(&mut self, attrs: &LinkAttrs) -> Result<Box<dyn Link>> {
        let mut req = link::link_get(attrs)?;
        let msgs = self.execute(&mut req, 0)?;

        match msgs.len() {
            0 => bail!("no link found"),
            1 => link::link_deserialize(&msgs[0]),
            _ => bail!("multiple links found"),
        }
    }

    pub fn link_setup(&mut self, attrs: &LinkAttrs) -> Result<()> {
        let index = self.ensure_index(attrs)?;
        let mut req = link::link_setup(index)?;
        let _ = self.execute(&mut req, 0)?;
        Ok(())
    }

    pub fn addr_handle(&mut self, cmd: AddrCmd, attrs: &LinkAttrs, addr: &Address) -> Result<()> {
        let index = self.ensure_index(attrs)?;
        let mut req = addr::addr_handle(cmd, index, addr)?;
        let _ = self.execute(&mut req, 0)?;
        Ok(())
    }

    pub fn addr_list(
        &mut self,
        link: &(impl Link + ?Sized),
        family: AddrFamily,
    ) -> Result<Vec<Address>> {
        let mut req = addr::addr_list(family)?;

        Ok(self
            .execute(&mut req, libc::RTM_NEWADDR)?
            .into_iter()
            .filter_map(|m| addr::addr_deserialize(&m).ok())
            .filter(|addr| addr.index == link.attrs().index)
            .collect())
    }

    pub fn route_handle(&mut self, cmd: RtCmd, route: &Route) -> Result<()> {
        let mut req = route::route_handle(cmd, route)?;
        let _ = self.execute(&mut req, 0)?;
        Ok(())
    }

    pub fn route_get(&mut self, dst: &IpAddr) -> Result<Vec<Route>> {
        let mut req = route::route_get(dst)?;

        Ok(self
            .execute(&mut req, libc::RTM_NEWROUTE)?
            .into_iter()
            .filter_map(|m| route::route_deserialize(&m).ok())
            .collect())
    }

    pub fn route_list(
        &mut self,
        family: AddrFamily,
        index: i32,
        filter_mask: RtFilter,
    ) -> Result<Vec<Route>> {
        let route = Route {
            family: family as u8,
            oif_index: index,
            ..Default::default()
        };

        let mut req = route::route_handle(RtCmd::Show, &route)?;

        Ok(self
            .execute(&mut req, 0)?
            .into_iter()
            .filter_map(|m| route::route_deserialize(&m).ok())
            .filter(|route| match filter_mask {
                RtFilter::Oif => route.oif_index == index,
                RtFilter::None => true,
            })
            .collect())
    }

    fn ensure_index(&mut self, attrs: &LinkAttrs) -> Result<i32> {
        Ok(match attrs.index {
            0 => self.link_get(attrs)?.attrs().index,
            _ => attrs.index,
        })
    }

    fn execute(&mut self, req: &mut NetlinkRequest, res_type: u16) -> Result<Vec<Vec<u8>>> {
        req.header.nlmsg_seq = {
            self.seq += 1;
            self.seq
        };

        let buf = req.serialize()?;

        self.socket.send(&buf)?;

        let pid = self.socket.pid()?;
        let mut res: Vec<Vec<u8>> = Vec::new();

        'done: loop {
            let (msgs, from) = self.socket.recv()?;

            if from.nl_pid != consts::PID_KERNEL {
                bail!(
                    "wrong sender pid: {}, expected: {}",
                    from.nl_pid,
                    consts::PID_KERNEL
                );
            }

            for m in msgs {
                if m.header.nlmsg_seq != req.header.nlmsg_seq {
                    continue;
                }

                if m.header.nlmsg_pid != pid {
                    continue;
                }

                match m.header.nlmsg_type {
                    consts::NLMSG_DONE | consts::NLMSG_ERROR => {
                        let err_no = i32::from_ne_bytes(m.data[0..4].try_into()?);

                        if err_no == 0 {
                            break 'done;
                        }

                        let err_msg = unsafe { std::ffi::CStr::from_ptr(libc::strerror(-err_no)) };
                        bail!("{} ({}): {:?}", err_msg.to_str()?, -err_no, &m.data[4..]);
                    }
                    t if res_type != 0 && t != res_type => {
                        continue;
                    }
                    _ => {
                        res.push(m.data);
                    }
                }

                if m.header.nlmsg_flags & libc::NLM_F_MULTI as u16 == 0 {
                    break 'done;
                }
            }
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        addr,
        link::{self, Kind, LinkAttrs},
        route::{Route, RtCmd},
        test_setup,
    };

    #[test]
    fn test_link_add_modify_del() {
        test_setup!();
        let mut handle = super::SocketHandle::new(libc::NETLINK_ROUTE).unwrap();
        let mut attr = LinkAttrs::new("foo");

        let link = Kind::Dummy(attr.clone());

        handle
            .link_new(
                &link,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            )
            .unwrap();

        let link = handle.link_get(&attr).unwrap();
        assert_eq!(link.attrs().name, "foo");

        attr = link.attrs().clone();
        attr.name = "bar".to_string();

        let link = Kind::Dummy(attr.clone());

        handle.link_new(&link, libc::NLM_F_ACK).unwrap();

        let link = handle.link_get(&attr).unwrap();
        assert_eq!(link.attrs().name, "bar");

        handle.link_del(link.attrs()).unwrap();

        let res = handle.link_get(&attr).err();
        assert!(res.is_some());
    }

    #[test]
    fn test_link_bridge() {
        test_setup!();
        let mut handle = super::SocketHandle::new(libc::NETLINK_ROUTE).unwrap();
        let attr = LinkAttrs::new("foo");

        let link = Kind::Bridge {
            attrs: attr.clone(),
            hello_time: None,
            ageing_time: Some(30102),
            multicast_snooping: None,
            vlan_filtering: Some(true),
        };

        handle
            .link_new(
                &link,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            )
            .unwrap();

        let link = handle.link_get(&attr).unwrap();
        assert_eq!(link.attrs().link_type, "bridge");
        assert_eq!(link.attrs().name, "foo");

        match link.kind() {
            Kind::Bridge {
                attrs: _,
                hello_time,
                ageing_time,
                multicast_snooping,
                vlan_filtering,
            } => {
                assert_eq!(hello_time.unwrap(), 200);
                assert_eq!(ageing_time.unwrap(), 30102);
                assert!(multicast_snooping.unwrap());
                assert!(vlan_filtering.unwrap());
            }
            _ => panic!("wrong link type"),
        }

        handle.link_del(link.attrs()).unwrap();

        let res = handle.link_get(&attr).err();
        assert!(res.is_some());
    }

    #[test]
    fn test_link_veth() {
        test_setup!();
        let mut handle = super::SocketHandle::new(libc::NETLINK_ROUTE).unwrap();

        let attr = LinkAttrs::new("br");
        let link = Kind::Bridge {
            attrs: attr.clone(),
            hello_time: None,
            ageing_time: Some(30102),
            multicast_snooping: None,
            vlan_filtering: Some(true),
        };

        handle
            .link_new(
                &link,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            )
            .unwrap();

        let link = handle.link_get(&attr).unwrap();
        let master_index = link.attrs().index;

        let mut attr = LinkAttrs::new("foo");
        attr.mtu = 1400;
        attr.tx_queue_len = 100;
        attr.num_tx_queues = 4;
        attr.num_rx_queues = 8;
        attr.master_index = master_index;

        // TODO: need to set peer hw addr and peer ns
        let link = Kind::Veth {
            attrs: attr.clone(),
            peer_name: "bar".to_string(),
            peer_hw_addr: None,
            peer_ns: None,
        };

        handle
            .link_new(
                &link,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            )
            .unwrap();

        let link = handle.link_get(&attr).unwrap();

        let peer = handle
            .link_get(&LinkAttrs {
                name: "bar".to_string(),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(link.attrs().link_type, "veth");
        assert_eq!(link.attrs().name, "foo");
        assert_eq!(link.attrs().mtu, 1400);
        assert_eq!(link.attrs().tx_queue_len, 100);
        assert_eq!(link.attrs().num_tx_queues, 4);
        assert_eq!(link.attrs().num_rx_queues, 8);

        assert_eq!(peer.attrs().link_type, "veth");
        assert_eq!(peer.attrs().name, "bar");
        assert_eq!(peer.attrs().mtu, 1400);
        assert_eq!(peer.attrs().tx_queue_len, 100);
        assert_eq!(peer.attrs().num_tx_queues, 4);
        assert_eq!(peer.attrs().num_rx_queues, 8);

        handle.link_del(peer.attrs()).unwrap();

        let res = handle.link_get(&attr).err();
        assert!(res.is_some());
    }

    #[test]
    fn test_link_get() {
        test_setup!();
        let mut handle = super::SocketHandle::new(libc::NETLINK_ROUTE).unwrap();
        let attr = link::LinkAttrs::new("lo");

        let link = handle.link_get(&attr).unwrap();

        assert_eq!(link.attrs().index, 1);
        assert_eq!(link.attrs().name, "lo");
    }

    #[test]
    fn test_addr_handle() {
        test_setup!();
        let mut handle = super::SocketHandle::new(libc::NETLINK_ROUTE).unwrap();
        let attr = link::LinkAttrs::new("lo");

        let link = handle.link_get(&attr).unwrap();

        let address = "127.0.0.2/24".parse().unwrap();
        let addr = addr::Address {
            address,
            ..Default::default()
        };

        handle
            .addr_handle(addr::AddrCmd::Add, link.attrs(), &addr)
            .unwrap();

        let addrs = handle.addr_list(&link, addr::AddrFamily::All).unwrap();

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].address, address);
    }

    #[test]
    fn test_route_handle() {
        test_setup!();
        let mut handle = super::SocketHandle::new(libc::NETLINK_ROUTE).unwrap();
        let attr = link::LinkAttrs::new("lo");

        let link = handle.link_get(&attr).unwrap();

        handle.link_setup(link.attrs()).unwrap();

        let route = Route {
            oif_index: link.attrs().index,
            dst: Some("192.168.0.0/24".parse().unwrap()),
            src: Some("127.0.0.2".parse().unwrap()),
            ..Default::default()
        };

        handle.route_handle(RtCmd::Add, &route).unwrap();

        let routes = handle.route_get(&route.dst.unwrap().addr()).unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].oif_index, link.attrs().index);
        assert_eq!(
            routes[0].dst.unwrap().network(),
            route.dst.unwrap().network()
        );

        handle.route_handle(RtCmd::Del, &route).unwrap();

        let res = handle.route_get(&route.dst.unwrap().addr()).err();
        assert!(res.is_some());
    }
}
