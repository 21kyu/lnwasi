use std::{collections::HashMap, net::IpAddr};

use anyhow::Result;

use crate::{
    addr::{AddrCmd, AddrFamily, Address},
    handle::SocketHandle,
    link::{Link, LinkAttrs},
    route::{Route, RtCmd, RtFilter},
};

const SUPPORTED_PROTOCOLS: [i32; 1] = [libc::NETLINK_ROUTE];

/// A Netlink instance.
/// This struct contains all the sockets for the supported protocols.
pub struct Netlink {
    /// A map of protocol to socket.
    pub sockets: HashMap<i32, SocketHandle>,
}

impl Netlink {
    /// Create a new Netlink instance.
    /// This function creates a new socket for each supported protocol.
    /// Currently, only `NETLINK_ROUTE` is supported.
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::netlink::Netlink;
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let nl = Netlink::new().unwrap();
    /// assert_eq!(nl.sockets.len(), 1);
    /// ```
    pub fn new() -> Result<Self> {
        let sockets = SUPPORTED_PROTOCOLS
            .iter()
            .map(|proto| Ok((*proto, SocketHandle::new(*proto)?)))
            .collect::<Result<HashMap<i32, SocketHandle>>>()?;

        Ok(Self { sockets })
    }

    /// Get a link device from the system.
    /// This function returns a boxed link.
    ///
    /// Equivalent to: `ip link show $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    ///
    /// let link = nl.link_get(&attr).unwrap();
    /// assert_eq!(link.attrs().name, "lo");
    /// assert_eq!(link.attrs().index, 1);
    /// ```
    pub fn link_get(&mut self, attr: &LinkAttrs) -> Result<Box<dyn Link>> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .link_get(attr)
    }

    /// Add a new link device to the system.
    ///
    /// Equivalent to: `ip link add $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("foo");
    /// let dummy = Kind::Dummy(attr);
    ///
    /// nl.link_add(&dummy).unwrap();
    ///
    /// let link = nl.link_get(dummy.attrs()).unwrap();
    /// assert_eq!(link.attrs().name, "foo");
    /// assert_eq!(link.link_type(), "dummy");
    /// ```
    pub fn link_add(&mut self, link: &(impl Link + ?Sized)) -> Result<()> {
        let flags = libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK;
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .link_new(link, flags)
    }

    /// Update a link in the system.
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("foo");
    /// let dummy = Kind::Dummy(attr);
    ///
    /// nl.link_add(&dummy).unwrap();
    ///
    /// let mut link = nl.link_get(dummy.attrs()).unwrap();
    /// link.attrs_mut().mtu = 3500;
    ///
    /// nl.link_modify(&link).unwrap();
    ///
    /// let link = nl.link_get(dummy.attrs()).unwrap();
    /// assert_eq!(link.attrs().mtu, 3500);
    /// ```
    pub fn link_modify(&mut self, link: &(impl Link + ?Sized)) -> Result<()> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .link_new(link, libc::NLM_F_ACK)
    }

    /// Delete a link from the system.
    /// Either the index or name must be set in the link attributes.
    ///
    /// Equivalent to: `ip link del $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr_foo = LinkAttrs::new("foo");
    /// let attr_bar = LinkAttrs::new("bar");
    /// let dummy_foo = Kind::Dummy(attr_foo);
    /// let dummy_bar = Kind::Dummy(attr_bar);
    ///
    /// nl.link_add(&dummy_foo).unwrap();
    /// nl.link_del(&dummy_foo).unwrap();
    /// assert!(nl.link_get(dummy_foo.attrs()).is_err());
    ///
    /// nl.link_add(&dummy_bar).unwrap();
    /// let link = nl.link_get(dummy_bar.attrs()).unwrap();
    /// nl.link_del(&link).unwrap();
    /// assert!(nl.link_get(dummy_bar.attrs()).is_err());
    /// ```
    pub fn link_del(&mut self, link: &(impl Link + ?Sized)) -> Result<()> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .link_del(link.attrs())
    }

    /// Set up a link in the system.
    ///
    /// Equivalent to: `ip link set $link up`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let br = Kind::Bridge {
    ///     attrs: LinkAttrs::new("foo"),
    ///     hello_time: None,
    ///     ageing_time: None,
    ///     multicast_snooping: None,
    ///     vlan_filtering: None,
    /// };
    ///
    /// nl.link_add(&br).unwrap();
    /// nl.link_setup(&br).unwrap();
    ///
    /// let br = nl.link_get(br.attrs()).unwrap();
    /// assert_eq!(br.attrs().flags & libc::IFF_UP as u32, 1);
    /// assert_ne!(br.attrs().oper_state, 2);
    /// ```
    pub fn link_setup(&mut self, link: &(impl Link + ?Sized)) -> Result<()> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .link_setup(link.attrs())
    }

    /// Get a list of IP addresses in the system.
    /// The list can be filtered by link and address family.
    ///
    /// Equivalent to: `ip addr show $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    /// let address = "127.0.0.2/32".parse().unwrap();
    /// let addr = Address::new(address);
    ///
    /// nl.addr_add(&lo, &addr).unwrap();
    ///
    /// let addrs = nl.addr_list(&lo, AddrFamily::All).unwrap();
    /// assert_eq!(addrs.len(), 1);
    /// ```
    pub fn addr_list(
        &mut self,
        link: &(impl Link + ?Sized),
        family: AddrFamily,
    ) -> Result<Vec<Address>> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .addr_list(link, family)
    }

    /// Add an IP address to a link device.
    ///
    /// Equivalent to: `ip addr add $addr dev $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    /// let address = "127.0.0.2/32".parse().unwrap();
    /// let addr = Address::new(address);
    ///
    /// nl.addr_add(&lo, &addr).unwrap();
    ///
    /// let addrs = nl.addr_list(&lo, AddrFamily::All).unwrap();
    /// assert_eq!(addrs.len(), 1);
    /// assert_eq!(addrs[0].address, addr.address);
    /// ```
    pub fn addr_add(&mut self, link: &(impl Link + ?Sized), addr: &Address) -> Result<()> {
        self.addr_handle(AddrCmd::Add, link, addr)
    }

    /// Replace an IP address on a link device.
    /// If the address does not exist, it will be added.
    ///
    /// Equivalent to: `ip addr replace $addr dev $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    /// let address = "127.0.0.2/32".parse().unwrap();
    /// let addr = Address::new(address);
    ///
    /// nl.addr_add(&lo, &addr).unwrap();
    ///
    /// let addrs = nl.addr_list(&lo, AddrFamily::All).unwrap();
    /// assert_eq!(addrs.len(), 1);
    ///
    /// nl.addr_replace(&lo, &addr).unwrap();
    ///
    /// let addrs = nl.addr_list(&lo, AddrFamily::All).unwrap();
    /// assert_eq!(addrs.len(), 1);
    /// ```
    pub fn addr_replace(&mut self, link: &(impl Link + ?Sized), addr: &Address) -> Result<()> {
        self.addr_handle(AddrCmd::Replace, link, addr)
    }

    /// Delete an IP address from a link device.
    ///
    /// Equivalent to: `ip addr del $addr dev $link`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attrs = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attrs).unwrap();
    /// let address = "127.0.0.2/32".parse().unwrap();
    /// let addr = Address::new(address);
    ///
    /// nl.addr_add(&lo, &addr).unwrap();
    ///
    /// let addrs = nl.addr_list(&lo, AddrFamily::All).unwrap();
    /// assert_eq!(addrs.len(), 1);
    ///
    /// nl.addr_del(&lo, &addr).unwrap();
    ///
    /// let addrs = nl.addr_list(&lo, AddrFamily::All).unwrap();
    /// assert_eq!(addrs.len(), 0);
    /// ```
    pub fn addr_del(&mut self, link: &(impl Link + ?Sized), addr: &Address) -> Result<()> {
        self.addr_handle(AddrCmd::Del, link, addr)
    }

    fn addr_handle(
        &mut self,
        cmd: AddrCmd,
        link: &(impl Link + ?Sized),
        addr: &Address,
    ) -> Result<()> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .addr_handle(cmd, link.attrs(), addr)
    }

    /// Get a list of routes for a given destination.
    ///
    /// Equivalent to: `ip route get $dst`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}, route::Route};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    ///
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    /// nl.link_setup(&lo).unwrap();
    ///
    /// let dst = "127.0.0.1".parse().unwrap();
    /// let routes = nl.route_get(&dst).unwrap();
    /// assert_eq!(routes.len(), 1);
    /// ```
    pub fn route_get(&mut self, dst: &IpAddr) -> Result<Vec<Route>> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .route_get(dst)
    }

    /// Get a list of routes in the system.
    /// The list can be filtered by link and address family.
    ///
    /// Equivalent to: `ip route show`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}, route::Route};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    ///
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    ///
    /// nl.link_setup(&lo).unwrap();
    ///
    /// let routes = nl.route_list(&lo, AddrFamily::All).unwrap();
    /// assert!(routes.len() > 0);
    /// ```
    pub fn route_list(
        &mut self,
        link: &(impl Link + ?Sized),
        family: AddrFamily,
    ) -> Result<Vec<Route>> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .route_list(family, link.attrs().index, RtFilter::Oif)
    }

    /// Add a route to the system.
    ///
    /// Equivalent to: `ip route add $route`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}, route::Route};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    ///
    /// nl.link_setup(&lo).unwrap();
    ///
    /// let route = Route {
    ///     oif_index: lo.attrs().index,
    ///     dst: Some("192.168.0.0/24".parse().unwrap()),
    ///     src: Some("127.1.1.1".parse().unwrap()),
    ///     ..Default::default()
    /// };
    ///
    /// nl.route_add(&route).unwrap();
    ///
    /// let routes = nl.route_get(&route.dst.unwrap().addr()).unwrap();
    /// assert_eq!(routes.len(), 1);
    /// assert_eq!(routes[0].oif_index, lo.attrs().index);
    /// assert_eq!(routes[0].dst.unwrap().network(), route.dst.unwrap().network());
    /// ```
    pub fn route_add(&mut self, route: &Route) -> Result<()> {
        self.route_handle(RtCmd::Add, route)
    }

    /// Append a route to the system.
    ///
    /// Equivalent to: `ip route append $route`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}, route::Route};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    ///
    /// nl.link_setup(&lo).unwrap();
    ///
    /// let mut route = Route {
    ///    oif_index: lo.attrs().index,
    ///    dst: Some("192.168.0.0/24".parse().unwrap()),
    ///    src: Some("127.1.1.1".parse().unwrap()),
    ///    ..Default::default()
    /// };
    ///
    /// nl.route_add(&route).unwrap();
    ///
    /// let link = nl.link_get(&attr).unwrap();
    ///
    /// let routes = nl.route_list(&link, AddrFamily::All).unwrap();
    /// let route_cnt = routes.len();
    ///
    /// route.src = Some("127.1.1.2".parse().unwrap());
    /// nl.route_append(&route).unwrap();
    ///
    /// let routes = nl.route_list(&link, AddrFamily::All).unwrap();
    /// assert_eq!(routes.len(), route_cnt + 1);
    /// ```
    pub fn route_append(&mut self, route: &Route) -> Result<()> {
        self.route_handle(RtCmd::Append, route)
    }

    /// Replace a route in the system.
    ///
    /// Equivalent to: `ip route replace $route`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}, route::Route};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    ///
    /// nl.link_setup(&lo).unwrap();
    ///
    /// let mut route = Route {
    ///    oif_index: lo.attrs().index,
    ///    dst: Some("192.168.0.0/24".parse().unwrap()),
    ///    src: Some("127.1.1.1".parse().unwrap()),
    ///    ..Default::default()
    /// };
    ///
    /// nl.route_add(&route).unwrap();
    ///
    /// let routes = nl.route_list(&lo, AddrFamily::V4).unwrap();
    /// let route_cnt = routes.len();
    ///
    /// route.src = Some("127.1.1.2".parse().unwrap());
    /// nl.route_replace(&route).unwrap();
    ///
    /// let routes = nl.route_list(&lo, AddrFamily::V4).unwrap();
    /// assert_eq!(routes.len(), route_cnt);
    /// ```
    pub fn route_replace(&mut self, route: &Route) -> Result<()> {
        self.route_handle(RtCmd::Replace, route)
    }

    /// Delete a route from the system.
    ///
    /// Equivalent to: `ip route del $route`
    ///
    /// # Examples
    ///
    /// ```
    /// use lnwasi::{link::{Kind, Link, LinkAttrs}, netlink::Netlink, addr::{Address, AddrFamily}, route::Route};
    /// # use lnwasi::test_setup;
    ///
    /// # test_setup!();
    /// let mut nl = Netlink::new().unwrap();
    /// let attr = LinkAttrs::new("lo");
    /// let lo = nl.link_get(&attr).unwrap();
    ///
    /// nl.link_setup(&lo).unwrap();
    ///
    /// let mut route = Route {
    ///    oif_index: lo.attrs().index,
    ///    dst: Some("192.168.0.0/24".parse().unwrap()),
    ///    src: Some("127.1.1.1".parse().unwrap()),
    ///    ..Default::default()
    /// };
    ///
    /// nl.route_add(&route).unwrap();
    ///
    /// let routes = nl.route_list(&lo, AddrFamily::V4).unwrap();
    /// let route_cnt = routes.len();
    ///
    /// nl.route_del(&route).unwrap();
    ///
    /// let routes = nl.route_list(&lo, AddrFamily::V4).unwrap();
    /// assert_eq!(routes.len(), route_cnt - 1);
    /// ```
    pub fn route_del(&mut self, route: &Route) -> Result<()> {
        self.route_handle(RtCmd::Del, route)
    }

    fn route_handle(&mut self, cmd: RtCmd, route: &Route) -> Result<()> {
        self.sockets
            .entry(libc::NETLINK_ROUTE)
            .or_insert(SocketHandle::new(libc::NETLINK_ROUTE)?)
            .route_handle(cmd, route)
    }
}

#[cfg(test)]
mod tests {
    use crate::{link::Kind, test_setup};

    use super::*;

    #[test]
    fn test_link_add_modify_del() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let dummy = Kind::Dummy(LinkAttrs {
            name: "foo".to_string(),
            ..Default::default()
        });

        netlink.link_add(&dummy).unwrap();

        let mut link = netlink.link_get(dummy.attrs()).unwrap();
        assert_eq!(link.attrs().name, "foo");
        assert_eq!(link.link_type(), "dummy");

        link.attrs_mut().name = "bar".to_string();
        netlink.link_modify(&link).unwrap();

        let link = netlink.link_get(link.attrs()).unwrap();
        assert_eq!(link.attrs().name, "bar");

        netlink.link_del(&link).unwrap();

        let link = netlink.link_get(link.attrs()).err();
        assert!(link.is_some());
    }

    #[test]
    fn test_addr_get() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let lo = netlink.link_get(&LinkAttrs::new("lo")).unwrap();

        let addr = Address {
            address: "127.0.0.2/32".parse().unwrap(),
            ..Default::default()
        };

        netlink.addr_add(&lo, &addr).unwrap();

        let addrs = netlink.addr_list(&lo, AddrFamily::All).unwrap();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn test_addr_add_replace_del() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let dummy = Kind::Dummy(LinkAttrs {
            name: "foo".to_string(),
            ..Default::default()
        });

        netlink.link_add(&dummy).unwrap();

        let link = netlink.link_get(dummy.attrs()).unwrap();

        let mut addr = Address {
            address: "127.0.0.2/24".parse().unwrap(),
            ..Default::default()
        };

        netlink.addr_add(&link, &addr).unwrap();

        let res = netlink.addr_list(&link, AddrFamily::All).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].address, addr.address);

        addr.address = "127.0.0.3/24".parse().unwrap();

        netlink.addr_replace(&link, &addr).unwrap();

        let res = netlink.addr_list(&link, AddrFamily::All).unwrap();

        assert_eq!(res.len(), 2);
        assert_eq!(res[1].address, addr.address);

        netlink.addr_del(&link, &addr).unwrap();

        let res = netlink.addr_list(&link, AddrFamily::All).unwrap();
        assert_eq!(res.len(), 1);
    }

    #[test]
    fn test_setup_veth() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let mut attr = LinkAttrs::new("foo");
        attr.mtu = 1400;
        attr.tx_queue_len = 100;
        attr.num_tx_queues = 4;
        attr.num_rx_queues = 8;
        attr.flags = 1;

        // TODO: need to set peer hw addr and peer ns
        let link = Kind::Veth {
            attrs: attr.clone(),
            peer_name: "bar".to_string(),
            peer_hw_addr: None,
            peer_ns: None,
        };

        let bar_attr = LinkAttrs::new("bar");

        netlink.link_add(&link).unwrap();
        let link = netlink.link_get(&attr).unwrap();

        let bar = netlink.link_get(&bar_attr).unwrap();

        netlink.link_setup(&link).unwrap();

        let link = netlink.link_get(&attr).unwrap();
        assert_ne!(link.attrs().oper_state, 2);

        netlink.link_setup(&bar).unwrap();

        let bar = netlink.link_get(&bar_attr).unwrap();
        assert_ne!(bar.attrs().oper_state, 2);
    }

    #[test]
    fn test_setup_bridge() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let link = Kind::Bridge {
            attrs: LinkAttrs::new("foo"),
            hello_time: None,
            ageing_time: None,
            multicast_snooping: None,
            vlan_filtering: None,
        };

        netlink.link_add(&link).unwrap();

        let link = netlink.link_get(&LinkAttrs::new("foo")).unwrap();

        netlink.link_setup(&link).unwrap();

        let link = netlink.link_get(&LinkAttrs::new("foo")).unwrap();
        assert_ne!(link.attrs().oper_state, 2);
    }

    #[test]
    fn test_route_get() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let attr = LinkAttrs::new("lo");

        let link = netlink.link_get(&attr).unwrap();

        netlink.link_setup(&link).unwrap();

        let dst = "127.0.0.1".parse().unwrap();

        let res = netlink.route_get(&dst).unwrap();

        assert_eq!(res.len(), 1);
    }

    #[test]
    fn test_route_append() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let attr = LinkAttrs::new("lo");

        let link = netlink.link_get(&attr).unwrap();

        netlink.link_setup(&link).unwrap();

        let mut route = Route {
            oif_index: link.attrs().index,
            dst: Some("192.168.0.0/24".parse().unwrap()),
            src: Some("127.1.1.1".parse().unwrap()),
            ..Default::default()
        };

        netlink.route_add(&route).unwrap();

        let res = netlink.route_list(&link, AddrFamily::All).unwrap();
        let route_cnt = res.len();

        route.src = Some("127.1.1.2".parse().unwrap());

        netlink.route_append(&route).unwrap();

        let res = netlink.route_list(&link, AddrFamily::All).unwrap();
        assert_eq!(res.len(), route_cnt + 1);
    }

    #[test]
    fn test_route_replace() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let attr = LinkAttrs::new("lo");

        let link = netlink.link_get(&attr).unwrap();

        netlink.link_setup(&link).unwrap();

        let mut route = Route {
            oif_index: link.attrs().index,
            dst: Some("192.168.0.0/24".parse().unwrap()),
            src: Some("127.1.1.1".parse().unwrap()),
            ..Default::default()
        };

        netlink.route_add(&route).unwrap();

        let res = netlink.route_list(&link, AddrFamily::V4).unwrap();
        let route_cnt = res.len();

        route.src = Some("127.1.1.2".parse().unwrap());

        netlink.route_replace(&route).unwrap();

        let res = netlink.route_list(&link, AddrFamily::V4).unwrap();

        assert_eq!(res.len(), route_cnt);
        assert!(res
            .into_iter()
            .filter(|r| r.dst.unwrap() == route.dst.unwrap())
            .all(|r| r.src.unwrap() == route.src.unwrap()));
    }

    #[test]
    fn test_route_add_del() {
        test_setup!();
        let mut netlink = Netlink::new().unwrap();

        let attr = LinkAttrs {
            name: "lo".to_string(),
            ..Default::default()
        };

        let link = netlink.link_get(&attr).unwrap();

        netlink.link_setup(&link).unwrap();

        let route = Route {
            oif_index: link.attrs().index,
            dst: Some("192.168.0.0/24".parse().unwrap()),
            src: Some("127.1.1.1".parse().unwrap()),
            ..Default::default()
        };

        netlink.route_add(&route).unwrap();

        let res = netlink.route_get(&route.dst.unwrap().addr()).unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].oif_index, link.attrs().index);
        assert_eq!(res[0].dst.unwrap().network(), route.dst.unwrap().network());

        netlink.route_del(&route).unwrap();

        let res = netlink.route_get(&route.dst.unwrap().addr()).err();
        assert!(res.is_some());
    }
}
