# lnwasi
A netlink library for web assembly written in Rust.
This project is heavily inspired by [vishvananda/netlink](https://github.com/vishvananda/netlink)
and exposes a high level API for interacting with the kernel's netlink interface,
similarly to the `iproute2` command line tool.
Ultimately, the goal is to make the library available in a **web assembly** environment as well.

## Examples

Add a new dummy link and modify its name:

```rust
use anyhow::Result;
use lnwasi::{
    link::{Kind, Link, LinkAttrs},
    netlink::Netlink,
};

fn main() {
    let mut netlink = Netlink::new().unwrap();

    let dummy = Kind::Dummy(LinkAttrs {
        name: "foo".to_string(),
        ..Default::default()
    });

    netlink.link_add(&dummy).unwrap();

    let mut link = netlink.link_get(dummy.attrs()).unwrap();

    link.attrs_mut().name = "bar".to_string();
    netlink.link_modify(&link).unwrap();

    let link = netlink.link_get(link.attrs()).unwrap();

    netlink.link_del(&link).unwrap();
}
```

## Supported commands

### Link

- [x] ip link show $link
- [x] ip link add $link
- [x] ip link del $link
- [x] ip link set $link up

### Address

- [x] ip addr show $link
- [x] ip addr add $addr dev $link
- [x] ip addr replace $addr dev $link
- [x] ip addr del $addr dev $link

### Route

- [x] ip route get $dst
- [x] ip route show $link
- [x] ip route add $route
- [x] ip route append $route
- [x] ip route replace $route
- [x] ip route del $route
