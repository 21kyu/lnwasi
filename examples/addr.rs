use lnwasi::{
    addr::{self, Address},
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

    let link = netlink.link_get(dummy.attrs()).unwrap();

    let mut addr = Address {
        address: "127.0.0.2/24".parse().unwrap(),
        ..Default::default()
    };

    netlink.addr_add(&link, &addr).unwrap();

    let result = netlink.addr_list(&link, addr::AddrFamily::All).unwrap();
    println!("{:?}", result);

    addr.address = "127.0.0.3/24".parse().unwrap();

    netlink.addr_replace(&link, &addr).unwrap();

    let result = netlink.addr_list(&link, addr::AddrFamily::All).unwrap();
    println!("{:?}", result);

    netlink.addr_del(&link, &addr).unwrap();

    let result = netlink.addr_list(&link, addr::AddrFamily::All).unwrap();
    println!("{:?}", result);
}
