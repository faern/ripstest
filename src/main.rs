extern crate rips;
extern crate pnet;

use std::thread;
use std::time::Duration;
use std::net::Ipv4Addr;

use pnet::util::MacAddr;
use pnet::packet::ethernet::EtherType;

use rips::NetworkStack;

fn main() {
    println!("Hello, world!");
    let ifaces = rips::get_network_interfaces();
    let mut iface = None;
    for curr_iface in ifaces.into_iter() {
        println!("iface: {:?}", curr_iface);
        if curr_iface.name == "en0" {
            iface = Some(curr_iface);
        }
    }
    let iface = iface.unwrap();
    let mut stack = NetworkStack::new(vec![iface.clone()])
                        .expect("Expected a working NetworkStack");
    // let ethernet = stack.get_ethernet(&iface).expect("Expected Ethernet");
    // let mut i = 1;
    // ethernet.send(5, 20, |pkg| {
    //     pkg.set_source(MacAddr::new(0x10, 0x11, 0x12, 0x13, 0x14, 0x15));
    //     pkg.set_destination(MacAddr::new(5, 6, 7, 8, 9, 4));
    //     pkg.set_ethertype(EtherType::new(0x1337));
    //     pkg.set_payload(vec![i, i + 1]);
    //     i += 1
    // });

    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let arp = stack.get_arp(&iface).expect("Expected arp");
    {
        let mut arp = arp.lock().unwrap();
        let mac = arp.get(&ip);
        println!("MAC {} belongs to {}", mac, ip);
    }

    thread::sleep(Duration::new(1, 0));
}
