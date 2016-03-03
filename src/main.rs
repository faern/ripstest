extern crate rips;
extern crate pnet;

use std::thread;
use std::time::Duration;

use pnet::util::MacAddr;
use pnet::packet::ethernet::EtherType;

use rips::NetworkStack;

fn main() {
    println!("Hello, world!");
    let ifaces = NetworkStack::get_network_interfaces();
    let mut lo = None;
    for iface in ifaces.into_iter() {
        println!("iface: {:?}", iface);
        if iface.is_loopback() {
            lo = Some(iface);
        }
    }
    let lo = lo.unwrap();
    let mut stack = NetworkStack::new(vec![lo.clone()]).expect("Expected a working NetworkStack");
    let mut i = 1;
    stack.send_ethernet(&lo, 5, 20, |pkg| {
        pkg.set_source(MacAddr::new(0x10, 0x11, 0x12, 0x13, 0x14, 0x15));
        pkg.set_destination(MacAddr::new(5, 6, 7, 8, 9, 4));
        pkg.set_ethertype(EtherType::new(0x1337));
        pkg.set_payload(vec![i, i + 1]);
        i += 1
    });

    thread::sleep(Duration::new(1, 0));
}
