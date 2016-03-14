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
    let eth = stack.get_ethernet(&iface).expect("Expected Ethernet");
    {
        let mut eth = eth.lock().unwrap();
        let mut i = 1;
        eth.send(5, 20, |pkg| {
            pkg.set_source(MacAddr::new(0x10, 0x11, 0x12, 0x13, 0x14, 0x15));
            pkg.set_destination(MacAddr::new(5, 6, 7, 8, 9, 4));
            pkg.set_ethertype(EtherType::new(0x1337));
            pkg.set_payload(vec![i, i + 1]);
            i += 1
        });
    }

    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
    let arp = stack.get_arp(&iface).expect("Expected arp");
    {
        let mut arp = arp.lock().unwrap();
        let mac = arp.get(&dst_ip);
        println!("MAC {} belongs to {}", mac, dst_ip);
        let mac2 = arp.get(&dst_ip);
        println!("Second time MAC {} belongs to {}", mac2, dst_ip);
    }

    let ipv4 = stack.get_ipv4(&iface).expect("Expected ipv4");
    {
        let mut ipv4 = ipv4.lock().unwrap();
        ipv4.send(&dst_ip, 10, |pkg| {
            pkg.set_payload(vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]);
        });
    }

    thread::sleep(Duration::new(1, 0));
}
