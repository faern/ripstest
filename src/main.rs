extern crate rips;
extern crate pnet;

use std::thread;
use std::time::Duration;
use std::net::{Ipv4Addr, IpAddr};

use pnet::util::{self, MacAddr};
use pnet::packet::ethernet::EtherType;

use rips::NetworkStackBuilder;
use rips::ipv4;

fn main() {
    println!("Hello, world!");
    let ifaces = util::get_network_interfaces();
    let mut iface = None;
    for curr_iface in ifaces.into_iter() {
        println!("iface: {:?}", curr_iface);
        if curr_iface.name == "en0" {
            iface = Some(curr_iface);
        }
    }
    let iface = iface.unwrap();
    let mut stack = NetworkStackBuilder::new()
                        .set_interfaces(vec![iface.clone()])
                        .create()
                        .expect("Expected a working NetworkStack");
    let eth = stack.get_ethernet(&iface).expect("Expected Ethernet");
    {
        let mut eth = eth.lock().unwrap();
        let mut i = 1;
        eth.send(5, 20, |pkg| {
            pkg.set_source(MacAddr::new(0x10, 0x11, 0x12, 0x13, 0x14, 0x15));
            pkg.set_destination(MacAddr::new(5, 6, 7, 8, 9, 4));
            pkg.set_ethertype(EtherType::new(0x1337));
            pkg.set_payload(&[i, i + 1]);
            i += 1
        });
    }

    let my_ip = iface.ips
                     .as_ref()
                     .unwrap()
                     .iter()
                     .filter_map(|&i| {
                         match i {
                             IpAddr::V4(ip) => Some(ip),
                             _ => None,
                         }
                     })
                     .next()
                     .expect("No IPv4 addr to use");

    // Figure out the GW addr in an ugly way. Not guaranteed to be correct
    let dst_ip = Ipv4Addr::new(my_ip.octets()[0], my_ip.octets()[1], my_ip.octets()[2], 1);

    let arp = stack.get_arp(&iface).expect("Expected arp");
    {
        let mut arp = arp.lock().unwrap();
        println!("Asking for MAC for {}", dst_ip);
        let mac = arp.get(&dst_ip);
        println!("MAC {} belongs to {}", mac, dst_ip);
        let mac2 = arp.get(&dst_ip);
        println!("Second time MAC {} belongs to {}", mac2, dst_ip);
    }

    let ipv4_conf = ipv4::Ipv4Conf::new(my_ip, 24, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    let ipv4_iface = stack.add_ipv4(&iface, ipv4_conf).expect("Expected ipv4");
    {
        let ipv4 = ipv4_iface.lock().unwrap();
        ipv4.send(dst_ip, 10, |pkg| {
            pkg.set_payload(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]);
        });
    }

    thread::sleep(Duration::new(1, 0));
}
