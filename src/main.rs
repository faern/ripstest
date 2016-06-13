extern crate clap;
extern crate rips;
extern crate pnet;

use std::thread;
use std::process;
use std::time::Duration;
use std::net::{Ipv4Addr, IpAddr};

use std::str::FromStr;

use clap::{Arg, App, SubCommand, ArgMatches};

use pnet::util::{self, MacAddr, NetworkInterface};
use pnet::packet::ethernet::EtherType;

use rips::NetworkStackBuilder;
// use rips::ipv4;

macro_rules! eprintln {
    ($($arg:tt)*) => (
        use std::io::Write;
        match writeln!(&mut ::std::io::stderr(), $($arg)* ) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr: {}", x),
        }
    )
}

fn main() {
    let iface_arg = Arg::with_name("iface")
                        .short("i")
                        .long("iface")
                        .help("Ethernet interface to use")
                        .takes_value(true);
    let smac_arg = Arg::with_name("smac")
                       .long("smac")
                       .help("Source MAC address. Defaults to MAC on <iface>")
                       .takes_value(true);
    let dmac_arg = Arg::with_name("dmac")
                       .long("dmac")
                       .help("Destination MAC address")
                       .takes_value(true);

    let app = App::new("RIPS testsuite")
                  .version("1.0")
                  .author("Linus Färnstrand <faern@faern.net>")
                  .about("Tests out the RIPS TCP/IP stack in the real world")
                  .arg(Arg::with_name("v")
                           .short("v")
                           .multiple(true)
                           .help("Sets the level of verbosity"))
                  .subcommand(SubCommand::with_name("eth")
                                  .version("1.0")
                                  .about("Sends raw ethernet frames to a given MAC \
                                          address.\nThe payload will be two bytes that \
                                          increment for each packet.")
                                  .arg(iface_arg.clone().required(true))
                                  .arg(smac_arg.clone())
                                  .arg(dmac_arg.required(true))
                                  .arg(Arg::with_name("pkgs")
                                           .short("n")
                                           .long("pkgs")
                                           .help("Amount of packets to send")
                                           .default_value("1")
                                           .takes_value(true)))
                  .subcommand(SubCommand::with_name("arp")
                                  .version("1.0")
                                  .about("Send an Arp query to the network and wait for the \
                                          response")
                                  .arg(iface_arg.required(true))
                                  .arg(Arg::with_name("ip")
                                           .long("ip")
                                           .help("IPv4 address to query for")
                                           .takes_value(true)
                                           .required(true))
                                  .arg(Arg::with_name("source_ip")
                                           .long("source_ip")
                                           .help("Ipv4 address to use as Arp sender. Defauts \
                                                  to first IPv4 address on given interface.")
                                           .takes_value(true)));

    let matches = app.clone().get_matches();

    if let Some(eth_matches) = matches.subcommand_matches("eth") {
        let iface = get_iface(eth_matches, app.clone());
        let smac = get_smac(eth_matches.value_of("smac"), &iface, app.clone());
        let dmac = get_mac(eth_matches.value_of("dmac"), app.clone()).unwrap();
        let pkgs = get_int(eth_matches.value_of("pkgs"), app.clone());
        println!("Sending {} raw Ethernet packets from {} to {}",
                 pkgs,
                 smac,
                 dmac);
        let mut stack = NetworkStackBuilder::new()
                            .set_interfaces(vec![iface.clone()])
                            .create()
                            .expect("Expected a working NetworkStack");

        let eth = stack.get_ethernet(&iface).expect("Expected Ethernet");
        {
            let mut eth = eth.lock().expect("Unable to lock Ethernet");
            let mut i = 1;
            eth.send(pkgs, 2, |pkg| {
                pkg.set_source(smac);
                pkg.set_destination(dmac);
                pkg.set_ethertype(EtherType::new(0x1337));
                pkg.set_payload(&[i, i + 1]);
                i += 1
            });
        }
    } else if let Some(arp_matches) = matches.subcommand_matches("arp") {
        let iface = get_iface(arp_matches, app.clone());
        let source_ip = get_source_ipv4(arp_matches.value_of("source_ip"), &iface, app.clone());
        let dest_ip = get_ipv4(arp_matches.value_of("ip"), app.clone())
                          .expect("No destination IP given");
        println!("Sending Arp request for {}", dest_ip);
        let mut stack = NetworkStackBuilder::new()
                            .set_interfaces(vec![iface.clone()])
                            .create()
                            .expect("Expected a working NetworkStack");

        let arp = stack.get_arp(&iface).expect("Expected arp");
        {
            let mut arp = arp.lock().expect("Unable to lock Arp");
            let mac = arp.get(&source_ip, &dest_ip);
            println!("{} has MAC {}", dest_ip, mac);
        }
    }

    // let ipv4_conf = ipv4::Ipv4Conf::new(my_ip, 24, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
    // let ipv4_iface = stack.add_ipv4(&iface, ipv4_conf).expect("Expected ipv4");
    // {
    //     let ipv4 = ipv4_iface.lock().unwrap();
    //     ipv4.send(dst_ip, 10, |pkg| {
    //         pkg.set_payload(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]);
    //     });
    // }

    thread::sleep(Duration::new(1, 0));
}

fn print_error(error: &str, app: App) -> ! {
    eprintln!("ERROR: {}", error);
    app.print_help().ok();
    println!("");
    process::exit(1);
}

fn get_iface(matches: &ArgMatches, app: App) -> NetworkInterface {
    let iface_name = matches.value_of("iface").expect("No iface given");
    let ifaces = util::get_network_interfaces();
    let mut iface = None;
    for curr_iface in ifaces.into_iter() {
        if curr_iface.name == iface_name {
            iface = Some(curr_iface);
            break;
        }
    }
    match iface {
        Some(i) => i,
        None => {
            print_error(&format!("Found no interface named {}\n", iface_name)[..],
                        app)
        }
    }
}

fn get_smac(mac: Option<&str>, iface: &NetworkInterface, app: App) -> MacAddr {
    get_mac(mac, app.clone()).unwrap_or_else(|| {
        match iface.mac {
            Some(m) => m,
            None => print_error("No MAC attached to selected interface", app),
        }
    })
}

fn get_mac(mac: Option<&str>, app: App) -> Option<MacAddr> {
    if let Some(mac) = mac {
        match MacAddr::from_str(mac) {
            Ok(mac) => Some(mac),
            Err(_) => print_error(&format!("Invalid MAC format: {}", mac)[..], app),
        }
    } else {
        None
    }
}

fn get_int(i: Option<&str>, app: App) -> usize {
    match i {
        Some(i_str) => {
            match i_str.parse::<usize>() {
                Ok(i) => i,
                Err(_) => print_error(&format!("Invalid integer: {}", i_str), app),
            }
        }
        None => print_error("No integer given", app),
    }
}

fn get_source_ipv4(opt_ip: Option<&str>, iface: &NetworkInterface, app: App) -> Ipv4Addr {
    if let Some(ip) = get_ipv4(opt_ip, app.clone()) {
        return ip;
    }
    match match iface.ips.as_ref() {
        Some(ips) => {
            ips.iter()
               .filter_map(|&i| {
                   match i {
                       IpAddr::V4(ip) => Some(ip),
                       _ => None,
                   }
               })
               .next()
        }
        None => None,
    } {
        Some(ip) => ip,
        None => print_error("No IPv4 to use on given interface", app),
    }
}

fn get_ipv4(opt_ip: Option<&str>, app: App) -> Option<Ipv4Addr> {
    match opt_ip {
        Some(ip_str) => {
            match Ipv4Addr::from_str(ip_str) {
                Ok(ip) => Some(ip),
                Err(_) => print_error(&format!("Invalid IPv4 format: {}", ip_str)[..], app),
            }
        }
        None => None,
    }
}
