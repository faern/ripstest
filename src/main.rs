extern crate clap;
extern crate rips;
extern crate pnet;
extern crate ipnetwork;

use std::process;
use std::net::{Ipv4Addr, IpAddr};
use std::fs::File;
use std::io::{self, Read};
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use std::collections::HashMap;

use clap::{Arg, App, SubCommand, ArgMatches};

use pnet::util::MacAddr;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EtherType;
use pnet::packet::ip::IpNextHeaderProtocols;

use ipnetwork::Ipv4Network;

use rips::ethernet::{Ethernet, EthernetListener};
use rips::arp::ArpFactory;
use rips::ipv4::{self, Ipv4Factory, Ipv4Listener};
use rips::icmp;

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
    let source_ip_arg = Arg::with_name("source_ip")
        .short("s")
        .long("source_ip")
        .help("Local IPv4 Address. Defaults to the first IPv4 address on the given interface.")
        .takes_value(true);
    let netmask_arg = Arg::with_name("netmask")
        .long("mask")
        .help("Local netmask.")
        .default_value("24");
    let gateway_arg = Arg::with_name("gateway")
        .long("gw")
        .help("Gateway IPv4. Defaults to the first IP in the network denoted by source_ip and \
               mask.")
        .takes_value(true);
    let payload_arg = Arg::with_name("payload")
        .long("payload")
        .help("A file containing the payload. Without this a packet without a payload will be \
               sent.")
        .takes_value(true);

    let app = App::new("RIPS testsuite")
        .version("1.0")
        .author("Linus Färnstrand <faern@faern.net>")
        .about("Test out the RIPS TCP/IP stack in the real world.")
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .subcommand(SubCommand::with_name("eth")
            .version("1.0")
            .about("Sends raw ethernet frames to a given MAC address.")
            .arg(iface_arg.clone().required(true))
            .arg(smac_arg.clone())
            .arg(dmac_arg.required(true))
            .arg(Arg::with_name("pkgs")
                .short("n")
                .long("pkgs")
                .help("Amount of packets to send")
                .default_value("1")
                .takes_value(true))
            .arg(payload_arg.clone()))
        .subcommand(SubCommand::with_name("arp")
            .version("1.0")
            .about("Send an Arp query to the network and wait for the response.")
            .arg(iface_arg.clone().required(true))
            .arg(Arg::with_name("ip")
                .long("ip")
                .help("IPv4 address to query for")
                .takes_value(true)
                .required(true))
            .arg(source_ip_arg.clone()))
        .subcommand(SubCommand::with_name("ipv4")
            .version("1.0")
            .about("Send an IPv4 packet with a given payload to the network.")
            .arg(iface_arg.clone().required(true))
            .arg(source_ip_arg.clone())
            .arg(netmask_arg.clone())
            .arg(gateway_arg.clone())
            .arg(Arg::with_name("ip")
                .long("ip")
                .help("Destination IP. Defaults to the gateway IP.")
                .takes_value(true))
            .arg(payload_arg.clone()))
        .subcommand(SubCommand::with_name("ping")
            .version("1.0")
            .about("Send an echo request (ping) packet with a given payload to the network.")
            .arg(iface_arg.clone().required(true))
            .arg(source_ip_arg.clone())
            .arg(netmask_arg.clone())
            .arg(gateway_arg.clone())
            .arg(Arg::with_name("ip")
                .long("ip")
                .help("Destination IP. Defaults to the gateway IP.")
                .takes_value(true))
            .arg(payload_arg.clone()));

    let matches = app.clone().get_matches();

    if let Some(cmd_matches) = matches.subcommand_matches("eth") {
        cmd_eth(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("arp") {
        cmd_arp(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("ipv4") {
        cmd_ipv4(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("ping") {
        cmd_ping(cmd_matches, app)
    } else {
        Ok(())
    }.expect("Command failed");
    sleep(Duration::new(2, 0));
}

fn cmd_eth(cmd_matches: &ArgMatches, app: App) -> io::Result<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let smac = get_smac(cmd_matches.value_of("smac"), &iface, app.clone());
    let dmac = get_mac(cmd_matches.value_of("dmac"), app.clone()).unwrap();
    let pkgs = get_int(cmd_matches.value_of("pkgs"), app.clone());
    let payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };
    println!("Sending {} raw Ethernet packets from {} to {} with {} bytes payload",
             pkgs,
             smac,
             dmac,
             payload.len());

    let mut ethernet = try!(create_ethernet(iface, vec![]));
    ethernet.send(pkgs, payload.len(), |pkg| {
        pkg.set_source(smac);
        pkg.set_destination(dmac);
        pkg.set_ethertype(EtherType::new(0x1337));
        pkg.set_payload(&payload);
    }).unwrap()
}

fn cmd_arp(cmd_matches: &ArgMatches, app: App) -> io::Result<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let source_ip = get_source_ipv4(cmd_matches.value_of("source_ip"), &iface, app.clone());
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap();
    println!("Sending Arp request for {}", dest_ip);

    let arp_factory = ArpFactory::new();
    let ethernet = try!(create_ethernet(iface, vec![arp_factory.listener()]));
    let mut arp = arp_factory.arp(ethernet);
    let mac = arp.get(source_ip, dest_ip);
    println!("{} has MAC {}", dest_ip, mac);
    Ok(())
}

fn cmd_ipv4(cmd_matches: &ArgMatches, app: App) -> io::Result<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let source_ip = get_source_ipv4(cmd_matches.value_of("source_ip"), &iface, app.clone());
    let netmask = {
        let mask = get_int(cmd_matches.value_of("netmask"), app.clone());
        if mask < 1 || mask >= 32 {
            print_error("netmask must be in interval 1 - 31", app.clone());
        }
        mask as u8
    };
    let gateway = get_ipv4(cmd_matches.value_of("gateway"), app.clone())
        .unwrap_or(default_gw(source_ip, netmask));
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap_or(gateway);
    let payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };

    println!("Sending IPv4 packet from:");
    println!("\tIP: {}/{}", source_ip, netmask);
    println!("\tgw: {}", gateway);
    println!("To {}", dest_ip);
    println!("With {} bytes payload", payload.len());

    let arp_factory = ArpFactory::new();
    let mut ipv4_factory = Ipv4Factory::new(arp_factory, HashMap::new());

    let ethernet = try!(create_ethernet(iface, ipv4_factory.listeners().unwrap()));
    let ipv4_conf = ipv4::Ipv4Config::new(source_ip, netmask, gateway).unwrap();
    let mut ipv4 = ipv4_factory.ip(ethernet, ipv4_conf);
    ipv4.send(dest_ip, payload.len() as u16, |pkg| {
        pkg.set_payload(&payload[..]);
    }).unwrap()
}

fn cmd_ping(cmd_matches: &ArgMatches, app: App) -> io::Result<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let source_ip = get_source_ipv4(cmd_matches.value_of("source_ip"), &iface, app.clone());
    let netmask = {
        let mask = get_int(cmd_matches.value_of("netmask"), app.clone());
        if mask < 1 || mask >= 32 {
            print_error("netmask must be in interval 1 - 31", app.clone());
        }
        mask as u8
    };
    let gateway = get_ipv4(cmd_matches.value_of("gateway"), app.clone())
        .unwrap_or(default_gw(source_ip, netmask));
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap_or(gateway);
    let payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };

    println!("Sending echo request packet from:");
    println!("\tIP: {}/{}", source_ip, netmask);
    println!("\tgw: {}", gateway);
    println!("To {}", dest_ip);
    println!("With {} bytes payload", payload.len());

    let icmp_factory = icmp::IcmpFactory::new();
    let icmp_listener = icmp_factory.listener();
    let mut ipv4_listeners = HashMap::new();
    ipv4_listeners.insert(IpNextHeaderProtocols::Icmp, Box::new(icmp_listener) as Box<Ipv4Listener>);

    let arp_factory = ArpFactory::new();
    let mut ipv4_factory = Ipv4Factory::new(arp_factory, ipv4_listeners);

    let ethernet = try!(create_ethernet(iface, ipv4_factory.listeners().unwrap()));
    let ipv4_conf = ipv4::Ipv4Config::new(source_ip, netmask, gateway).unwrap();
    let ipv4 = ipv4_factory.ip(ethernet, ipv4_conf);

    let icmp = icmp::Icmp::new(ipv4);
    let mut ping = icmp::Echo::new(icmp);
    ping.send(dest_ip, &payload[..]).unwrap()
}

fn create_ethernet(interface: NetworkInterface, listeners: Vec<Box<EthernetListener>>) -> io::Result<Ethernet> {
    let mac = match interface.mac {
        Some(mac) => mac,
        None => {
            return Err(io::Error::new(io::ErrorKind::Other,
                                      format!("No mac for {}", interface.name)))
        }
    };
    let config = datalink::Config::default();
    let channel = try!(datalink::channel(&interface, config));
    Ok(Ethernet::new(mac, channel, listeners))
}

fn print_error(error: &str, mut app: App) -> ! {
    eprintln!("ERROR: {}", error);
    app.print_help().ok();
    println!("");
    process::exit(1);
}

fn get_iface(matches: &ArgMatches, app: App) -> NetworkInterface {
    let iface_name = matches.value_of("iface").expect("No iface given");
    let ifaces = datalink::interfaces();
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

fn get_payload(opt_path: Option<&str>) -> io::Result<Vec<u8>> {
    match opt_path {
        Some(path) => {
            let mut f = try!(File::open(path));
            let mut buffer = vec![];
            let size = try!(f.read_to_end(&mut buffer));
            if size > u16::max_value() as usize {
                Err(io::Error::new(io::ErrorKind::Other, "Too large payload"))
            } else {
                Ok(buffer)
            }
        }
        None => Ok(vec![]),
    }
}

fn default_gw(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let ip_net = Ipv4Network::new(ip, prefix).expect("Invalid network");
    let net = u32::from(ip_net.network());
    Ipv4Addr::from(net + 1)
}
