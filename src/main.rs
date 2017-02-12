#[macro_use]
extern crate clap;
#[macro_use(tx_send)]
extern crate rips;
extern crate pnet;

use std::process;
use std::net::{Ipv4Addr, IpAddr, SocketAddrV4};
use std::fs::File;
use std::io::{self, Read};
use std::str::FromStr;
use std::time::SystemTime;
use std::sync::{Arc, Mutex, mpsc};

use clap::{Arg, App, SubCommand, ArgMatches};

use pnet::util::MacAddr;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EtherType;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::Packet;

use rips::{NetworkStack, Interface, StackResult, StackError, CustomPayload, Tx};
use rips::ethernet::EthernetFields;
use rips::arp::ArpPayload;
use rips::ipv4::{Ipv4Fields, Ipv4Network};
use rips::udp::UdpSocket;
use rips::icmp::{IcmpListener, IcmpFields};

mod util;

macro_rules! eprintln {
    ($($arg:tt)*) => (
        use std::io::Write;
        let _ = writeln!(&mut ::std::io::stderr(), $($arg)* );
    )
}

fn main() {
    let app = create_app();
    let matches = app.clone().get_matches();

    let result = if let Some(cmd_matches) = matches.subcommand_matches("eth") {
        cmd_eth(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("arp") {
        cmd_arp(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("ipv4") {
        cmd_ipv4(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("ping") {
        cmd_ping(cmd_matches, app)
    } else if let Some(cmd_matches) = matches.subcommand_matches("udp") {
        cmd_udp(cmd_matches, app)
    } else {
        Ok(())
    };
    result.expect("Command failed");
}

fn cmd_eth(cmd_matches: &ArgMatches, app: App) -> StackResult<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let smac = get_smac(cmd_matches.value_of("smac"), &iface, app.clone());
    let dmac = get_dmac(cmd_matches.value_of("dmac"), app.clone());
    let pkgs = get_int(cmd_matches.value_of("pkgs"), app.clone());
    let mut payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };
    if payload.len() == 0 {
        payload.push(0);
    }
    let payload_len = payload.len();
    println!("Sending {} raw Ethernet packets from {} to {} with {} bytes payload",
             pkgs,
             smac,
             dmac,
             payload_len);

    let mut stack = rips::default_stack()?;
    let interface = stack.interface_from_name(&iface.name).unwrap();
    for _ in 0..pkgs {
        let mut builder = CustomPayload::new(EthernetFields(EtherType::new(0x1337)), &payload);
        tx_send!(|| interface.ethernet_tx(dmac); &mut builder).map_err(|e| StackError::from(e))?;
    }
    Ok(())
}

fn cmd_arp(cmd_matches: &ArgMatches, app: App) -> StackResult<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let smac = get_smac(cmd_matches.value_of("smac"), &iface, app.clone());
    let source_ip = get_source_ipv4(cmd_matches.value_of("sip"), &iface, app.clone());
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap();
    println!("Sending Arp request for {}", dest_ip);

    let mut stack = rips::default_stack()?;
    let interface = stack.interface_from_name(&iface.name).unwrap();
    let arp_table_rx = interface.arp_table().get(dest_ip).err().unwrap();
    let mut arp_request = ArpPayload::request(smac, source_ip, dest_ip);
    tx_send!(|| interface.arp_request_tx(); &mut arp_request)?;
    let mac = arp_table_rx.recv().unwrap();
    println!("{} has MAC {}", dest_ip, mac);
    Ok(())
}

fn cmd_ipv4(cmd_matches: &ArgMatches, app: App) -> StackResult<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let src_ip = get_source_ipv4(cmd_matches.value_of("sip"), &iface, app.clone());
    let netmask = {
        let mask = get_int(cmd_matches.value_of("netmask"), app.clone());
        if mask < 1 || mask >= 32 {
            print_error("netmask must be in interval 1 - 31", app.clone());
        }
        mask as u8
    };
    let gateway = get_ipv4(cmd_matches.value_of("gateway"), app.clone())
        .unwrap_or(default_gw(src_ip, netmask));
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap_or(gateway);
    let payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };

    println!("Sending IPv4 packet from:");
    println!("\tIP: {}/{}", src_ip, netmask);
    println!("\tgw: {}", gateway);
    println!("To {}", dest_ip);
    println!("With {} bytes payload", payload.len());

    let mut stack = try!(rips::default_stack());

    let interface = stack.interface_from_name(&iface.name).unwrap().interface().clone();
    let ipv4_conf = Ipv4Network::new(src_ip, netmask).unwrap();
    try!(stack.add_ipv4(&interface, ipv4_conf));
    add_default_route(&mut stack, gateway, interface);
    let mut builder = CustomPayload::new(Ipv4Fields(IpNextHeaderProtocols::Igmp), &payload);
    tx_send!(|| stack.ipv4_tx(dest_ip).unwrap(); &mut builder)?;
    Ok(())
}

fn add_default_route(stack: &mut NetworkStack, gw: Ipv4Addr, iface: Interface) {
    let mut routing_table = stack.routing_table();
    let default = Ipv4Network::from_str("0.0.0.0/0").unwrap();
    routing_table.add_route(default, Some(gw), iface);
}

fn cmd_ping(cmd_matches: &ArgMatches, app: App) -> StackResult<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let src_ip = get_source_ipv4(cmd_matches.value_of("sip"), &iface, app.clone());
    let netmask = {
        let mask = get_int(cmd_matches.value_of("netmask"), app.clone());
        if mask < 1 || mask >= 32 {
            print_error("netmask must be in interval 1 - 31", app.clone());
        }
        mask as u8
    };
    let gateway = get_ipv4(cmd_matches.value_of("gateway"), app.clone())
        .unwrap_or(default_gw(src_ip, netmask));
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap_or(gateway);
    let payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };

    println!("Sending echo request packet from:");
    println!("\tIP: {}/{}", src_ip, netmask);
    println!("\tgw: {}", gateway);
    println!("To {}", dest_ip);
    println!("With {} bytes payload", payload.len());


    let (tx, rx) = mpsc::channel();
    let ping_listener = PingListener { tx: tx };

    let mut stack = try!(rips::default_stack());

    let interface = stack.interface_from_name(&iface.name).unwrap().interface().clone();
    let ipv4_conf = Ipv4Network::new(src_ip, netmask).unwrap();
    try!(stack.add_ipv4(&interface, ipv4_conf));
    add_default_route(&mut stack, gateway, interface);

    stack.icmp_listen(src_ip, IcmpTypes::EchoReply, ping_listener).unwrap();

    let start_time = SystemTime::now();
    let fields = IcmpFields::echo_request();
    let mut builder = CustomPayload::new(fields, &payload);
    tx_send!(|| stack.icmp_tx(dest_ip).unwrap(); &mut builder)?;

    let (time, pkg) = rx.recv().unwrap();

    let elapsed1 = time.elapsed().unwrap();
    let elapsed2 = start_time.elapsed().unwrap();
    let ip_pkg = Ipv4Packet::new(&pkg[..]).unwrap();
    println!("Ping reply from {} in {:?}ms -> {:?}ms",
             ip_pkg.get_source(),
             util::duration_to_ms(elapsed1),
             util::duration_to_ms(elapsed2));
    Ok(())
}

fn cmd_udp(cmd_matches: &ArgMatches, app: App) -> StackResult<()> {
    let iface = get_iface(cmd_matches, app.clone());
    let src_ip = get_source_ipv4(cmd_matches.value_of("sip"), &iface, app.clone());
    let netmask = {
        let mask = get_int(cmd_matches.value_of("netmask"), app.clone());
        if mask < 1 || mask >= 32 {
            print_error("netmask must be in interval 1 - 31", app.clone());
        }
        mask as u8
    };
    let gateway = get_ipv4(cmd_matches.value_of("gateway"), app.clone())
        .unwrap_or(default_gw(src_ip, netmask));
    let dest_ip = get_ipv4(cmd_matches.value_of("ip"), app.clone()).unwrap_or(gateway);
    let src_port = get_int(cmd_matches.value_of("sport"), app.clone()) as u16;
    let dst_port = get_int(cmd_matches.value_of("dport"), app.clone()) as u16;
    let payload = match get_payload(cmd_matches.value_of("payload")) {
        Ok(payload) => payload,
        Err(e) => print_error(&format!("Payload error: {}", e)[..], app.clone()),
    };

    let mut stack = try!(rips::default_stack());
    let interface = stack.interface_from_name(&iface.name).unwrap().interface().clone();

    let ipv4_conf = Ipv4Network::new(src_ip, netmask).unwrap();
    try!(stack.add_ipv4(&interface, ipv4_conf));
    add_default_route(&mut stack, gateway, interface);

    let stack = Arc::new(Mutex::new(stack));
    let mut socket = UdpSocket::bind(stack, SocketAddrV4::new(src_ip, src_port)).unwrap();
    let local_addr = socket.local_addr().unwrap();
    println!("Sending IPv4 UDP packet from:");
    println!("\tIP: {}/{}:{}",
             local_addr.ip(),
             netmask,
             local_addr.port());
    println!("\tgw: {}", gateway);
    println!("To {}:{}", dest_ip, dst_port);
    println!("With {} bytes payload", payload.len());

    let result = socket.send_to(&payload, SocketAddrV4::new(dest_ip, dst_port));
    let result = result.map_err(|e| StackError::from(e));
    result.map(|_| ())
}

#[derive(Clone)]
struct PingListener {
    pub tx: mpsc::Sender<(SystemTime, Vec<u8>)>,
}

impl IcmpListener for PingListener {
    fn recv(&mut self, time: SystemTime, packet: &Ipv4Packet) {
        self.tx.send((time, packet.packet().to_vec())).unwrap();
    }
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
    get_mac(mac, app.clone()).unwrap_or_else(|| match iface.mac {
        Some(m) => m,
        None => print_error("No MAC attached to selected interface", app),
    })
}

fn get_dmac(mac: Option<&str>, app: App) -> MacAddr {
    get_mac(mac, app.clone()).unwrap()
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
                .filter_map(|&i| match i {
                    IpAddr::V4(ip) => Some(ip),
                    _ => None,
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


fn create_app() -> App<'static, 'static> {
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
        .default_value("FF:FF:FF:FF:FF:FF");
    let source_ip_arg = Arg::with_name("sip")
        .short("s")
        .long("sip")
        .help("Source IPv4 Address. Defaults to the first IPv4 address on the given interface.")
        .takes_value(true);
    let src_port_arg = Arg::with_name("sport")
        .long("sport")
        .help("Source port.")
        .default_value("0");
    let dst_port_arg = Arg::with_name("dport")
        .long("dport")
        .help("Destination port.")
        .default_value("9999");
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

    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .subcommand(SubCommand::with_name("eth")
            .version("1.0")
            .about("Sends raw ethernet frames to a given MAC address.")
            .arg(iface_arg.clone().required(true))
            .arg(smac_arg.clone())
            .arg(dmac_arg)
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
            .arg(payload_arg.clone()))
        .subcommand(SubCommand::with_name("udp")
            .version("1.0")
            .about("Send UDP packets with a given payload")
            .arg(iface_arg.clone().required(true))
            .arg(source_ip_arg.clone())
            .arg(netmask_arg.clone())
            .arg(gateway_arg.clone())
            .arg(src_port_arg.clone())
            .arg(dst_port_arg.clone())
            .arg(Arg::with_name("ip")
                .long("ip")
                .help("Destination IP. Defaults to the gateway IP.")
                .takes_value(true))
            .arg(payload_arg.clone()))
}
