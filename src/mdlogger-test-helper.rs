use std::{collections::HashMap, hash::Hash, mem::MaybeUninit, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, str::from_utf8};

use rsclp::CommandLineParser;
use mdlogger::utils::{self, network_interface_exists};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use socket2::{Domain, SockAddr, Socket, Type};

// Network interface information object
struct NetworkInterfaceInfo {
    name: String,
    index: u32,
    mac_addr: String,
    addresses: Vec<Addr>
}

// Network interface information object implementation
impl NetworkInterfaceInfo {
    // Create a network interface information object
    // * `name` network interface name 
    // * `index` network interface system index
    // * `mac_addr` network interface MAC address
    // * `addresses` network interface associated IP addresses
    fn new(name: String, index: u32, mac_addr: String, addresses: Vec<Addr>) -> Self {
        Self {
            name,
            index,
            mac_addr,
            addresses
        }
    }    
}

// Hash trait implementation for network interface information object
impl Hash for NetworkInterfaceInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state)
    }
}

// PartialEq trait implementation for network interface information object
impl PartialEq for NetworkInterfaceInfo {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

// Print-out command line help and exit 
// * `clp` command line parser reference 
fn show_help_and_exit_with_error(clp: &CommandLineParser) {
    let _ = clp.show_help_on(&mut std::io::stderr().lock());
    std::process::exit(-1);
}

/// This executable has been created to test mdlogger library
fn main() {
    let valid_servers = vec!["tcp", "udp", "mcast", "unix-udp", "unix-tcp"];

    let mut clp = CommandLineParser::new(None);
    let help_option = clp.add_help_option("show this help").unwrap();
    let server_type_opt = clp.add_string_option('t', "server-type", true, "server type", &format!("valid server type are: {}", valid_servers.join(", "))).unwrap();
    let server_address = clp.add_string_option('a', "server-address", true, "ip address", "IPV4 or IPV6 for tcp/udp server path for unix domain server").unwrap();
    let port_option = clp.add_integer_option('p', "server-port", false, "port number", "server port number (tcp/udp server only)").unwrap();
    let mcast_itf_option = clp.add_string_option('i', "itf-address", false, "interface ip address ", "IPV4 or IPV6 for multicat server").unwrap();
    
    clp.process();
    if !clp.is_set(&help_option) {
        if let Err(parse_error) = clp.check_mandatory_options() {
            eprintln!("{}", parse_error);
            show_help_and_exit_with_error(&clp);
        }

        let server_type = clp.get_value::<String>(&server_type_opt).unwrap().to_lowercase();
        println!("server_type: {}", server_type);
        if !valid_servers.contains(&server_type.as_str()) {
            eprintln!("{} is not valid server type, valids are: {}", 
                    server_type, valid_servers.join(", "));
            show_help_and_exit_with_error(&clp);
        }
        if cfg!(windows) && server_type == "unix-udp" {
            eprintln!("{} cannot be created on windows os", server_type);
            show_help_and_exit_with_error(&clp);
        }

        let server_addr = clp.get_value::<String>(&server_address).unwrap();
        if !server_type.starts_with("unix") {
            let mut server_ip: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            match server_addr.parse::<IpAddr>() {
                Ok(ip) => {
                    server_ip = ip;
                },
                Err(parse_error) => {
                    eprintln!("server address: {} prase error: {}", server_addr, parse_error);
                    show_help_and_exit_with_error(&clp);
                }
            };
            if server_type == "tcp" || server_type == "udp" {
                if  !clp.is_set(&port_option) {
                    eprintln!("tcp or udp server needs a port");
                    show_help_and_exit_with_error(&clp);
                }
            }

            if !clp.is_set(&server_address) {
                eprintln!("missing server address");
                show_help_and_exit_with_error(&clp);
            }

            let mut mcast_itf_ip: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            if server_ip.is_ipv6() {
                mcast_itf_ip = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
            }
            if "mcast" == server_type {
                if clp.is_set(&mcast_itf_option) {

                    if !server_ip.is_multicast() {
                        eprintln!("Server address is not a multicast address: {}", server_ip);
                        std::process::exit(-1);
                    }

                    let mcast_itf_address = clp.get_value::<String>(&mcast_itf_option).unwrap();

                    mcast_itf_ip = mcast_itf_address.parse().unwrap_or_else(|e| {
                        eprintln!("{}", e);
                        std::process::exit(-1);
                    });

                    if server_ip.is_ipv4() && mcast_itf_ip.is_ipv6() {
                        eprintln!("mismatch IPV4/IPV6 type between server ip & interface ip");
                        std::process::exit(-1);
                    }

                    if !network_interface_exists(&mcast_itf_address) {
                        eprintln!("multicast interface ip '{}' does not exist", mcast_itf_address);
                        show_network_interfaces();
                        std::process::exit(-1);
                    }

                }
            }

            let port: i32 = clp.get_value(&port_option).unwrap(); 
            if !server_type.starts_with("unix") {
                if port < 1 || port > u16::MAX as i32 {
                    eprintln!("port {} is out of ragne 1..{}", port, u16::MAX);
                    std::process::exit(-1);
                }
            }        
            if "udp" == server_type {
                udp_server(server_ip, port as u16);
            } else if "mcast" == server_type {
                mcast_server(server_ip, port as u16, mcast_itf_ip);
            } else if "tcp" == server_type { 
                tcp_server(server_ip, port as u16);
            }
        } else {
            unix_domain_server(&server_type, &server_addr);
        }                

    } else {
        clp.show_help();
    }

}

// Print-out network interfaces list
fn show_network_interfaces() {
    match NetworkInterface::show() {
        Ok(network_interfaces) => {
            let mut infos: HashMap<String, NetworkInterfaceInfo> = HashMap::new();
            for network_interface in network_interfaces {
                if let Some(info) = infos.get_mut(&network_interface.name) {
                    info.addresses.append(&mut network_interface.addr.clone());
                } else {
                    let info = NetworkInterfaceInfo::new(
                        network_interface.name.clone(), 
                        network_interface.index,
                        network_interface.mac_addr.unwrap_or(String::new()), 
                        network_interface.addr);
                    infos.insert(network_interface.name, info);
                }
            }    

            for (_key, info) in infos { 
                println!("Name: {} - index: {} mac address: {}", info.name, 
                    info.index, info.mac_addr);
                println!("--------------------------------------------------------------------");
                for addr in info.addresses {
                    let ip = addr.ip();
                    let mut ip_type = "IPV4";
                    if ip.is_ipv6() {
                        ip_type = "IPV6";
                    }
                    println!("{}: {}", ip_type, ip.to_string());
                }
                println!("");
            }
        },
        Err(_) => {
            eprintln!("netwotk interfaces not found");
        }
    }    
}

// This function implements a udp server
// * `server_ip` server receiving ip address 
// * `port` server receiving ip address
fn udp_server(server_ip: IpAddr, port: u16) {
    let domain: Domain;
    
    let bind_address: SocketAddr;
    if server_ip.is_ipv4() {
        domain = Domain::IPV4;
        bind_address = format!("{}:{}", server_ip.to_string(), port).as_str().parse().unwrap();
    } else {
        domain = Domain::IPV6;
        bind_address = format!("[{}]:{}", server_ip.to_string(), port).as_str().parse().unwrap();
    }
    match Socket::new(domain, Type::DGRAM, None) {
        Ok(srv_socket) => {
            match srv_socket.set_reuse_address(true) {
                Ok(_) => {
                    match srv_socket.bind(&bind_address.into()) {
                        Ok(_) => {
                            println!("Waiting for message {:#}", bind_address);
                            let mut buf: [MaybeUninit<u8>; u16::MAX as usize] = unsafe { MaybeUninit::zeroed().assume_init() };
                            loop {
                                match srv_socket.recv_from(&mut buf)  {
                                    Ok(rx_result) => {
                                        let mut message: Vec<u8> = Vec::with_capacity(rx_result.0);
                                        for i in 0..rx_result.0 {
                                            message.push(unsafe { *buf[i].as_ptr() });
                                        }
                                        let message = from_utf8(&message).unwrap_or_else(|e| {
                                            eprintln!("{}", e);
                                            ""
                                        });
                                        if !message.is_empty() {
                                            println!("{}", message);
                                        }
                                    },
                                    Err(error) => {
                                        eprintln!("UDP Server receive error: {}", error);
                                    }
                                }
                            }
                        },
                        Err(error) => {
                            eprintln!("Cannot bind UDP socket to {:#?}, {}", bind_address, error);
                        }
                    }        
                },
                Err(error) => {
                    eprintln!("UDP server error setting reuse address: {}", error);
                }
            }
        },
        Err(error) => {
            eprintln!("Cannot create UDP socket: {}", error);
        }
    }
}


// This function implements a multicast udp server
// * `server_ip` server multicast receiving ip address 
// * `port` server receiving ip address
// * `mcast_itf_ip` server multicast intrface receiving ip address
fn mcast_server(server_ip: IpAddr, port: u16, mcast_itf_ip: IpAddr) {
    let domain: Domain;
    
    let bind_address: SocketAddr;
    let mut join_address_v4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    let mut join_address_v6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
    match server_ip {
        IpAddr::V4(address) => {
            domain = Domain::IPV4;
            bind_address = format!("{}:{}", Ipv4Addr::UNSPECIFIED, port).as_str().parse().unwrap();
            join_address_v4 = address;
        },
        IpAddr::V6(address) => {
            domain = Domain::IPV6;
            bind_address = format!("[{}]:{}", Ipv6Addr::UNSPECIFIED, port).as_str().parse().unwrap();
            join_address_v6 = address;
        }
    }
    match Socket::new(domain, Type::DGRAM, None) {
        Ok(srv_socket) => {
            match srv_socket.set_reuse_address(true) {
                Ok(_) => {
                    if let Err(error) = srv_socket.bind(&bind_address.into()) {
                        eprintln!("UDP multicast cannot bind address {:#?}, {}", bind_address, error);
                        ()
                    }
                    let join_result: std::io::Result<()>;
                    let mut join_mcast_itf: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
                    let mut join_mcast_idx = 0;
                    if !mcast_itf_ip.is_unspecified() {
                         join_mcast_idx = utils::network_index(&mcast_itf_ip).unwrap_or(0u32);
                    }
                    match mcast_itf_ip {
                        IpAddr::V4(address) => {
                            join_mcast_itf = address;
                        }
                        _=> {
                            
                        }
                    }
                    if server_ip.is_ipv4() {
                        join_result = srv_socket.join_multicast_v4(&join_address_v4, &join_mcast_itf);
                    } else {                        
                        join_result = srv_socket.join_multicast_v6(&join_address_v6, join_mcast_idx);
                    }
                    if let Err(error) = join_result {
                        if server_ip.is_ipv4() {
                            eprintln!("UDP multicast server cannot join multicast address {:#?} interface address {:#?}, {},", 
                                join_address_v4, join_mcast_itf, error);
                                return ();
                        }
                        eprintln!("UDP multicast server cannot join multicast address {:#?} interface idx {:#?}, {},", 
                            join_address_v6, join_mcast_idx, error);
                            return ();
                    } 
                    if mcast_itf_ip.is_unspecified() {
                        println!("UDP multicast server waiting message on {:#?} port {} from any network ineterface", 
                            server_ip, port);
                    } else {
                        if mcast_itf_ip.is_ipv4() {
                            println!("UDP multicast server waiting message on {:#?} port {} from network ineterface {}", 
                                server_ip, port, mcast_itf_ip);
                        } else {
                            println!("UDP multicast server waiting message on {:#?} port {} from network ineterface index {}", 
                                server_ip, port, join_mcast_idx);
                        }
                    }

                    let mut buf: [MaybeUninit<u8>; u16::MAX as usize] = unsafe { MaybeUninit::zeroed().assume_init() };
                    loop {
                        match srv_socket.recv_from(&mut buf)  {
                            Ok(rx_result) => {
                                let mut message: Vec<u8> = Vec::with_capacity(rx_result.0);
                                for i in 0..rx_result.0 {
                                    message.push(unsafe { *buf[i].as_ptr() });
                                }
                                let message = from_utf8(&message).unwrap_or_else(|e| {
                                    eprintln!("{}", e);
                                    ""
                                });
                                if !message.is_empty() {
                                    println!("{}", message);
                                }
                            },
                            Err(error) => {
                                eprintln!("UDP multicast server receive error: {}", error);
                            }
                        }
                    }
                },
                Err(error) => {
                    eprintln!("UDP multicast server error setting reuse address: {}", error);
                }
            }
        },
        Err(error) => {
            eprintln!("Cannot create UDP multicast socket: {}", error);
        }
    }
}

// This function implements a tcp server
// * `server_ip` server multicast receiving ip address 
// * `port` server receiving ip address
fn tcp_server(server_ip: IpAddr, port: u16) {
    let domain: Domain;
    
    let bind_address: SocketAddr;
    if server_ip.is_ipv4() {
        domain = Domain::IPV4;
        bind_address = format!("{}:{}", server_ip.to_string(), port).as_str().parse().unwrap();
    } else {
        domain = Domain::IPV6;
        bind_address = format!("[{}]:{}", server_ip.to_string(), port).as_str().parse().unwrap();
    }
    match Socket::new(domain, Type::STREAM, None) {
        Ok(srv_socket) => {

            if let Err(error) = srv_socket.set_reuse_address(true) {
                eprintln!("TCP server error setting reuse address: {}", error);    
                return ()
            }
            if let Err(error) = srv_socket.bind(&bind_address.into()) {
                eprintln!("TCP server cannot bind address {:#?} : {}", bind_address, error);    
                return ()
            }
            if let Err(error) = srv_socket.listen(5) {
                eprintln!("TCP server cannot listen: {}", error);    
                return ()
            }

            loop {
                println!("TCP server waiting connection on {:#?}", bind_address);
                match srv_socket.accept() {
                    Ok(client_socket) => {
                        println!("connection receive from: {:#?}", client_socket.1.as_socket());
                        loop {
                            match tcp_receive_message(&client_socket.0) {
                                Ok(message) => {
                                    println!("{}", message)
                                },
                                Err(error) => {
                                    eprintln!("TCP server error receiving a message: {}", error);
                                    break;
                                }
                            }
                        }
                    },
                    Err(error) => {
                        eprintln!("TCP server accept error: {}", error);  
                    }
                }
            }
        },
        Err(error) => {
            eprintln!("Cannot create TCP socket: {}", error);
        }
    }
}

// Receive a messag from a tcp peer socket
// * `client_socket` client peer socket reference
fn tcp_receive_message(client_socket: &Socket) -> std::io::Result<String> {
    let mut buf:[MaybeUninit<u8>; 1] = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut v: Vec<u8> = vec![];
    loop {
        match client_socket.recv(&mut buf) {
            Ok(size) => {
                if size > 0 {
                    let byte = unsafe { *buf[0].as_ptr() };
                    if 0x3 as u8 != byte {
                        v.push(byte);        
                    } else {
                        break;
                    
                    }
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "Connection reset by peer",
                    ));
                }
            },
            Err(error) => {
                return Err(error);
            }
        }
    }
    Ok(from_utf8(&v).unwrap_or("").to_string())
}

// This function implements a tcp or udp server
// * `server_type` server type (tcp or udp)
// * `server_addr` unix domain server address
fn unix_domain_server(server_type: &String, server_addr: &String) {
    match SockAddr::unix(server_addr) {
        Ok(sock_addr) => {
            let mut socket_type: Type = Type::DGRAM;
            if server_type == "unix-tcp" {
                socket_type = Type::STREAM;
            }
            match Socket::new(Domain::UNIX, socket_type, None) {
                Ok(socket) => {
                    if std::path::Path::new(&server_addr).exists() {
                        if let Err(error) = std::fs::remove_file(server_addr) {
                            eprintln!("UNIX DOMAIN TCP server cannot remove {}: {}", server_addr, error);
                            return;
                        }
                    }
                    if let Err(error) = socket.bind(&sock_addr) {
                        eprintln!("UNIX DOMAIN TCP server cannot bind socket to {}: {}", server_addr, error);
                        return;
                    }
                    if socket_type == Type::STREAM {
                        unix_domain_tcp_server(socket, server_addr);
                    } else {
                        unix_domain_udp_server(socket, server_addr);
                    }
                },
                Err(error) => {
                    eprintln!("UNIX DOMAIN cannot create server socket: {}", error);
                }
            }
        },
        Err(parse_error) => {
            eprintln!("UNIX DOMAIN server error: {}", parse_error);
        }
    } 
}


// This function implements a tcp server
// * `socket` server socket 
// * `addr` unix domain server address
fn unix_domain_tcp_server(socket: Socket, addr: &String) {
    if let Err(error) = socket.listen(5) {
        eprintln!("UNIX DOMAIN TCP server cannot listen: {}", error);
        return;
    }
    loop {
        println!("Waiting for message {:#?}", addr);
        match socket.accept() {
            Ok(client_socket) => {
                println!("connection receive from: {:#?}", client_socket.1.as_socket());
                loop {
                    match tcp_receive_message(&client_socket.0) {
                        Ok(message) => {
                            println!("{}", message)
                        },
                        Err(error) => {
                            eprintln!("UNIX DOMAIN TCP server error receiving a message: {}", error);
                            break;
                        }
                    }
                }
            },
            Err(error) => {
                eprintln!("UNIX DOMAIN TCP server cannot accept incoming connectio: {}", error);
            }
        }
    }
}

// This function implements a udp server
// * `socket` server socket 
// * `addr` unix domain server address
fn unix_domain_udp_server(socket: Socket, addr: &String) {
    println!("Waiting for message {}", addr);
    let mut buf: [MaybeUninit<u8>; u16::MAX as usize] = unsafe { MaybeUninit::zeroed().assume_init() };
    loop {
        match socket.recv_from(&mut buf)  {
            Ok(rx_result) => {
                let mut message: Vec<u8> = Vec::with_capacity(rx_result.0);
                for i in 0..rx_result.0 {
                    message.push(unsafe { *buf[i].as_ptr() });
                }
                let message = from_utf8(&message).unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    ""
                });
                if !message.is_empty() {
                    println!("{}", message);
                }
            },
            Err(error) => {
                eprintln!("UDP Server receive error: {}", error);
            }
        }
    }
}