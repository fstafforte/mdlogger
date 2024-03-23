use crate::{
    interfaces::{LogHandler, LogHandlerFactory}, 
    logmessage::LogMessage, 
    pretty_function, 
    types::{LogHandlerBase, LogMsgType, LOG_MSG_TYPE_NUM}, 
    utils::{
        check_log_handler_common_parameters, get_log_handler_common_parameters,
        network_index, network_interface_exists
    }
};
use std::{
    fmt::Display, 
    io::{self, ErrorKind}, 
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr
    }, 
    str::FromStr
};

use serde::Serialize;
use serde_json::{json, Value};
use socket2::{Domain, SockAddr, Socket, Type};


const UDP_NETWORK_PROTOCOL: &str = "udp";
const MCAST_NETWORK_PROTOCOL: &str = "mcast";
const TCP_NETWORK_PROTOCOL: &str = "tcp";
const VALID_NETWORK_PROTOCOLS: [&str; 2] = [
    UDP_NETWORK_PROTOCOL,
    TCP_NETWORK_PROTOCOL
];

const PROTOCOL_KEY: &str = "protocol";
const REMOTE_ADDRESS_KEY: &str = "remote_address";
const MULTICAST_IF_KEY: &str = "multicast_if";
const REMOTE_PORT_KEY: &str = "remote_port";
const SUN_PATH_KEY: &str = "sun_path";
enum NetworkProtocol {
    UdpProtocol(String),
    MCastProtocol(String),
    TcpProtocol(String)
}

impl NetworkProtocol {
    fn unwrap(&self) -> &String {
        match self {
            Self::UdpProtocol(value) => { value }
            Self::MCastProtocol(value) => { value }
            Self::TcpProtocol(value) => { value }
        }
    }
}

impl PartialEq for NetworkProtocol {
    fn eq(&self, other: &Self) -> bool {
        self.unwrap() == other.unwrap()
    }
}

struct NetworkProtocolFormatError {
    message: String
}

impl Display for NetworkProtocolFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl FromStr for NetworkProtocol {
    type Err = NetworkProtocolFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lowercase = s.to_lowercase();
        if UDP_NETWORK_PROTOCOL == s_lowercase {
            Ok(NetworkProtocol::UdpProtocol(UDP_NETWORK_PROTOCOL.to_string()))
        } else if MCAST_NETWORK_PROTOCOL == s_lowercase {
            Ok(NetworkProtocol::MCastProtocol(MCAST_NETWORK_PROTOCOL.to_string()))
        } else if TCP_NETWORK_PROTOCOL == s_lowercase {
            Ok(NetworkProtocol::TcpProtocol(TCP_NETWORK_PROTOCOL.to_string()))
        } else {
            Err(NetworkProtocolFormatError{message: format!("Invalid network protocol '{}' valid are: {}",
                s, VALID_NETWORK_PROTOCOLS.join(", "))})
        }
    }
}

impl Display for NetworkProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.unwrap())
    }
}



pub (crate) struct NetworkLogHandlerFactory {

}

impl LogHandlerFactory for NetworkLogHandlerFactory {
    fn type_name(&self) -> &str {
        "network"
    }
    fn check_parameters(&self, settings: &rssettings::Settings, log_handler_name: &str) -> Result<(), String> {
        check_log_handler_common_parameters(settings, self.type_name(), log_handler_name)?;

        let network_protocol = settings.get(log_handler_name,PROTOCOL_KEY, "".to_string());
        if network_protocol.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", 
                    log_handler_name, self.type_name(), network_protocol.error));
        }
        if let Err(parse_error) = network_protocol.value.parse::<NetworkProtocol>() {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'",
                    log_handler_name, self.type_name(), parse_error));
        }

        let remote_address = settings.get(log_handler_name, REMOTE_ADDRESS_KEY, "".to_string());
        if remote_address.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", 
                    log_handler_name, self.type_name(), remote_address.error));
        }


        match remote_address.value.parse::<IpAddr>() {
            Ok(address) => {
                if address.is_multicast() {
                    if network_protocol.value != MCAST_NETWORK_PROTOCOL {
                        return Err(format!("Log handler: '{}' type: '{}' error: {} is multicast address but {} is unicast",
                            log_handler_name, self.type_name(), REMOTE_ADDRESS_KEY, PROTOCOL_KEY));
                    }
                    let multicast_if = settings.get(log_handler_name, MULTICAST_IF_KEY, "".to_string()).value;
                    

                    if !multicast_if.is_empty() {
                        match multicast_if.parse::<IpAddr>() {
                            Ok(if_addr) => {
                                if if_addr.is_multicast() {
                                    return Err(format!("Log handler: '{}' type: '{}' error: {} has to be an unicast address",
                                        log_handler_name, self.type_name(), MULTICAST_IF_KEY));
                                }
                                if address.is_ipv4() && if_addr.is_ipv6() {
                                    return Err(format!("Log handler: '{}' type: '{}' error: {} is and IPV4 addrees while {} is and IVP6 address",
                                        log_handler_name, self.type_name(), REMOTE_ADDRESS_KEY, MULTICAST_IF_KEY));
                                }
                                if address.is_ipv6() && if_addr.is_ipv4() {
                                    return Err(format!("Log handler: '{}' type: '{}' error: {} is and IPV6 addrees while {} is and IVP4 address",
                                        log_handler_name, self.type_name(), REMOTE_ADDRESS_KEY, MULTICAST_IF_KEY));

                                }
                            },
                            Err(parse_error) => {
                                return Err(format!("Log handler: '{}' type: '{}' error: '{}' {}",
                                log_handler_name, self.type_name(), MULTICAST_IF_KEY, parse_error));                            
                            }
                        } 
                        if false == network_interface_exists(&multicast_if) {
                            return Err(format!("Log handler: '{}' type: '{}' error: {} '{}' is not a valid local network interface address",
                                log_handler_name, self.type_name(), MULTICAST_IF_KEY, multicast_if));
                        }
                    }
                } else {
                    if network_protocol.value == MCAST_NETWORK_PROTOCOL {
                        return Err(format!("Log handler: '{}' type: '{}' error: {} is unicast but {} is multicast",
                            log_handler_name, self.type_name(), REMOTE_ADDRESS_KEY, PROTOCOL_KEY));
                    }
                }        
            },
            Err(parse_error) =>  {
                return Err(format!("Log handler: '{}' type: '{}' error: '{}' {}",
                    log_handler_name, self.type_name(), REMOTE_ADDRESS_KEY, parse_error));        
            }
        }

        let remote_port = settings.get(log_handler_name, REMOTE_PORT_KEY, 0);

        if remote_port.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", 
                    log_handler_name, self.type_name(), remote_port.error));
        }

        if (remote_port.value <= 0) || (remote_port.value > u16::MAX as i32) {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}' has value '{}' that is out of range 1..{} ", 
                    log_handler_name, self.type_name(), REMOTE_PORT_KEY, remote_port.value, u16::MAX));
        }

        Ok(())
    }

    fn create_log_handler(&self, settings: &rssettings::Settings, log_handler_name: &str, appname: &str, appver: &str) -> Box<dyn crate::interfaces::LogHandler> {
        let mut enabled = false;
        let mut pattern =  String::new();
        let mut timestamp_format = String::new();
        let mut msg_types_enabled: [bool; LOG_MSG_TYPE_NUM] = [false, false, false, false, false]; 
        let mut msg_types_text: [String; LOG_MSG_TYPE_NUM] = [
            String::new(), String::new(), String::new(),
            String::new(), String::new()
        ];
        let mut message_format = String::new();
        get_log_handler_common_parameters(
            &mut enabled, &mut pattern, &mut timestamp_format,
            &mut msg_types_enabled, &mut msg_types_text,
            &mut message_format, settings, log_handler_name,
        pretty_function!());

        let protocol_type = settings.get(log_handler_name, PROTOCOL_KEY, "".to_string()).value;
        let protocol: NetworkProtocol = protocol_type.parse().unwrap_or(NetworkProtocol::UdpProtocol(UDP_NETWORK_PROTOCOL.to_string()));

        let mut address = settings.get(log_handler_name, REMOTE_ADDRESS_KEY, "".to_string()).value;
        let remote_address: IpAddr = address.parse().unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        
        address = settings.get(log_handler_name, MULTICAST_IF_KEY, "".to_string()).value;
        
        let multicast_if: IpAddr;
        if remote_address.is_ipv4() {
            multicast_if = address.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        } else {
            multicast_if = address.parse().unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        }
        let remote_port = settings.get(log_handler_name, REMOTE_PORT_KEY, 0u16).value;
        Box::new(
            NetworkLogHandler::new(log_handler_name.to_string(), 
            enabled,
            timestamp_format, 
            msg_types_enabled, 
            msg_types_text,
            message_format,
            pattern,
            appname.to_string(),
            appver.to_string(),
            protocol,
            remote_address,
            multicast_if,
            remote_port))
    }
}

#[derive(Serialize)]
struct NetworkJsonConfig {
    base: LogHandlerBase,
    protocol: String,
    remote_address: String
} 

struct NetworkLogHandler {
    base: LogHandlerBase,
    protocol: NetworkProtocol,
    remote_address: Option<SocketAddr>,
    socket: Option<Socket>,
    is_connected: bool, // TCP Only
    errors_list: Vec<ErrorKind>
}


impl NetworkLogHandler {
    fn new(name: String,
        enabled: bool,
        timestamp_format: String,
        msg_types_enabled: [bool; LOG_MSG_TYPE_NUM],
        msg_types_text: [String; LOG_MSG_TYPE_NUM],
        message_format: String, 
        pattern: String,
        appname: String,
        appver: String,
        protocol: NetworkProtocol,
        remote_address: IpAddr,
        multicast_if: IpAddr,
        remote_port: u16
    ) -> Self {
        let mut result = Self {
            base: LogHandlerBase::new(name,
                                    enabled,
                                    timestamp_format,
                                    msg_types_enabled,
                                    msg_types_text,
                                    message_format,
                                    pattern, appname, appver),
            protocol,
            remote_address: None,
            socket: None,
            is_connected: false,
            errors_list: vec![]
        };

        let is_multicast: bool = remote_address.is_multicast();
        result.remote_address = Some(SocketAddr::new(remote_address, remote_port));
        
        if let Err(error) = Self::create(&mut result) {
            eprintln!("Cannot create socket: {}", error);
        } else {
            let socket = result.socket.unwrap();
            println!("Log handler '{}' socket created to send log to: {} port {}", 
                    result.base.get_name(), remote_address.to_string(), remote_port);
            if is_multicast && !multicast_if.is_unspecified() {
                let itf_index = network_index(&multicast_if);
                match &multicast_if {
                    IpAddr::V4(interface) => {
                        if let Err(socket_error) = socket.set_multicast_if_v4(interface) {
                            eprintln!("Log handler '{}' cannot set IPV4 multicast interface: {}",
                                result.base.get_name(), socket_error);
                        } else {
                            println!("Log handler '{}' set multicast interface: {}", 
                                result.base.get_name(), interface.to_string())
                        }
                    },
                    IpAddr::V6(interface) => {
                        if let Some(itf_idx) = itf_index {
                            if let Err(socket_error) = socket.set_multicast_if_v6(itf_idx) {
                                eprintln!("Log handler '{}' cannot set IPV6 multicast interface: {}",
                                    result.base.get_name(), socket_error);
                            } else {
                                println!("Log handler '{}' set multicast interface: {}", 
                                    result.base.get_name(), interface.to_string())
                            }
                        }
                    }
                }
            }
            result.socket = Some(socket);
        }

    
        result
    }

    fn create(handler: &mut NetworkLogHandler) -> io::Result<()> {
        if let None = handler.socket {
            if let Some(remote_address) = handler.remote_address {
                let mut domain = Domain::IPV4;
                let mut socket_type = Type::DGRAM;
                if handler.protocol.unwrap() == TCP_NETWORK_PROTOCOL {
                    socket_type = Type::STREAM;
                }
                if remote_address.ip().is_ipv6() {
                        domain = Domain::IPV6;
                }
                handler.socket = Some(Socket::new(domain, socket_type, None)?);
            }
        }
        Ok(())
    }
    
}


impl LogHandler for NetworkLogHandler {
    fn get_name(&self) ->&String {
        self.base.get_name()
    }
    fn is_enabled(&self) ->bool {
        self.base.is_enabled()
    }

    fn is_msg_type_enabled(&self, msg_type: &LogMsgType) -> bool{
        self.base.is_msg_type_enabled(msg_type)
    }

    fn get_pattern(&self) ->&String {
        &self.base.get_pattern()
    }

    fn get_config(&self) -> Value {
        let config: NetworkJsonConfig = NetworkJsonConfig {
            base: self.base.clone(),
            protocol: self.protocol.to_string(),
            remote_address: format!("{}", self.remote_address.unwrap_or(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0u16)
            ))
        };
        match serde_json::to_value::<NetworkJsonConfig>(config) {
            Ok(value) => { value },
            Err(error) => { 
                let e = format!("{}", error);
                json!({"name": self.base.get_name(), "error": e})
            }
        }
    }

    fn log(&mut self, msg_type: &LogMsgType, log_message: &LogMessage) {
        if self.is_enabled() && self.is_msg_type_enabled(msg_type) {
            let mut formatted_message = log_message.formatted_message(
                self.base.get_message_format(),
                self.base.get_pattern(),
                self.base.get_appname(),
                self.base.get_appver(),
                self.base.get_timestamp_format(),
                self.base.get_msg_types_text());


            if let Some(socket_addres) = self.remote_address {
                let protocol_type = self.protocol.unwrap();
                if (protocol_type == UDP_NETWORK_PROTOCOL) ||
                   (protocol_type == MCAST_NETWORK_PROTOCOL) {
                    if let Some(udp_socket) = &self.socket {
                        if let Err(ioerror) = udp_socket.send_to(formatted_message.as_bytes(), &socket_addres.into()) {
                            if !self.errors_list.contains(&ioerror.kind()) {
                                eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                        self.base.get_name(), self.protocol, ioerror);
                                self.errors_list.push(ioerror.kind());
                            }
                        }
                    }
                } else if protocol_type == TCP_NETWORK_PROTOCOL {
                    formatted_message.push(0x03 as char);
                    if let Some(socket) = &self.socket {
                        if !self.is_connected {
                            if let Err(ioerror) = socket.connect(&socket_addres.into()) {
                                if !self.errors_list.contains(&ioerror.kind()) {
                                    eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                            self.base.get_name(), self.protocol, ioerror);
                                    self.errors_list.push(ioerror.kind());
                                }
                            } else {
                                println!("Log handler '{}' protocol '{}' connected to: {:#?}", 
                                    self.base.get_name(), self.protocol, socket_addres);
                                self.is_connected = true;
                                self.errors_list.clear();
                            }
                        }

                        if self.is_connected {
                            if let Err(ioerror) = socket.send(&formatted_message.as_bytes()) {
                                if !self.errors_list.contains(&ioerror.kind()) {
                                    eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                            self.base.get_name(), self.protocol, ioerror);
                                    self.errors_list.push(ioerror.kind());
                                }
                                self.is_connected = false;
                                self.socket = None;
                                if let Err(ioerror) = Self::create(self) {
                                    if !self.errors_list.contains(&ioerror.kind()) {
                                        eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                                self.base.get_name(), self.protocol, ioerror);
                                        self.errors_list.push(ioerror.kind());
                                    }
                                } else {
                                    self.errors_list.clear();
                                }
                            }
                        }
                    }
                }
            }                
        }
    }
}


enum UnixDomainProtocol {
    UdpProtocol(String),
    TcpProtocol(String)
}

impl UnixDomainProtocol {
    fn unwrap(&self) -> &String {
        match self {
            Self::UdpProtocol(value) => { value }
            Self::TcpProtocol(value) => { value }
        }
    }
}

impl PartialEq for UnixDomainProtocol {
    fn eq(&self, other: &Self) -> bool {
        self.unwrap() == other.unwrap()
    }
}

struct UnixDomainProtocolFormatError {
    message: String
}

impl Display for UnixDomainProtocolFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl FromStr for UnixDomainProtocol {
    type Err = UnixDomainProtocolFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lowercase = s.to_lowercase();
        if UDP_NETWORK_PROTOCOL == s_lowercase {
            Ok(UnixDomainProtocol::UdpProtocol(UDP_NETWORK_PROTOCOL.to_string()))
        } else if TCP_NETWORK_PROTOCOL == s_lowercase {
            Ok(UnixDomainProtocol::TcpProtocol(TCP_NETWORK_PROTOCOL.to_string()))
        } else {
            Err(UnixDomainProtocolFormatError{message: format!("Invalid unix domain protocol '{}' valid are: {}",
                s, VALID_NETWORK_PROTOCOLS.join(", "))})
        }
    }
}

impl Display for UnixDomainProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.unwrap())
    }
}


pub (crate) struct UnixDomainLogHandlerFactory {

}

impl LogHandlerFactory for UnixDomainLogHandlerFactory {
    fn type_name(&self) -> &str {
        "unix-domain"
    }

    fn check_parameters(&self, settings: &rssettings::Settings, log_handler_name: &str) -> Result<(), String> {
        check_log_handler_common_parameters(settings, self.type_name(), log_handler_name)?;

        let unixdomain_protocol = settings.get(log_handler_name,PROTOCOL_KEY, "".to_string());
        if unixdomain_protocol.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", 
                    log_handler_name, self.type_name(), unixdomain_protocol.error));
        }
        if let Err(parse_error) = unixdomain_protocol.value.parse::<UnixDomainProtocol>() {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'",
                    log_handler_name, self.type_name(), parse_error));
        }

        if cfg!(windows) && unixdomain_protocol.value == UDP_NETWORK_PROTOCOL {
            return Err(format!("Log handler: '{}' type: '{}' error: protocol '{}' is not valid on windows systems",
                    log_handler_name, self.type_name(), unixdomain_protocol.value));
        }

        let mut sun_path = settings.get(log_handler_name, SUN_PATH_KEY, String::from(""));
        if sun_path.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", 
                    log_handler_name, self.type_name(), unixdomain_protocol.error));
        }
        if sun_path.value.is_empty() {
            return Err(format!("Log handler: '{}' type: '{}' {}: is empty", 
                    log_handler_name, self.type_name(), SUN_PATH_KEY));
        }

        let mut env_var_name = "";
        let mut env_var_value = String::new();
        if let Some(start) = sun_path.value.find("${") {
            if let Some(end) = sun_path.value.find("}") {
                if start < end {
                    env_var_name = &sun_path.value[start + 2..end];
                    match std::env::var(env_var_name) {
                        Ok(value) => {
                            env_var_value = value;
                        },
                        Err(error) => {
                            return Err(format!("Log handler: '{}' type: '{}'  {} error: '{}' - {} ", 
                                log_handler_name, self.type_name(), SUN_PATH_KEY, env_var_name, error));    
                        }
                    }                    
                }
            }
        }
        
        if !env_var_name.is_empty() {
            sun_path.value = sun_path.value.replace(env_var_name, &env_var_value);
        }
        if let Err(error) = SockAddr::unix(&sun_path.value) {
            return Err(format!("Log handler: '{}' type: '{}'  {} error: '{}' - {}", 
                log_handler_name, self.type_name(), SUN_PATH_KEY, sun_path.value, error));    
        }


        Ok(())
    }

    fn create_log_handler(&self, settings: &rssettings::Settings, log_handler_name: &str, appname: &str, appver: &str) -> Box<dyn LogHandler> {
        let mut enabled = false;
        let mut pattern =  String::new();
        let mut timestamp_format = String::new();
        let mut msg_types_enabled: [bool; LOG_MSG_TYPE_NUM] = [false, false, false, false, false]; 
        let mut msg_types_text: [String; LOG_MSG_TYPE_NUM] = [
            String::new(), String::new(), String::new(),
            String::new(), String::new()
        ];
        let mut message_format = String::new();
        get_log_handler_common_parameters(
            &mut enabled, &mut pattern, &mut timestamp_format,
            &mut msg_types_enabled, &mut msg_types_text,
            &mut message_format, settings, log_handler_name,
        pretty_function!());

        
        let unixdomain_protocol = settings.get(log_handler_name,PROTOCOL_KEY, "".to_string()).value;
        let protocol: UnixDomainProtocol = unixdomain_protocol.parse().unwrap_or(UnixDomainProtocol::UdpProtocol(UDP_NETWORK_PROTOCOL.to_string()));

        let mut remote_address = settings.get(log_handler_name, SUN_PATH_KEY, String::from("")).value;
        if let Some(start) = remote_address.find("${") {
            if let Some(end) = remote_address.find("}") {
                if start < end {
                    let env_var_name = String::from(&remote_address[start + 2..end]);
                    let env_var_value = &std::env::var(&env_var_name).unwrap_or(String::new());
                    if !env_var_value.is_empty() {
                        remote_address = remote_address.replace("${", "")
                                    .replace("}", "")
                                    .replace(&env_var_name, env_var_value);
                    }
                }
            }
        }
        if cfg!(windows) {
            remote_address = remote_address.replace("/", "\\");
        } else {
            remote_address = remote_address.replace("\\", "/");
        }
        Box::new(UnixDomainLogHandler::new(log_handler_name.to_string(),
                                enabled,
                                timestamp_format, 
                                msg_types_enabled, 
                                msg_types_text,
                                message_format,
                                pattern,
                                appname.to_string(),
                                appver.to_string(),
                                protocol,
                                remote_address))
    }
}

#[derive(Serialize)]
struct UnixDomainJsonConfig {
    base: LogHandlerBase,
    protocol: String,
    remote_address: String,
}

struct UnixDomainLogHandler {
    base: LogHandlerBase,
    protocol: UnixDomainProtocol,
    remote_address: String,
    socket: Option<Socket>,
    is_connected: bool, // TCP Only
    errors_list: Vec<ErrorKind>
}


impl UnixDomainLogHandler {
    fn new(name: String,
        enabled: bool,
        timestamp_format: String,
        msg_types_enabled: [bool; LOG_MSG_TYPE_NUM],
        msg_types_text: [String; LOG_MSG_TYPE_NUM],
        message_format: String, 
        pattern: String,
        appname: String,
        appver: String,
        protocol: UnixDomainProtocol,
        remote_address: String) -> Self {
            let mut result = Self {
                base: LogHandlerBase::new(name,
                    enabled,
                    timestamp_format,
                    msg_types_enabled,
                    msg_types_text,
                    message_format,
                    pattern, appname, appver),
                protocol,
                remote_address,
                socket: None,
                is_connected: false,
                errors_list: vec![]             
            };
            if let Err(error) = Self::create(&mut result) {
                eprintln!("Log handler '{}' cannot create socket: {}", 
                    result.base.get_name(), error);
            } else {
                println!("Log handler '{}' socket created to send log to: {}", 
                        result.base.get_name(), result.remote_address);

            }
            result
    }

    fn create(handler: &mut UnixDomainLogHandler) -> io::Result<()> {
        if let None = handler.socket {
            if !handler.remote_address.is_empty() {
                let mut socket_type = Type::DGRAM;
                if handler.protocol.unwrap() == TCP_NETWORK_PROTOCOL {
                    socket_type = Type::STREAM;
                }
                handler.socket = Some(Socket::new(Domain::UNIX, socket_type, None)?);
            }
        }
        println!("OK");
        Ok(())
    }
}

impl LogHandler for UnixDomainLogHandler {
    fn get_name(&self) ->&String {
        self.base.get_name()
    }
    fn is_enabled(&self) ->bool {
        self.base.is_enabled()
    }

    fn is_msg_type_enabled(&self, msg_type: &LogMsgType) -> bool{
        self.base.is_msg_type_enabled(msg_type)
    }

    fn get_pattern(&self) ->&String {
        &self.base.get_pattern()
    }

    fn get_config(&self) -> Value {
        let config: UnixDomainJsonConfig = UnixDomainJsonConfig {
            base: self.base.clone(),
            protocol: self.protocol.to_string(),
            remote_address: self.remote_address.clone()
        };
        match serde_json::to_value::<UnixDomainJsonConfig>(config) {
            Ok(value) => { value },
            Err(error) => { 
                let e = format!("{}", error);
                json!({"name": self.base.get_name(), "error": e})
            }
        }
    }


    fn log(&mut self, msg_type: &LogMsgType, log_message: &LogMessage) {
        if self.is_enabled() && self.is_msg_type_enabled(msg_type) {
            let mut formatted_message = log_message.formatted_message(
                self.base.get_message_format(),
                self.base.get_pattern(),
                self.base.get_appname(),
                self.base.get_appver(),
                self.base.get_timestamp_format(),
                self.base.get_msg_types_text());
            let protocol_type = self.protocol.unwrap();
            if let Ok(remote_address) = SockAddr::unix(&self.remote_address) {
                if protocol_type == UDP_NETWORK_PROTOCOL {
                    if let Some(udp_socket) = &self.socket {
                        if let Err(ioerror) = udp_socket.send_to(formatted_message.as_bytes(), &remote_address) {
                            if !self.errors_list.contains(&ioerror.kind()) {
                                eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                        self.base.get_name(), self.protocol, ioerror);
                                self.errors_list.push(ioerror.kind());
                            }
                        }
                    }    
                } else if protocol_type == TCP_NETWORK_PROTOCOL {
                    formatted_message.push(0x03 as char);
                    if let Some(socket) = &self.socket {
                        if !self.is_connected {
                            if let Err(ioerror) = socket.connect(&remote_address) {
                                if !self.errors_list.contains(&ioerror.kind()) {
                                    eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                            self.base.get_name(), self.protocol, ioerror);
                                    self.errors_list.push(ioerror.kind());
                                }
                            } else {
                                println!("Log handler '{}' protocol '{}' connected to: {:#?}", 
                                    self.base.get_name(), self.protocol, self.remote_address);
                                self.is_connected = true;
                                self.errors_list.clear();
                            }
                        }

                        if self.is_connected {
                            if let Err(ioerror) = socket.send(&formatted_message.as_bytes()) {
                                if !self.errors_list.contains(&ioerror.kind()) {
                                    eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                            self.base.get_name(), self.protocol, ioerror);
                                    self.errors_list.push(ioerror.kind());
                                }
                                self.is_connected = false;
                                self.socket = None;
                                if let Err(ioerror) = Self::create(self) {
                                    if !self.errors_list.contains(&ioerror.kind()) {
                                        eprintln!("Log handler '{}' protocol '{}' io error: '{:#}'", 
                                                self.base.get_name(), self.protocol, ioerror);
                                        self.errors_list.push(ioerror.kind());
                                    }
                                } else {
                                    self.errors_list.clear();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}