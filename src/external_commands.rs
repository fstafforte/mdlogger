use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::from_utf8;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::Builder;
use std::time::Duration;
use std::{sync::{Arc, Mutex}, thread::JoinHandle};
use rssettings::Settings;

use rssettings::GLOBAL_SECTION;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use socket2::{Domain, Socket, Type};

use crate::constants::{
    CRITICAL_ENABLED_KEY, CRITICAL_TEXT_KEY, DEBUG_ENABLED_KEY, DEBUG_TEXT_KEY, DEFAULT_CRITICAL_TEXT, DEFAULT_DEBUG_TEXT, DEFAULT_FATAL_TEXT, DEFAULT_INFO_TEXT, DEFAULT_PATTERN_VALUE, DEFAULT_TIMESTAMP_FORMAT, DEFAULT_WARNING_TEXT, ENABLED_KEY, FATAL_TEXT_KEY, INFO_ENABLED_KEY, INFO_TEXT_KEY, PATTERN_KEY, ROOT_LOG_HANDLER_KEY, TIMESTAMP_FORMAT_KEY, WARNING_ENABLED_KEY, WARNING_TEXT_KEY};
use crate::interfaces::LogHandler;

use crate::{format, mdlogger_cinfo, pretty_function, set_mdlogger_enabled};
use crate::utils::{network_index, network_interface_exists};

const EXTERNAL_COMMNDS_THREAD_NAME: &str = "ExternalCommandsThread";
pub(crate) const EXTERNAL_COMMNDS_MESSAGE: &str = "__EXTERNAL_COMMND_MESSAGE__";
const EXTERNAL_COMMNDS_MESSAGE_SEP: &str = ".";
const EXTERNAL_COMMNDS_CATEGORY: &str = "external.commands";

const EXT_CMDS_IPADDR_KEY: &str = "external_command.ipaddress";
const EXT_CMDS_PORT_KEY: &str = "external_command.port";
const EXT_CMDS_MCAST_ITF_KEY: &str = "external_command.multicast_if";

const EXT_CMD_GET_CONFIG: &str = "get-config";
const EXT_CMD_SET_GLOBAL: &str = "set-global";
const EXT_CMD_SET_HANDLER: &str = "set-handler";

const VALID_EXT_CMDS: [&str; 3] = [
    EXT_CMD_GET_CONFIG,
    EXT_CMD_SET_GLOBAL,
    EXT_CMD_SET_HANDLER
];

pub const PARAMETER_KEY_NAME: &str = "name";
pub const PARAMETER_VALUE_NAME: &str = "value";
pub const PARAMETER_SAVE_NAME: &str = "save";


#[derive(Deserialize)]
struct ExternalCommandParameter {
    name: String,
    value: Value
}

#[derive(Deserialize)]
struct ExternalCommand {
    command: String,
    parameters: Vec<ExternalCommandParameter>
}

impl ExternalCommand {
    fn get_paramter(&self, name: &str) -> Option<Value> {
        for param in &self.parameters {
            if param.name == name {
                return Some(param.value.clone());
            } 
        }
        None
    }
}

#[derive(Serialize)]
enum AckNack {
    NACK = -1,
    ACK = 0,
    PARTIALACK = 1
}

#[derive(Serialize)]
struct ExternalCommandAnswer {
    ack_nack: AckNack,
    nack_reason: String,
    value: Value, 
}

// #[derive(Serialize)]
// struct GlobalConfiguration {
//     enabled: bool,
//     pattern: String,
//     timestamp_format: String,
//     msg_types_enabled: [bool; LOG_MSG_TYPE_NUM],
//     msg_types_text: [String; LOG_MSG_TYPE_NUM],
//     root_log_handler: String,
//     log_handlers: Value
// }

pub (crate) fn create_external_commands_thread(settings: &Settings,
        answer_rx_channel: Receiver<String>) -> Option<(JoinHandle<()>, Arc<Mutex<bool>>)> {
    let ext_cmds_ipaddr = settings.get(GLOBAL_SECTION, EXT_CMDS_IPADDR_KEY, String::new());
    if ext_cmds_ipaddr.error.len() > 0 {
        eprintln!("{} settings error: {} external commands will not be executed", 
            EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_ipaddr.error);
        return None;
    }
    if ext_cmds_ipaddr.value.is_empty() {
        eprintln!("{} settings error: ip address is empty external commands will not be executed", 
            EXTERNAL_COMMNDS_THREAD_NAME);
        return None;
    }
    let ipaddr = ext_cmds_ipaddr.value.parse::<IpAddr>(). unwrap_or_else(|e| {
        eprintln!("{} ip address settings error: {} external commands will not be executed", 
            EXTERNAL_COMMNDS_THREAD_NAME, e);        
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    });
    if ipaddr.is_unspecified() {
        return None;
    }

    let ext_cmds_port = settings.get(GLOBAL_SECTION, EXT_CMDS_PORT_KEY, -1i32);
    if ext_cmds_port.error.len() > 0 {
        eprintln!("{} ip port settings error: {} external commands will not be executed", 
            EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_port.error);
        return None;
    }

    if (ext_cmds_port.value < 1) || (ext_cmds_port.value > u16::MAX as i32) {
        eprintln!("{} ip port settings error: external commands port {} out of range 1..{}", 
            EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_port.value, u16::MAX);
        return None;
    }
    let mut multicast_itf = Ipv4Addr::UNSPECIFIED.to_string();
    let mut ext_cmds_sock_addr = format!("{}:{}", ext_cmds_ipaddr.value, ext_cmds_port.value); 
    if ipaddr.is_ipv6() {
        ext_cmds_sock_addr = format!("[{}]:{}",  ext_cmds_ipaddr.value, ext_cmds_port.value);
        multicast_itf = Ipv6Addr::UNSPECIFIED.to_string();
    }
    if ipaddr.is_multicast() && 
       settings.key_exists(GLOBAL_SECTION, EXT_CMDS_MCAST_ITF_KEY) {
        let interface = settings.get(GLOBAL_SECTION, EXT_CMDS_MCAST_ITF_KEY, String::new()).value;
        if !interface.is_empty() {
            if true == network_interface_exists(&interface) {
                multicast_itf = interface;
            } else {
                eprintln!("{} settings error: network interface {} does not exist!!!",
                    EXTERNAL_COMMNDS_THREAD_NAME, interface);
                return None;
            }
        } else {
            eprintln!("{} settings error: network interface is empty!!! any network interface will be used",
                EXTERNAL_COMMNDS_THREAD_NAME);
        }
    }
    let ext_cmds_sock_addr: SocketAddr = ext_cmds_sock_addr.parse().unwrap();
    let multicast_itf: IpAddr = multicast_itf.parse().unwrap();

    if ext_cmds_sock_addr.ip().is_multicast() {
        if ext_cmds_sock_addr.is_ipv4() && multicast_itf.is_ipv6() {
            eprintln!("{} settings error: ip address is an IPV4 address while network interface is IPV6",
                EXTERNAL_COMMNDS_THREAD_NAME);
            return None;
        }
        if ext_cmds_sock_addr.ip().is_ipv6() && multicast_itf.is_ipv4() {
            eprintln!("{} settings error: ip address is an IPV6 address while network interface is IPV4",
                EXTERNAL_COMMNDS_THREAD_NAME);
            return None;
        }
    }

    let mut domain = Domain::IPV4;
    if ext_cmds_sock_addr.is_ipv6() {
        domain = Domain::IPV6;
    }    

    let commands_socket: Socket; 
    match Socket::new(domain, Type::DGRAM, None) {
        Ok(socket) => {
            commands_socket = socket;
        },
        Err(error) => {
            eprintln!("{} cannot create socket to receive commands: {}", 
                EXTERNAL_COMMNDS_THREAD_NAME, error);
            return None;
        }
    }
    if let Err(error) = commands_socket.set_reuse_address(true) {
        eprintln!("{} cannot set socket reuse address: {}", 
            EXTERNAL_COMMNDS_THREAD_NAME, error);
        return None;
    }

    if let Err(error) = commands_socket.set_read_timeout(Some(Duration::from_millis(250))) {
        eprintln!("{} cannot set socket read timeout: {}", 
            EXTERNAL_COMMNDS_THREAD_NAME, error);
        return None;
    }

    if ext_cmds_sock_addr.ip().is_multicast() {
        let bind_address: SocketAddr;
        let mut join_address_v4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
        let mut join_address_v6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
        match ext_cmds_sock_addr.ip() {
            IpAddr::V4(address) => {
                bind_address = format!("{}:{}", Ipv4Addr::UNSPECIFIED, ext_cmds_sock_addr.port()).as_str().parse().unwrap();
                join_address_v4 = address;
            },
            IpAddr::V6(address) => {
                bind_address = format!("[{}]:{}", Ipv6Addr::UNSPECIFIED, ext_cmds_sock_addr.port()).as_str().parse().unwrap();
                join_address_v6 = address;
            }
        }
        if let Err(error) = commands_socket.bind(&bind_address.into()) {
            eprintln!("{} cannot bind socket to: {}, {}", 
                EXTERNAL_COMMNDS_THREAD_NAME, bind_address, error);
            return None;
        }
        let join_result: std::io::Result<()>;
        let mut join_mcast_itf: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
        let mut join_mcast_idx = 0;
        if !multicast_itf.is_unspecified() {
             join_mcast_idx = network_index(&multicast_itf).unwrap_or(0u32);
        }
        match multicast_itf {
            IpAddr::V4(address) => {
                join_mcast_itf = address;
            }
            _=> {
                
            }
        }
        if ext_cmds_sock_addr.is_ipv4() {
            join_result = commands_socket.join_multicast_v4(&join_address_v4, &join_mcast_itf);
        } else {                        
            join_result = commands_socket.join_multicast_v6(&join_address_v6, join_mcast_idx);
        }
        if let Err(error) = join_result {
            if ext_cmds_sock_addr.is_ipv4() {
                eprintln!("{} cannot join multicast address {:#?} interface address {:#?}, {},", 
                    EXTERNAL_COMMNDS_THREAD_NAME, join_address_v4, join_mcast_itf, error);
                    return None;
            }
            eprintln!("{} cannot join multicast address {:#?} interface idx {:#?}, {},", 
                EXTERNAL_COMMNDS_THREAD_NAME, join_address_v6, join_mcast_idx, error);
                return None;
        }

        
        if multicast_itf.is_unspecified() {
            println!("{} waiting message on {} from any network ineterface", 
                EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_sock_addr);
        } else {
            if multicast_itf.is_ipv4() {
                println!("{} waiting message on {} from network ineterface {}", 
                EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_sock_addr, multicast_itf);
            } else {
                println!("{} waiting message on {} from network ineterface index {}", 
                        EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_sock_addr, join_mcast_idx);
            }
        }
    } else {
        if let Err(error) = commands_socket.bind(&ext_cmds_sock_addr.into()) {
            eprintln!("{} cannot bind socket to: {}, {}", 
                EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_ipaddr.value, error);
            return None;
        }
        println!("{} Waiting commands on {}", EXTERNAL_COMMNDS_THREAD_NAME, ext_cmds_sock_addr);     
    }

    let commands_thread_builder: Builder = Builder::new().name(String::from(EXTERNAL_COMMNDS_THREAD_NAME));
    let commands_running: Arc<Mutex<bool>> = Arc::new(Mutex::new(true));
    let commands_running1: Arc<Mutex<bool>> = commands_running.clone();
    
    let commands_thread_handle = match commands_thread_builder.spawn(move || {
        commands_thread_function(answer_rx_channel,
                                    commands_socket,
                                    commands_running1);
        }) {
        Ok(join_handle) => {
            Some((join_handle, commands_running))
        },
        Err(error) => {
            eprintln!("Cannot create external commands thread: {}", error);
            None
        }
    }; 
    commands_thread_handle           
}


pub(crate) fn join_create_external_commands_thread(commands_thread_result: Option<(JoinHandle<()>, Arc<Mutex<bool>>)>) {
    match commands_thread_result {
        Some((join_handle, running)) => {
            set_running(&running, false);
            let _ = join_handle.join().unwrap_or_else(|_e| {                
                eprintln!("{} error joining thread", EXTERNAL_COMMNDS_THREAD_NAME);
                ()             
            });
        },
        None => {

        }
    }
}

pub (crate) fn commands_thread_function(answer_rx_channel: Receiver<String>,
                                        commands_socket: Socket,
                                        commands_running1: Arc<Mutex<bool>>) {

    let mut buf: [MaybeUninit<u8>; u16::MAX as usize] = unsafe {
        MaybeUninit::zeroed().assume_init()    
    };
    let mut error_list: Vec<ErrorKind> = vec![];
    while is_running(&commands_running1) {
        match commands_socket.recv_from(&mut buf) {
            Ok((receive_len, from)) => {
                let mut message: Vec<u8> = Vec::with_capacity(receive_len);
                for i in 0..receive_len {
                    message.push(unsafe { *buf[i].as_ptr() });
                }
                let message = from_utf8(&message).unwrap_or_else(|e| {
                    eprintln!("{} convert to and utf8 string error: {}", 
                            EXTERNAL_COMMNDS_THREAD_NAME, e);
                    ""
                });
                if !message.is_empty() {
                    println!("Command received from: {}: {}", from.as_socket().unwrap(), message);
                    mdlogger_cinfo!(EXTERNAL_COMMNDS_CATEGORY, "{}{}{}", 
                        EXTERNAL_COMMNDS_MESSAGE, EXTERNAL_COMMNDS_MESSAGE_SEP, message);
                    match answer_rx_channel.recv() {
                        Ok(answer) => {
                            if let Err(error) = commands_socket.send_to(answer.as_bytes(), &from) {
                                eprintln!("{} send answer error: {}", 
                                    EXTERNAL_COMMNDS_THREAD_NAME, error);                                    
                            }
                        },
                        Err(error) => {
                            eprintln!("{} answer rx channel error: {}", 
                            EXTERNAL_COMMNDS_THREAD_NAME, error);                                                    }
                    }
                }
            },
            Err(error) => {
                if (error.kind() != ErrorKind::TimedOut) && 
                    error_list.contains(&error.kind()) {
                        eprintln!("{} receiving error: {}", EXTERNAL_COMMNDS_THREAD_NAME, error);
                        error_list.push(error.kind());
                }
            }
        }
    }

}

pub (crate) fn is_running(running: &Arc<Mutex<bool>>) -> bool {
    let guard = running.lock().unwrap_or_else(
        |poinson_error| {
            poinson_error.into_inner()
        }
    );
    *guard
}

pub(crate) fn set_running(running: &Arc<Mutex<bool>>, value: bool) {
    let mut guard = running.lock().unwrap_or_else(
        |poinson_error| {
            poinson_error.into_inner()
        }
    );
    *guard = value;
}                        

pub(crate) fn execute_external_commands(answer_tx_channel: &Sender<String>,
                                        command: String,
                                        log_handlers: &Vec<Box<dyn LogHandler>>,
                                        settings: &mut Settings) {
    let json_command = command.replace(EXTERNAL_COMMNDS_MESSAGE, "").
                                            replace(EXTERNAL_COMMNDS_MESSAGE_SEP, "");
    
    let mut answer = ExternalCommandAnswer {ack_nack: AckNack::ACK, 
        nack_reason: String::new(),
        value: Value::Null};
    match serde_json::from_str::<ExternalCommand>(&json_command) {
        Ok(external_command) => {
            if VALID_EXT_CMDS.contains(&external_command.command.as_str()) {
                if external_command.command == EXT_CMD_GET_CONFIG {
                    exec_get_config(&mut answer, log_handlers, settings);
                }
                if external_command.command == EXT_CMD_SET_GLOBAL {
                    exec_set_global_command(&external_command, &mut answer, settings);
                } else if external_command.command == EXT_CMD_SET_HANDLER {
                    exec_set_handler_command(&external_command, log_handlers, &mut answer, settings);
                }
            } else {
                answer.ack_nack = AckNack::NACK;
                answer.nack_reason = format!("{} is not a valid command valid are: {}", 
                        external_command.command, VALID_EXT_CMDS.join(", "));
            }
        },
        Err(error) => {
            answer.ack_nack = AckNack::NACK;
            answer.nack_reason = format!("invalid json format: {}", error);
        }
    }
    let answer = serde_json::to_string(&answer).unwrap_or_else(|e| {
        eprintln!("{} wrong external command answer serializing: {}", EXTERNAL_COMMNDS_THREAD_NAME, e);
        format!("{{ \"ack_nack\": \"NACK\", \"nack_reason\": \"{}\" }}", e)
    });

    if let Err(error) = answer_tx_channel.send(answer) {
        eprintln!("{} error sending answer: {}", EXTERNAL_COMMNDS_THREAD_NAME, error);
    }
}


fn exec_get_config(answer: &mut ExternalCommandAnswer,
                    log_handlers: &Vec<Box<dyn LogHandler>>,
                    settings: &mut Settings) {
                            
    let mut all_config: Map<String, Value> = Map::new();
    let global_section = get_global(settings);
    all_config.insert("global".to_string(), global_section);
    let mut log_handlers_value: Vec<Value> = vec![];

    for log_handler in log_handlers {
        log_handlers_value.push(log_handler.get_config())
    }

    all_config.insert("log_handlers".to_string(), Value::Array(log_handlers_value));

    answer.ack_nack = AckNack::ACK;
    answer.value = Value::Object(all_config);

}

fn get_global(settings: &Settings) -> Value {
    let mut global_section : Map<String, Value> = Map::new();
    global_section.insert(ENABLED_KEY.to_string(), 
        json!(settings.get(GLOBAL_SECTION, ENABLED_KEY, true).value));
    global_section.insert(PATTERN_KEY.to_string(),
            json!(settings.get(GLOBAL_SECTION, PATTERN_KEY, DEFAULT_PATTERN_VALUE.to_string()).value));
    global_section.insert(TIMESTAMP_FORMAT_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, TIMESTAMP_FORMAT_KEY, DEFAULT_TIMESTAMP_FORMAT.to_string()).value));
    
    global_section.insert(DEBUG_ENABLED_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, DEBUG_ENABLED_KEY, true).value));
    global_section.insert(INFO_ENABLED_KEY.to_string(),    
        json!(settings.get(GLOBAL_SECTION, INFO_ENABLED_KEY, true).value));
    global_section.insert(WARNING_ENABLED_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, WARNING_ENABLED_KEY, true).value));
    global_section.insert(CRITICAL_ENABLED_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, CRITICAL_ENABLED_KEY, true).value));
    
    global_section.insert(DEBUG_TEXT_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, DEBUG_TEXT_KEY, DEFAULT_DEBUG_TEXT.to_string()).value));
    global_section.insert(INFO_TEXT_KEY.to_string(), 
        json!(settings.get(GLOBAL_SECTION, INFO_TEXT_KEY, DEFAULT_INFO_TEXT.to_string()).value));
    global_section.insert(WARNING_TEXT_KEY.to_string(), 
        json!(settings.get(GLOBAL_SECTION, WARNING_TEXT_KEY, DEFAULT_WARNING_TEXT.to_string()).value));
    global_section.insert(CRITICAL_TEXT_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, CRITICAL_TEXT_KEY, DEFAULT_CRITICAL_TEXT.to_string()).value));
    global_section.insert(FATAL_TEXT_KEY.to_string(),
        json!(settings.get(GLOBAL_SECTION, FATAL_TEXT_KEY, DEFAULT_FATAL_TEXT.to_string()).value));
    global_section.insert(ROOT_LOG_HANDLER_KEY.to_string(),
    json!(settings.get(GLOBAL_SECTION, ROOT_LOG_HANDLER_KEY, String::from("")).value));

    global_section.insert(EXT_CMDS_IPADDR_KEY.to_string(), 
        json!(settings.get(GLOBAL_SECTION, EXT_CMDS_IPADDR_KEY, String::from("")).value));

    global_section.insert(EXT_CMDS_PORT_KEY.to_string(), 
        json!(settings.get(GLOBAL_SECTION, EXT_CMDS_PORT_KEY, 0u16).value));
    
    Value::Object(global_section)
}


fn has_tobe_saved(external_command: &ExternalCommand,
                    answer: &mut ExternalCommandAnswer) -> bool {
    let mut result = false;
    if let Some(_save) = external_command.get_paramter(PARAMETER_SAVE_NAME) {
        if let Some(value) = external_command.get_paramter(PARAMETER_VALUE_NAME) {
            if value.is_boolean() {
                result = value.as_bool().unwrap_or(false); 
            } else {
                answer.ack_nack = AckNack::PARTIALACK;
                answer.nack_reason = format!("parameter {} has not a boolean value", PARAMETER_SAVE_NAME);    
            }
        } else {
            answer.ack_nack = AckNack::PARTIALACK;
            answer.nack_reason = format!("parameter {} missing {}", PARAMETER_SAVE_NAME, PARAMETER_VALUE_NAME);
        }
    }
    return result;
}

fn exec_set_global_command(external_command: &ExternalCommand, 
                        answer: &mut ExternalCommandAnswer,
                        settings: &mut Settings) {

    if external_command.parameters.len() > 0 {

        if let Some(key) = external_command.get_paramter(PARAMETER_KEY_NAME) {
            if let Some(value) = external_command.get_paramter(PARAMETER_VALUE_NAME) {
                if key.is_string() {
                    if !value.is_array() && !value.is_null() && !value.is_object() {
                        let key = key.as_str().unwrap_or("");
                        if settings.key_exists(GLOBAL_SECTION, key) {
                            if ENABLED_KEY == key {
                                if let Some(enabled) = value.as_bool() {
                                    set_mdlogger_enabled(enabled);
                                    answer.ack_nack = AckNack::ACK;                                    
                                    if has_tobe_saved(external_command, answer) {
                                        if let Err(error) = settings.set(GLOBAL_SECTION, key, enabled) {
                                            answer.ack_nack = AckNack::PARTIALACK;
                                            answer.nack_reason = error;
                                        }
                                    }
                                } else {
                                    answer.ack_nack = AckNack::NACK;
                                    answer.nack_reason = format!("{} need a boolean value", key)
                                }
                            }
                        } else {
                            answer.ack_nack = AckNack::NACK;
                            answer.nack_reason = format!("parameter {} => {} not found", 
                                PARAMETER_KEY_NAME, key);    
                            }
                    } else {
                        answer.ack_nack = AckNack::NACK;
                        answer.nack_reason = format!("parameter {} cannot be an array nor a null nor an object", PARAMETER_VALUE_NAME);    
                    }
                } else {
                    answer.ack_nack = AckNack::NACK;
                    answer.nack_reason = format!("parameter {} has to be a string", PARAMETER_KEY_NAME);    
                }
            } else {
                answer.ack_nack = AckNack::NACK;
                answer.nack_reason = format!("missing {} parameter", PARAMETER_VALUE_NAME);    
            }
        } else {
            answer.ack_nack = AckNack::NACK;
            answer.nack_reason = format!("missing {} parameter", PARAMETER_KEY_NAME);
        }

    } else {
        answer.ack_nack = AckNack::NACK;
        answer.nack_reason = format!("command '{}' needs 1 parameter at least", external_command.command);
    }
}

fn exec_set_handler_command(external_command: &ExternalCommand,
                        log_handlers: &Vec<Box<dyn LogHandler>>,
                        answer: &mut ExternalCommandAnswer,
                        settings: &mut Settings) {

}