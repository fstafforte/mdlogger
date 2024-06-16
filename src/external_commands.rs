use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::from_utf8;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::Builder;
use std::time::Duration;
use std::usize;
use std::{sync::{Arc, Mutex}, thread::JoinHandle};
use rssettings::Settings;
use time::format_description; 
use rssettings::GLOBAL_SECTION;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use socket2::{Domain, Socket, Type};

use crate::constants::{
    CRITICAL_ENABLED_KEY, CRITICAL_TEXT_KEY, DEBUG_ENABLED_KEY, DEBUG_TEXT_KEY, DEFAULT_CRITICAL_TEXT, DEFAULT_DEBUG_TEXT, DEFAULT_FATAL_TEXT, DEFAULT_INFO_TEXT, DEFAULT_PATTERN_VALUE, DEFAULT_TIMESTAMP_FORMAT, DEFAULT_WARNING_TEXT, ENABLED_KEY, FATAL_TEXT_KEY, INFO_ENABLED_KEY, INFO_TEXT_KEY, MSG_TYPE_ENABLED_KEYS, MSG_TYPE_TEXT_KEYS, PATTERN_KEY, ROOT_LOG_HANDLER_KEY, TIMESTAMP_FORMAT_KEY, WARNING_ENABLED_KEY, WARNING_TEXT_KEY};
use crate::interfaces::LogHandler;
use crate::{format, mdlogger_cinfo, pretty_function, set_mdlogger_enabled};
use crate::utils::{add_quotes, check_message_pattern, network_index, network_interface_exists, remove_quotes};

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

pub const PARAMETER_KEY_NAME: &str = "key";
pub const PARAMETER_VALUE_NAME: &str = "value";
pub const PARAMETER_LOG_HANDLER: &str = "log_handler";
pub const PARAMETER_SAVE_NAME: &str = "save";
pub const PARAMETER_NEW_VALUE_NAME: &str = "new-value";


// External command parameter object
#[derive(Deserialize)]
struct ExternalCommandParameter {
    name: String,
    value: Value
}

// External command object
#[derive(Deserialize)]
struct ExternalCommand {
    command: String,
    parameters: Vec<ExternalCommandParameter>
}

// External command object implementation
impl ExternalCommand {

    // Return external command associated parameters number
    fn get_paramter_numbers(&self) -> usize {
        self.parameters.len()
    }

    // Return external command associated parameter by index
    // * `self` itself reference
    // * `idx` parameter index 
    fn get_parameter_byidx(&self, idx: usize) -> Result<(String, Value), String> {
        if idx < self.parameters.len() {
            return Ok((self.parameters[idx].name.clone(), self.parameters[idx].value.clone()));
        }
        Err(format!("index value '{}' out of range 0..{}", idx, self.parameters.len()))
    }


    // Return external command associated parameter by index
    // * `self` itself reference
    // * `paramter_name` parameter name 
    fn get_parameter_byname(&self, paramter_name: &str) -> Option<(String, Value)> {
        for param in &self.parameters {
            if param.name == paramter_name {
                return Some((param.name.clone(), param.value.clone()));
            } 
        }
        None
    }
}

// Ack/Nack enumeration
#[derive(Serialize)]
enum AckNack {
    NACK = -1,
    ACK = 0,
    PARTIALACK = 1
}

// External command answer object
#[derive(Serialize)]
struct ExternalCommandAnswer {
    ack_nack: AckNack,
    reason: String,
    value: Value, 
}

// Create a thread to manage external commands
// * `settings` reference to mdlogger settings file
// * `answer_rx_channel` channel where command answer are passed to external commands thread
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

// join external commands thread cretion result
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

// Commands thread function
// * `idx` parameter index 
// * `answer_rx_channel` channel where command answer are passed to external commands thread
// * `commands_socket` commands comunication socket
// * `commands_running1` commands thread running flag
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

// Return running flag status 
// * `running` running flag status 
pub (crate) fn is_running(running: &Arc<Mutex<bool>>) -> bool {
    let guard = running.lock().unwrap_or_else(
        |poinson_error| {
            poinson_error.into_inner()
        }
    );
    *guard
}


// Set running flag status 
// * `running` running flag status 
// * `value` new running flag status to set
pub(crate) fn set_running(running: &Arc<Mutex<bool>>, value: bool) {
    let mut guard = running.lock().unwrap_or_else(
        |poinson_error| {
            poinson_error.into_inner()
        }
    );
    *guard = value;
}                        

// Run and external command 
// * `answer_tx_channel` answer transmition channel
// * `command` json format command to run
// * `log_handlers` log handlers if command is directed to one of them
// * `settings` mutable reference to mdlogger settings file
pub(crate) fn execute_external_commands(answer_tx_channel: &Sender<String>,
                                        command: String,
                                        log_handlers: &mut Vec<Box<dyn LogHandler>>,
                                        settings: &mut Settings) {
    let json_command = command.replace(EXTERNAL_COMMNDS_MESSAGE, "").
                                            replacen(EXTERNAL_COMMNDS_MESSAGE_SEP, "", 1);
    
    let mut answer = ExternalCommandAnswer {ack_nack: AckNack::ACK, 
        reason: String::new(),
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
                answer.reason = format!("{} is not a valid command valid are: {}", 
                        external_command.command, VALID_EXT_CMDS.join(", "));
            }
        },
        Err(error) => {
            answer.ack_nack = AckNack::NACK;
            answer.reason = format!("invalid json format: {}", error);
        }
    }
    let answer = serde_json::to_string(&answer).unwrap_or_else(|e| {
        eprintln!("{} wrong external command answer serializing: {}", EXTERNAL_COMMNDS_THREAD_NAME, e);
        format!("{{ \"ack_nack\": \"NACK\", \"reason\": \"{}\" }}", e)
    });

    if let Err(error) = answer_tx_channel.send(answer) {
        eprintln!("{} error sending answer: {}", EXTERNAL_COMMNDS_THREAD_NAME, error);
    }
}

// Run get configuration command
// * `answer` command execution answer 
// * `log_handlers` log handlers to retrieve configuration from
// * `settings` mutable reference to mdlogger settings file
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

// Return a json value containing mdlogger global section configuration
// * `settings` mutable reference to mdlogger settings file
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


// Run set mdlogger global configuration command
// * `external_command` command to run  
// * `answer` command execution answer 
// * `settings` mutable reference to mdlogger settings file
fn exec_set_global_command(external_command: &ExternalCommand,
                        answer: &mut ExternalCommandAnswer,
                        settings: &mut Settings) {

    if external_command.get_paramter_numbers() > 0 {
        match  external_command.get_parameter_byidx(0) {
            Ok(key_value) => {
                if !key_value.1.is_array() && !key_value.1.is_null() && !key_value.1.is_object() {
                    if settings.key_exists(GLOBAL_SECTION, &key_value.0) {
                        if ENABLED_KEY == &key_value.0 {
                            if let Some(enabled) = key_value.1.as_bool() {
                                set_mdlogger_enabled(enabled);
                                answer.ack_nack = AckNack::ACK;                                    
                                if let Err(error) = settings.set(GLOBAL_SECTION, &key_value.0, enabled) {
                                    answer.ack_nack = AckNack::PARTIALACK;
                                    answer.reason = error;
                                } else {
                                    if let Err(error) = settings.save() {
                                        answer.ack_nack = AckNack::PARTIALACK;
                                        answer.reason = format!("{} changed but and error occured during saving action: {}",
                                                            ENABLED_KEY, error);    
                                    } else {
                                        answer.reason = format!("{} changed and saved",
                                                            ENABLED_KEY);
                                    }
                                }
                            } else {
                                answer.ack_nack = AckNack::NACK;
                                answer.reason = format!("{} need a boolean value", key_value.0)
                            }
                        } else if PATTERN_KEY == &key_value.0 {
                            if let Some(pattern) = key_value.1.as_str() {           
                                let pattern = String::from(pattern);                   
                                if let Err(error) = check_message_pattern(&pattern) {
                                    answer.ack_nack = AckNack::NACK;
                                    answer.reason = error;
                                } else {
                                    if let Err(error) = settings.set(GLOBAL_SECTION, PATTERN_KEY, pattern) {
                                        answer.ack_nack = AckNack::NACK;
                                        answer.reason = error;
                                    } else {
                                        if let Err(error) = settings.save() {
                                            answer.ack_nack = AckNack::PARTIALACK;
                                            answer.reason = format!("{} changed but and error occured during saving action: {}",
                                                            PATTERN_KEY, error);    
                                        } else {
                                            answer.ack_nack = AckNack::ACK;
                                            answer.reason = format!("{} changed and saved, it will be applid to all log handlers not having their own log {} on next running",
                                                            PATTERN_KEY, PATTERN_KEY);
                                        }                                            
                                    }
                                }
                            } else {
                                answer.ack_nack = AckNack::NACK;
                                answer.reason = format!("{} need a string value", key_value.0)        
                            }
                        } else if TIMESTAMP_FORMAT_KEY == &key_value.0 {
                            if let Some(timestamp_format) = key_value.1.as_str() {
                                let no_quotes_timestamp_format = remove_quotes(timestamp_format); 
                                if let Err(error) = format_description::parse(&no_quotes_timestamp_format) {
                                    answer.ack_nack = AckNack::NACK;
                                    answer.reason = format!("{} invalid format description: {}", TIMESTAMP_FORMAT_KEY,
                                            error);
                                } else {
                                    if let Err(error) = settings.set(GLOBAL_SECTION, TIMESTAMP_FORMAT_KEY, add_quotes(timestamp_format)) {
                                        answer.ack_nack = AckNack::NACK;
                                        answer.reason = error;
                                    } else {
                                        answer.ack_nack = AckNack::ACK;
                                        if let Err(error) = settings.save() {
                                            answer.ack_nack = AckNack::PARTIALACK;
                                            answer.reason = format!("{} changed but and error occured during saving action: {}",
                                                            PATTERN_KEY, error);    
                                        } else {
                                            answer.ack_nack = AckNack::ACK;
                                            answer.reason = format!("{} changed and saved, it will be applid to all log handlers not having their own log {} on next running",
                                                            PATTERN_KEY, PATTERN_KEY);
                                        }                                            
                                    }
                                }
                            } else {
                                answer.ack_nack = AckNack::NACK;
                                answer.reason = format!("{} need a string value", key_value.0)        
                            }
                        } else if MSG_TYPE_ENABLED_KEYS.contains(&key_value.0.as_str()) {
                            if let Some(enabled) = key_value.1.as_bool() {
                                if let Err(error) = settings.set(GLOBAL_SECTION, key_value.0.as_str(), enabled) {
                                    answer.ack_nack = AckNack::NACK;
                                    answer.reason = error;
                                } else {
                                    let key = key_value.0.as_str();
                                    if let Err(error) = settings.save() {
                                        answer.ack_nack = AckNack::PARTIALACK;
                                        answer.reason = format!("{} changed but and error occured during saving action: {}",
                                                            key, error);    
                                    } else {
                                        answer.ack_nack = AckNack::ACK;
                                        answer.reason = format!("{} changed and saved, it will be applid to all log handlers not having their own log {} on next running",
                                                            key, key);
                                    }
                                }           
                            } else {
                                answer.ack_nack = AckNack::NACK;
                                answer.reason = format!("{} need a boolean value", key_value.0)        
                            }
                        } else if MSG_TYPE_TEXT_KEYS.contains(&key_value.0.as_str()) {
                            if let Some(text) = key_value.1.as_str() {
                                if let Err(error) = settings.set(GLOBAL_SECTION, key_value.0.as_str(), text.to_string()) {
                                    answer.ack_nack = AckNack::NACK;
                                    answer.reason = error;                                    
                                } else {
                                    let key = key_value.0.as_str();
                                    if let Err(error) = settings.save() {
                                        answer.ack_nack = AckNack::PARTIALACK;
                                        answer.reason = format!("{} changed but and error occured during saving action: {}",
                                                            key, error);    
                                    } else {
                                        answer.ack_nack = AckNack::ACK;
                                        answer.reason = format!("{} changed and saved, it will be applid to all log handlers not having their own log {} on next running",
                                                            key, key);
                                    }
                                }
                            } else {
                                answer.ack_nack = AckNack::NACK;
                                answer.reason = format!("{} need a string value", key_value.0)        
                            }
                        } else {
                            answer.ack_nack = AckNack::NACK;
                            answer.reason = format!("{} cannot be changed runtime", key_value.0)
                        }
                    } else {
                        answer.ack_nack = AckNack::NACK;
                        answer.reason = format!("parameter {} => '{}' not found", 
                            PARAMETER_KEY_NAME, key_value.0);    
                    }
                } else {
                    answer.ack_nack = AckNack::NACK;
                    answer.reason = format!("parameter {} cannot be an array nor a null nor an object", PARAMETER_VALUE_NAME);    
                }
            },
            Err(error) => {
                answer.ack_nack = AckNack::NACK;
                answer.reason = error;
            }
        } // match  external_command.get_parameter_byidx(0) 
    } else {
        answer.ack_nack = AckNack::NACK;
        answer.reason = format!("command '{}' needs 1 parameter at least", external_command.command);
    }
}


// Run set mdlogger log handler set configuration command
// * `external_command` command to run  
// * `log_handlers` log handlers if command is directed to one of them
// * `answer` command execution answer 
// * `settings` mutable reference to mdlogger settings file
fn exec_set_handler_command(external_command: &ExternalCommand,
                        log_handlers: &mut Vec<Box<dyn LogHandler>>,
                        answer: &mut ExternalCommandAnswer,
                        settings: &mut Settings) {
    if external_command.get_paramter_numbers() > 2 {
        match  external_command.get_parameter_byname(PARAMETER_LOG_HANDLER) {
            Some(log_handler_name_value) => {
                if let Some(log_handler_name) = log_handler_name_value.1.as_str() {
                    let mut found = false;
                    let mut iter = log_handlers.iter();
                    while let Some(log_handler) = iter.next() {
                        if log_handler.get_name() == log_handler_name {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        answer.ack_nack = AckNack::NACK;
                        answer.reason = format!("{} '{}' not found in the log chain", 
                                            PARAMETER_LOG_HANDLER, log_handler_name);
                        return;
                    }
                    match  external_command.get_parameter_byname(PARAMETER_KEY_NAME) {
                        Some(key_value) => {
                            if let Some(key) = key_value.1.as_str() {
                                match external_command.get_parameter_byname(PARAMETER_NEW_VALUE_NAME) {
                                    Some(new_value_param) => {
                                        let mut iter = log_handlers.iter_mut();
                                        while let Some(log_handler) = iter.next() {
                                            if log_handler.get_name() == log_handler_name {
                                                match log_handler.set_config(key, &new_value_param.1) {
													Err(error) => {
														answer.ack_nack = AckNack::NACK;
														answer.reason = format!("Log handler '{}' parameter '{}' error: {}", log_handler_name, key, error);
													},
													Ok(reason) => {
														answer.reason = format!("Log handler '{}' parameter '{}' changed but not saved for the next run",
															log_handler_name, key);
														if let Some(reason_text) = reason {
                                                            answer.ack_nack = AckNack::PARTIALACK;
															answer.reason = format!("Log handler '{}' parameter '{}' {}",
																log_handler_name, key, reason_text);
														}
														if let Some(save) = external_command.get_parameter_byname(PARAMETER_SAVE_NAME) {
															match save.1.as_bool() {
																Some(save_value) => {
																	if save_value {
																		let mut new_value = new_value_param.1.to_string();
																		if new_value.starts_with('"') && new_value.ends_with('"') {
																			new_value = new_value[1..new_value.len() -1].to_string();
																		}                                                                    
																		if !settings.key_exists(log_handler_name, key) {
																			answer.ack_nack = AckNack::PARTIALACK;
																			answer.reason = format!("Log handler '{}' parameter '{}' changed but it does not exist in configuration file, it cannot be saved", 
																								log_handler_name, key);    
																		} else if let Err(error) = settings.set(log_handler_name, key, new_value) {
																			answer.ack_nack = AckNack::PARTIALACK;
																			answer.reason = format!("Log handler {} key {} changed but an error occured while settings its new value: {}",
																								log_handler_name, key, error);    
																		} else {
																			if let Err(error) = settings.save() {
																				answer.ack_nack = AckNack::PARTIALACK;
																				answer.reason = format!("Log handler {} key {} changed but an error occured while saving its new value: {}",
																									log_handler_name, key, error);
																			} else {
																				answer.ack_nack = AckNack::ACK;
																				answer.reason = format!("Log handler '{}' parameter '{}' changed and saved for the next run",
																								log_handler_name, key);                    
																			}
																		}
																	}
																}
																None => {
																	answer.ack_nack = AckNack::PARTIALACK;
																	answer.reason = format!("Log handler {} key {} changed, but not saved because {} needs a boolean value",
																						log_handler_name, key, PARAMETER_SAVE_NAME);
																}
															}
														}
													}
												}
                                                break;
                                            }
                                        }                                                    
                                    }
                                    None => {
                                        answer.ack_nack = AckNack::NACK;
                                        answer.reason = format!("Log handler '{}' parameter '{}' missing {}", 
                                                log_handler_name, key, PARAMETER_NEW_VALUE_NAME);    

                                    }
                                }
                            } else {
                                answer.ack_nack = AckNack::NACK;
                                answer.reason = format!("Log handler '{}' parameter log_handler_name as to be a string",
                                                    log_handler_name);    
                            }
                        }, 
                        None => {
                            answer.ack_nack = AckNack::NACK;
                            answer.reason = format!("Log handler {} missing {}", log_handler_name, PARAMETER_KEY_NAME);
                        }            
                    }
                } else {
                    answer.ack_nack = AckNack::NACK;
                    answer.reason = format!("Log handler log_handler_name has to be a string value");
                }
            },
            None => {
                answer.ack_nack = AckNack::NACK;
                answer.reason = format!("parameter '{}' not found", PARAMETER_LOG_HANDLER);
            }            
        } // match  external_command.get_parameter_byidx(0) 
    } else {
        answer.ack_nack = AckNack::NACK;
        answer.reason = format!("command '{}' needs 2 parameter at least", external_command.command);
    }
}