pub mod interfaces;
pub mod logmessage;
pub mod types;
mod console;
pub mod constants;
pub mod utils;
mod rollingfile;
mod network;
mod external_commands;

pub use std::fmt::format;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Condvar, Mutex, OnceLock};
use std::thread::{self, Builder};
use std::time::Duration;
use console::ConsoleLogHandlerFactory;
use rollingfile::RollingFileLogHandlerFactory;
use network::{NetworkLogHandlerFactory, UnixDomainLogHandlerFactory};
use time::{format_description, OffsetDateTime, UtcOffset};
use constants::{DEFAULT_NEXT_VALUE, DEFAULT_PATTERN_VALUE, DEFAULT_TIMESTAMP_FORMAT, ENABLED_KEY, MSG_TYPE_ENABLED_KEYS, MSG_TYPE_TEXT_KEYS, NEXT_KEY, PATTERN_KEY, ROOT_LOG_HANDLER_KEY, TIMESTAMP_FORMAT_KEY, TYPE_KEY};
use interfaces::{LogHandler, LogHandlerFactory};
use logmessage::{LocalOffset, LogMessage};
use rssettings::{Settings, GLOBAL_SECTION};
use types::LogMsgType;

use crate::external_commands::{create_external_commands_thread, execute_external_commands, join_create_external_commands_thread, EXTERNAL_COMMNDS_MESSAGE};
use crate::utils::{check_message_pattern, remove_quotes};

const MDLOGGER_MAJOR: u16 = 0;
const MDLOGGER_MINOR: u16 = 0;
const MDLOGGER_PATCHES: u16 = 1;

const MDLOGGER_CATEGORY: &str = "mdlogger";
const __FINALIZE_MSG__: &str = "__FINALIZE_MSG__";
#[allow(dead_code)]
pub const DEFAULT_CATEGORY: &str = "default";

static APPNAME: OnceLock<String> = OnceLock::new();
static APPVERSION: OnceLock<String> = OnceLock::new();
static INITIALIZED: Mutex<bool> = Mutex::new(false);
static MDLOGGER_MUTEX: Mutex<bool> = Mutex::new(false);
static REGISTERED_LOG_HANDLER_FACTORIES: Mutex<Vec<Box<dyn LogHandlerFactory + Send>>> = Mutex::new(vec![]);
static LOG_MESSAGE_TX_CHANNEL: OnceLock<Sender<LogMessage>> = OnceLock::new();
static FATAL_LOG_CONDVAR: OnceLock<Condvar> = OnceLock::new(); 
static FATAL_LOG_MUTEX: Mutex<bool> = Mutex::new(false); 
static FINALIZE_CONDVAR: OnceLock<Condvar> = OnceLock::new();
static FINALIZE_MUTEX: Mutex<bool> = Mutex::new(false); 
static LOCAL_OFFSET: Mutex<UtcOffset> = Mutex::new(UtcOffset::UTC);

/// mdlogger macros module
mod macros {

    /// use this macro to get function name where it is used
    /// similar to the gnu c++ macro __PRETTY_FUNCTION__ 
    /// it is used in the logging macros
    #[macro_export]
    macro_rules! pretty_function {
        () => {{
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str {
                std::any::type_name::<T>()
            }
            let mut parts: Vec<&str> =
            type_name_of(f)
                .split("::")
                .map(|part|
                    if (part != "f") && (part != "{{closure}}") {
                        part
                    } else {
                        ""
                    })
                .collect();
                parts.retain(|&part| part != "");
                &parts.join("::")
        }};
    }

    /// use this macro to do a debug message type log
    #[macro_export]
    macro_rules! mdlogger_debug {
        ($($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::DebugMsgType, $crate::DEFAULT_CATEGORY, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a categorized debug message type log
    #[macro_export]
    macro_rules! mdlogger_cdebug {
        ($cat:tt, $($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::DebugMsgType, $cat, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a information message type log
    #[macro_export]
    macro_rules! mdlogger_info {
        ($($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::InfoMsgType, $crate::DEFAULT_CATEGORY, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a categorized information message type log
    #[macro_export]
    macro_rules! mdlogger_cinfo {
        ($cat:tt, $($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::InfoMsgType, $cat, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a warning message type log
    #[macro_export]
    macro_rules! mdlogger_warning {
        ($($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::WarningMsgType, $crate::DEFAULT_CATEGORY, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a categorized warning message type log
    #[macro_export]
    macro_rules! mdlogger_cwarning {
        ($cat:tt, $($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::WarningMsgType, $cat, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a critical message type log
    #[macro_export]
    macro_rules! mdlogger_critical {
        ($($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::CriticalMsgType, $crate::DEFAULT_CATEGORY, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a categorized critical message type log
    #[macro_export]
    macro_rules! mdlogger_ccritical {
        ($cat:tt, $($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::CriticalMsgType, $cat, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a fatal message type log
    #[macro_export]
    macro_rules! mdlogger_fatal {
        ($($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::FatalMsgType, $crate::DEFAULT_CATEGORY, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }

    /// use this macro to do a categorized fatal message type log
    #[macro_export]
    macro_rules! mdlogger_cfatal {
        ($cat:tt, $($arg:tt)*) => {
            $crate::log($crate::types::LogMsgType::FatalMsgType, $cat, file!(), pretty_function!(), line!(), format(format_args!($($arg)*)))
        };
    }
}


// Initialize the global mdlogger enabling flag
// * `settings` reference to mdlogger setting file management object
fn init_mdlogger_mutex(settings: &Settings) {
    let enabled = settings.get(GLOBAL_SECTION, ENABLED_KEY, false);
    if enabled.error.len() > 0 {
        eprintln!("'{}', WARNING: '{}'", pretty_function!(), enabled.error);
    }
    let mut guard = MDLOGGER_MUTEX.lock().unwrap_or_else(|poison_error| {
        poison_error.into_inner()
    });
    *guard = enabled.value;
}

// Return the global mdlogger enabling flag value
fn is_mdlogger_enabled() -> bool {
    let guard = MDLOGGER_MUTEX.lock().unwrap_or_else(|poison_error| {
        poison_error.into_inner()
    });
    guard.clone()
}

// Set the global mdlogger enabling flag value
pub (crate) fn set_mdlogger_enabled(enabled: bool) {
    let mut guard = MDLOGGER_MUTEX.lock().unwrap_or_else(|poison_error| {
        poison_error.into_inner()
    });

    *guard = enabled;
}

// Return application name
fn get_appname() -> String {
    let _guard = MDLOGGER_MUTEX.lock().unwrap_or_else(|poison_error|{
        poison_error.into_inner()
    });
    let mut appname = String::from("<unset appname>");
    match APPNAME.get() {
        Some(name) => {
            appname = name.clone();
        },
        None => {

        }
    }
    appname
}

// Return application version
fn get_appver() -> String {
    let _guard = MDLOGGER_MUTEX.lock().unwrap_or_else(|poison_error|{
        poison_error.into_inner()
    });
    let mut appver = String::from("<unset appver>");
    match APPVERSION.get() {
        Some(name) => {
            appver = name.clone();
        },
        None => {

        }
    }
    appver
}


// Send a log message to mdlogger log thread function
// * `log_message` log message object to be sent to log thread function
fn send_log_message(log_message: LogMessage) {

    let _guard = MDLOGGER_MUTEX.lock().unwrap_or_else(|poison_error|{
        poison_error.into_inner()
    });


    let message = log_message.get_message().clone();
    match LOG_MESSAGE_TX_CHANNEL.get() {
        Some(sender) => {
            if  let Err(send_error) = sender.send(log_message) {
                println!("Multi-device send log messag error '{}': {}", send_error, message);    
            }
        },
        None => {
            println!("Multi-device no log message sender found: {}", message);
        }
    }
}



// Send a message from the log thread funtion to the mdlogger
// initialization function 
fn log_thread_send_function(sender: &Sender<String>, message: &String) {
    let mut cnt = 0;
    while let Err(error) = sender.send(message.clone()) {
        thread::sleep(Duration::from_millis(100));
        cnt = cnt + 1;
        if 0 == (cnt % 10) {
            eprintln!("{}", error.to_string());
        }
    }
}



// Check mdlogger global section settings file
// * `settings` reference to mdlogger setting file management object
fn check_global_configuration(settings: &Settings)  -> Result<(), String> {

    if !settings.key_exists(GLOBAL_SECTION, ENABLED_KEY) {
        return Err(format!("'{}' section: missing '{}' key", GLOBAL_SECTION, ENABLED_KEY));
    }

    let pattern = settings.get(GLOBAL_SECTION, PATTERN_KEY, DEFAULT_PATTERN_VALUE.to_string());
    if pattern.error.len() > 0 {
        eprintln!("'{}', Warning: '{}'", pretty_function!(), pattern.error);
    }

    check_message_pattern(&pattern.value)?;

    for key in MSG_TYPE_ENABLED_KEYS {
        if !settings.key_exists(GLOBAL_SECTION, key) {
            return Err(format!("'{}' section: missing '{}' key", GLOBAL_SECTION, key));
        }
    }

    for key in MSG_TYPE_TEXT_KEYS {
        if !settings.key_exists(GLOBAL_SECTION, key) {
            return Err(format!("'{}' section: missing '{}' key", GLOBAL_SECTION, key));
        }
    }

    if !settings.key_exists(GLOBAL_SECTION, TIMESTAMP_FORMAT_KEY) {
        return Err(format!("'{}' section: missing '{}' key", GLOBAL_SECTION, TIMESTAMP_FORMAT_KEY));
    }

    let timestamp_format = remove_quotes(&settings.get(GLOBAL_SECTION, 
        TIMESTAMP_FORMAT_KEY, 
        DEFAULT_TIMESTAMP_FORMAT.to_string()).value);
    if let Err(error) = format_description::parse(&timestamp_format) {
        return Err(format!("{}", error));
    };   

    Ok(())
}


// Check if log handlers form a loop chain or not
// * `settings` reference to mdlogger setting file management object
fn check_log_handlers_chain(settings: &Settings)  -> Result<(), String> {
    let root_log_handler = settings.get(GLOBAL_SECTION, ROOT_LOG_HANDLER_KEY, "".to_string());
    if root_log_handler.error.len() > 0 {
        return Err(format!("{}, Error: '{}'", pretty_function!(), root_log_handler.error));
    }
    if 0 == root_log_handler.value.len() {
        return Err(format!("{}, Error: '{}' is emprty", pretty_function!(), ROOT_LOG_HANDLER_KEY));
    }
    let mut next_log_handler = root_log_handler.value;
    let mut curr_log_handler = next_log_handler.clone();
    let mut log_handlers: Vec<String> = vec![];
    while next_log_handler.len() > 0 {
        if settings.section_exists(&next_log_handler) {
            if !log_handlers.contains(&next_log_handler) {
                let tmp_next_log_handler = settings.get(&curr_log_handler, NEXT_KEY, DEFAULT_NEXT_VALUE.to_string()).value;
                log_handlers.push(curr_log_handler.clone());
                curr_log_handler = next_log_handler;
                next_log_handler = tmp_next_log_handler;
            } else {
                return Result::Err(format!("{}, Error: log handler '{}' create a log handler loop chain with log handler '{}'", pretty_function!(), curr_log_handler, next_log_handler));
            }
        } else {
            return Result::Err(format!("{}, Error: Log handler '{}' does not exist in the settings file", pretty_function!(), next_log_handler));
        }
    }

    Ok(())
}



// Check  log handlers configured in the mdlogger settings file
// * `settings` reference to mdlogger setting file management object
fn check_log_handlers(settings: &Settings)  -> Result<(), String> {
    check_log_handlers_chain(&settings)?;

    let mut next_log_handler = settings.get(GLOBAL_SECTION, ROOT_LOG_HANDLER_KEY, "???".to_string()).value;

    while next_log_handler.len() > 0 {
        if !settings.key_exists(&next_log_handler, TYPE_KEY) {
            return Result::Err(format!("Log handler '{}': missing {} key", next_log_handler, TYPE_KEY));
        }
        let log_handler_type = settings.get(&next_log_handler, TYPE_KEY, "".to_string()).value;
        if !log_handler_type_exists(&log_handler_type) {
            return Result::Err(format!("Log handler '{}': {} '{}' has not been registered", next_log_handler, TYPE_KEY, log_handler_type));
        }

        next_log_handler = settings.get(&next_log_handler, NEXT_KEY, "".to_string()).value;
    } 
    Ok(())
}


// Check  mdlogger configuration settings file
// * `settings` reference to mdlogger setting file management object
fn check_mdlogger_configuration(settings: &Settings)  -> Result<(), String> {
    check_global_configuration(&settings)?;
    check_log_handlers(&settings)?;
    Ok(()) 
}

// Create mdlogger  log handlers configured in the mdlogger settings file
// * `settings` reference to mdlogger setting file management object
fn create_log_handlers(settings: &Settings) ->  Vec<Box<dyn LogHandler>> {
    let mut log_handlers: Vec<Box<dyn LogHandler>> = vec![];    

    let mut next_log_handler = settings.get(GLOBAL_SECTION, ROOT_LOG_HANDLER_KEY, "???".to_string()).value;

    let appname = &get_appname();
    let appver = &get_appver();
    while next_log_handler.len() > 0 {
        let log_handler_type = settings.get(&next_log_handler, TYPE_KEY, "".to_string()).value;
        {
            let mutex_guard = REGISTERED_LOG_HANDLER_FACTORIES.lock().unwrap_or_else(|poison_error| {
                poison_error.into_inner()
            });
            for factory in mutex_guard.iter() {
                if factory.type_name() == log_handler_type {
                    if let Err(error) = factory.check_parameters(settings, &next_log_handler) {
                        eprintln!("{}\nLog handler '{}' discarded", error, next_log_handler);
                    } else {
                        log_handlers.push(factory.create_log_handler(settings, &next_log_handler, appname, appver));
                    }
                    break;
                }
            }          
        }
        next_log_handler = settings.get(&next_log_handler, NEXT_KEY, "".to_string()).value;
    } 


    log_handlers
}

// Log thread function 
// * `settings_file_path` mdlogger setting file path
// * `log_thread_tx_channel` log thread string message transmition channel
// * `log_message_rx_channel` log thread log messages receving channel
fn log_thread_function(settings_file_path: String, 
                        log_thread_tx_channel: Sender<String>,
                        log_message_rx_channel: Receiver<LogMessage>) {
    
    println!("{} ------------------------- START", pretty_function!());
    let mut result = String::new();
    { // Open a scope to drop the settings file before the thread dies
        let mut settings = Settings::new();
        match settings.load(&settings_file_path) {
            Ok(_) => {
                match check_mdlogger_configuration(&settings) {
                    Ok(_) => {
                        init_mdlogger_mutex(&settings);
                        let mut log_handlers: Vec<Box<dyn LogHandler>> = create_log_handlers(&settings);
                        let mut running = true;

                        let (answer_tx_channel, answer_rx_channel) = channel::<String>();
                        let commands_thread_result = 
                                create_external_commands_thread(&settings, answer_rx_channel);

                        log_thread_send_function(&log_thread_tx_channel, &"".to_string());
                                                
                        while running {
                            match log_message_rx_channel.recv() {
                                Ok(log_message) => {
                                    if log_message.get_message() != __FINALIZE_MSG__ {
                                        if log_message.get_message().starts_with(EXTERNAL_COMMNDS_MESSAGE) {
                                            let command: String = log_message.get_message().clone();
                                            execute_external_commands(&answer_tx_channel, command, &mut log_handlers, &mut settings);
                                        } else if is_mdlogger_enabled() {
                                            let msg_type = log_message.get_msg_type();
                                            for log_handler in log_handlers.iter_mut() {
                                                if log_handler.is_enabled() && log_handler.is_msg_type_enabled(msg_type) {
                                                    log_handler.log(msg_type, &log_message);
                                                }
                                            }
                    
                                            if LogMsgType::FatalMsgType == *msg_type {
                                                let mut fatal_logged = FATAL_LOG_MUTEX.lock().unwrap_or_else(|poison_error|{
                                                    poison_error.into_inner()
                                                });
                                                *fatal_logged = true;
                                                thread::sleep(Duration::from_millis(500));
                                                FATAL_LOG_CONDVAR.get().unwrap().notify_one();
                                            }
                                        }
                                    } else {
                                        running = false;
                                    }
                                },
                                Err(error) =>{
                                    eprintln!("{} log message rx channel error: {}", pretty_function!(), error.to_string());
                                    running = false;
                                }
                            }
                        }
                        
                        join_create_external_commands_thread(commands_thread_result);
                    },
                    Err(error) => {
                        result = error;
                    }
                }
            },
            Err(error) => {
                result = error;
            }
        }
    }
    println!("{} ------------------------- END", pretty_function!());
    if result.len() > 0 {
        log_thread_send_function(&log_thread_tx_channel, &result);
    } else {
        let mut finalize_logged = FINALIZE_MUTEX.lock().unwrap_or_else(|poison_error|{
            poison_error.into_inner()
        });
        *finalize_logged = true;
        FINALIZE_CONDVAR.get().unwrap().notify_one()        
    }
}


// Check if a log handler type has been previously registered 
// * `settings_file_path` mdlogger setting file path
fn log_handler_type_exists(log_handler_type: &str) -> bool {
    let mutex_guard = REGISTERED_LOG_HANDLER_FACTORIES.lock().unwrap_or_else(|poison_error| {
        poison_error.into_inner()
    });

    let mut result = false;

    for factory in  mutex_guard.iter() {
        if factory.type_name() == log_handler_type {
            result = true;
            break;
        }
    }
    result
}

// Return if a mdlogger is initialized 
fn is_initialized() ->bool {
    let guard = INITIALIZED.lock().unwrap_or_else(|poison_error| {
        poison_error.into_inner()
    });

    *guard
}

// Set mdlogger initialization flag to true
fn set_initialized() {
    let mut guard = INITIALIZED.lock().unwrap_or_else(|poison_error| {
        poison_error.into_inner()
    });

    *guard = true;
}

// Function used to wait that a fatal log message has been logged
// before panic
fn wait_fatal_log_completed() {
    let mut fatal_logged = FATAL_LOG_MUTEX.lock().unwrap();
    while !*fatal_logged {
        fatal_logged = FATAL_LOG_CONDVAR.get().unwrap().wait(fatal_logged).unwrap();
        thread::sleep(Duration::from_millis(100));
    }
    panic!();
}

// Register predefined log habdler factory objects
fn register_predefined_log_handler_factories() {
    if let Err(error) = register_log_handler_factory(Box::new(ConsoleLogHandlerFactory{})) {
        eprintln!("{}", error);
    }
    if let Err(error) = register_log_handler_factory(Box::new(RollingFileLogHandlerFactory{})) {
        eprintln!("{}", error);
    }
    if let Err(error) = register_log_handler_factory(Box::new(NetworkLogHandlerFactory{})) {
        eprintln!("{}", error);
    }

    if let Err(error) = register_log_handler_factory(Box::new(UnixDomainLogHandlerFactory{})) {
        eprintln!("{}", error);
    }
}

/// Register a log handler factory object 
/// Call this function before initialize function
/// * `factory` log handler factory object to be registered
pub fn register_log_handler_factory(factory: Box<dyn LogHandlerFactory + Send>) -> Result<(), String> {
    if !log_handler_type_exists(factory.type_name()) {
        let mut mutex_guard = REGISTERED_LOG_HANDLER_FACTORIES.lock().unwrap_or_else(|poison_error| {
            poison_error.into_inner()
        });
        mutex_guard.push(factory);
        Ok(())
    } else {
        Err(format!("Log handler factory '{}' already registered", factory.type_name()))
    }
}

/// Initialize mdlogger
/// * `appname` application name
/// * `appversion` application version
/// * `settings_file_path` mdlogger configuration file path
/// 
/// # Examples
/// ```
/// use mdlogger::{initialize, finalize, format, pretty_function, mdlogger_cinfo };
/// 
/// fn main() {
///     let settings_file_path = "test_files/console.ini";
///     match initialize("console-test", "1.0.0", settings_file_path) {
///         Ok(_) => {
///             mdlogger_cinfo!("main", "Hello World!!!");
///             if let Err(error) = finalize() {
///                 println!("{}", error);
///             }
///         },
///         Err(error) => {
///             println!("{}", error);
///         }
///     }
/// }
/// ```

pub fn initialize<P>(appname: &str, appversion: &str, settings_file_path: P) -> Result<(), String> where P : AsRef<Path> {
    
    {
        let mut guard = LOCAL_OFFSET.lock().unwrap_or_else(|poison_error| {
            poison_error.into_inner()
        });
        *guard = UtcOffset::local_offset_at(OffsetDateTime::UNIX_EPOCH).unwrap_or(UtcOffset::UTC);
    }

    let mut result: Result<(), String> = Ok(());

    if !is_initialized() {
        register_predefined_log_handler_factories();
        let _ = APPNAME.get_or_init(|| { appname.to_string() });
        let _ = APPVERSION.get_or_init(|| { appversion.to_string() });
        FATAL_LOG_CONDVAR.get_or_init(|| { Condvar::new() });
        FINALIZE_CONDVAR.get_or_init(|| { Condvar::new() });

        
        let (log_thread_tx_channel, log_thread_rx_channel) = channel::<String>();
        let (log_message_tx_channel, log_message_rx_channel) = channel::<LogMessage>();
        
        LOG_MESSAGE_TX_CHANNEL.get_or_init(|| { log_message_tx_channel });
        let log_thread_builder: Builder = Builder::new().name("mdlogger-thread".to_string());
        let path: String = settings_file_path.as_ref().display().to_string();
        
        let _ = log_thread_builder.spawn(move|| {
            log_thread_function(path, log_thread_tx_channel, log_message_rx_channel)
        });

        match log_thread_rx_channel.recv() {
            Ok(message) => {
                if message.len() > 0 {
                    result = Err(message);
                } else {
                    set_initialized();
                    mdlogger_cinfo!(MDLOGGER_CATEGORY, "Multi-device logger version: {}.{}.{}", MDLOGGER_MAJOR, MDLOGGER_MINOR, MDLOGGER_PATCHES);
                }
            }, 
            Err(recv_error) => {
                result = Err(format!("Multi-device error: {}", recv_error))
            }
        }
    } else {
        result = Err(format!("Multi-device logger already initialize"))
    }

    result 
}

/// Filalization mdlogger function that release all resources
/// allocated by mdlogger
pub fn finalize() -> Result<(), String> {
    if !is_initialized() {
        return Err(String::from("Multi-device logger is not initialized"));
    }
    mdlogger_cinfo!(MDLOGGER_CATEGORY, "{}", String::from(__FINALIZE_MSG__));

    let mut finalize_logged = FINALIZE_MUTEX.lock().unwrap();
    while !*finalize_logged {
        finalize_logged = FINALIZE_CONDVAR.get().unwrap().wait(finalize_logged).unwrap();
    }

    Ok(())
}

/// mdlogger log function you can use directly 
/// but it's better to use log macros
/// * `msg_type` log message type
/// * `category` log category name
/// * `file` file name where the log occurs
/// * `function` function nam where the log occurs
/// * `line` file line number where the log occurs
/// * `message` log message text
pub fn log(msg_type: LogMsgType, 
            category: &str, 
            file: &str, 
            function: &str, 
            line: u32, 
            message: String) {
                
    if !is_initialized() {
        eprintln!("Multi-device logger is not initialized");
        if msg_type == LogMsgType::FatalMsgType {
            eprintln!("category:'{}' file: '{}' function: '{}' line: '{}' message: '{}'",
                    category, file, function, line, message);
            panic!();
        }
        return;
    }

    let mut local_offset = LocalOffset::new();
    {
        let guard = LOCAL_OFFSET.lock().unwrap_or_else(|poison_error| {
            poison_error.into_inner()
        });
        local_offset.set_hms(guard.as_hms());
    }
    let log_message = LogMessage::new(
        msg_type, category.to_string(),
        file.to_string(), 
        function.to_string(),
        line, message,
        local_offset);
    send_log_message(log_message);
    if msg_type == LogMsgType::FatalMsgType {
        wait_fatal_log_completed();
    }
}


#[cfg(test)]
mod tests {

    use std::{sync::Arc, thread::JoinHandle};

    use crate::{
        rollingfile::VALID_BASENAME_PLACEHOLDERS, 
        utils::{
            check_pattern,
            VALID_MESSAGE_PLACEHOLDERS
        }
    };
    

    use super::*;
    use rand::Rng;

    fn do_logs(millis: u64) {
        let thread_names: [&str; 4] = [
            "thread-1", "thread-2", "thread-3", "thread-4"
        ];
        let mut join_handles: Vec<JoinHandle<()>> = vec![];
        let running = Arc::new(Mutex::new(true));
        for thread_name in thread_names {
            let arc_running = running.clone();
            let join_handle = Builder::new()
                .name(thread_name.to_string()).spawn(move || {
                    let thread = thread::current();
                    let thread_name = thread.name().unwrap_or("");

                    let mut rng = rand::thread_rng();
                    let mut thread_running: bool;
                    {
                        let mutex_guard = arc_running.lock().unwrap_or_else(|poison_error| {
                            poison_error.into_inner()
                        });
                        thread_running = *mutex_guard;
                    }
                    while true == thread_running {
                        mdlogger_debug!("I'm logging from '{}'", thread_name);
                        let mut interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));
                        mdlogger_cdebug!("cat1", "I'm logging from '{}'", thread_name); 
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));

                        mdlogger_info!("I'm logging from '{}'", thread_name);
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));
                        mdlogger_cinfo!("cat2", "I'm logging from '{}'", thread_name); 
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));

                        mdlogger_warning!("I'm logging from '{}'", thread_name);
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));
                        mdlogger_cwarning!("cat2", "I'm logging from '{}'", thread_name); 
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));

                        mdlogger_critical!("I'm logging from '{}'", thread_name);
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));
                        mdlogger_ccritical!("cat2", "I'm logging from '{}'", thread_name); 
                        interval = rng.gen_range(10..1000);
                        thread::sleep(Duration::from_millis(interval));
                        {
                            let mutex_guard = arc_running.lock().unwrap_or_else(|poison_error| {
                                poison_error.into_inner()
                            });
                            thread_running = *mutex_guard;
                        }    
                    }
            }).unwrap();
            join_handles.push(join_handle);
        }

        thread::sleep(Duration::from_millis(millis));
        {
            let mut mutex_guard = running.lock().unwrap_or_else(|poison_error| {
                poison_error.into_inner()
            });
            *mutex_guard = false;
        }

    }

    #[test]
    fn finalize_uninitialize_mdlogger() {
        assert_eq!(Err(format!("Multi-device logger is not initialized")), finalize());
    }

    #[test]
    fn wrong_config_file_path() {
        let settings_file_path = "test_files/wrong_config_file_path.ini";
        assert_ne!(Ok(()), initialize("wrong_config_file_path", "1.0.0", settings_file_path));
    }

    #[test]
    fn message_pattern() {
        let mut pattern = "[%<%{timestamp:utc}] %{message}".to_string();
        assert_eq!(Err(format!("Waiting for '%' or '{{' found '<' at index 2")), check_message_pattern(&pattern));
        
        pattern = "[%}<%{timestamp:utc}] %{message}".to_string();
        assert_eq!(Err(format!("Waiting for '%' or '{{' found '}}' at index 2")), check_message_pattern(&pattern));
    
        pattern = "[<%{timestamp:utc} {] %{message}".to_string();
        assert_eq!(Err(format!("Waiting for another '{{' found ']' at index 20")), check_message_pattern(&pattern));
    
        pattern = "[<%{timestamp:utc} } %{message}".to_string();
        assert_eq!(Err(format!("Missing placeholder start tag '%{{' or another and tag '}}' at index 20")), check_message_pattern(&pattern));

        pattern = "[<%{timestamp:utc} } %{message}".to_string();
        assert_eq!(Err(format!("Missing placeholder start tag '%{{' or another and tag '}}' at index 20")), check_message_pattern(&pattern));
   
        pattern = "[%{timestam:utc}] %{message}".to_string();
        let error = format!("Invalid placeholder 'timestam:utc' at index 15, valid placeholder are:\n\t{}", VALID_MESSAGE_PLACEHOLDERS.join("\n\t"));
        assert_eq!(Err(error), check_message_pattern(&pattern));
    }

    #[test]
    fn file_basename() {
        let mut valid_placeholders: Vec<&str> = vec![];

        for valid_placeholder in VALID_BASENAME_PLACEHOLDERS {
            valid_placeholders.push(valid_placeholder);
        }
        let mut basename = "mdlogger".to_string();
        assert_eq!(Ok(()), check_pattern(&basename, &valid_placeholders));

        basename = "{appname}_%{datetime:loc}".to_string();
        assert_eq!(Err("Waiting for another '{' found 'a' at index 1".to_string()), check_pattern(&basename, &valid_placeholders));

        basename = "}%{appname}_%{datetime:loc}".to_string();
        assert_eq!(Err("Missing placeholder start tag '%{' or another and tag '}' at index 1".to_string()), check_pattern(&basename, &valid_placeholders));
    
        basename = "{%{appname}_%{datetime:loc}".to_string();
        assert_eq!(Err("Waiting for another '{' found '%' at index 1".to_string()), check_pattern(&basename, &valid_placeholders));
        
        basename = "%{appname}_%{datetime:utc}".to_string();
        assert_eq!(Ok(()), check_pattern(&basename, &valid_placeholders));

        basename = "%{appname}_%{datetime:loc}".to_string();
        assert_eq!(Ok(()), check_pattern(&basename, &valid_placeholders));

        basename = "%{appname}_%{datetime}".to_string();
        let error = format!("Invalid placeholder 'datetime' at index 21, valid placeholder are:\n\t{}", VALID_BASENAME_PLACEHOLDERS.join("\n\t"));
        assert_eq!(Err(error), check_pattern(&basename, &valid_placeholders));
    }


    #[test]
    fn wrong_timestamp_format() {
        let settings_file_path = "test_files/wrong_timestamp_format.ini";
        assert_eq!(Err(format!("invalid modifier `mandator` at byte index 85")), initialize("wrong_timestamp_format", "1.0.0", settings_file_path));
    }

    #[test]
    fn missing_root_handler() {
        let settings_file_path = "test_files/missing_root_handler.ini";
        assert_eq!(Err(format!("mdlogger::check_log_handlers_chain, Error: 'Section 'GLOBAL' key 'root_log_handler' not found'")), initialize("missing_root_handler", "1.0.0", settings_file_path));
    }

    #[test]
    fn log_handler_chain_loop() {
        let settings_file_path = "test_files/log_handler_chain_loop.ini";
        assert_eq!(Err(format!("mdlogger::check_log_handlers_chain, Error: log handler 'FILE' create a log handler loop chain with log handler 'CONSOLE'")), initialize("log_handler_chain_loop", "1.0.0", settings_file_path));
    }

    #[test]
    fn console_missing_redirection() {
        let settings_file_path = "test_files/console_missing_redirection.ini";
        assert_eq!(Ok(()), initialize("console_missing_redirection", "1.0.0", settings_file_path));
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn console_wrong_redirection() {
        let settings_file_path = "test_files/console_wrong_redirection.ini";
        assert_eq!(Ok(()), initialize("console_wrong_redirection", "1.0.0", settings_file_path));
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn console_wrong_log_message_format() {
        let settings_file_path = "test_files/console_wrong_log_message_format.ini";
        assert_eq!(Ok(()), initialize("console_wrong_log_message_format", "1.0.0", settings_file_path));
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn console_handler() {
        let settings_file_path = "test_files/console.ini";
        assert_eq!(Ok(()), initialize("console-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn rollingfile_wrong_basename() {
        let settings_file_path = "test_files/rollingfile_wrong_basename.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn rollingfile_wrong_maxsize() {
        let settings_file_path = "test_files/rollingfile_wrong_maxsize.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn rollingfile_wrong_sizeum() {
        let settings_file_path = "test_files/rollingfile_wrong_sizeum.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn rollingfile_handler() {
        let settings_file_path = "test_files/rollingfile.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_wrong_protocol() {
        let settings_file_path = "test_files/network_wrong_protocol.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));
    }

    #[test]
    fn network_wrong_remote_address() {
        let settings_file_path = "test_files/network_wrong_remote_address.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));
    }

    #[test]
    fn network_wrong_remote_port() {
        let settings_file_path = "test_files/network_wrong_remote_port.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));
    }

    #[test]
    fn network_wrong_proto_unicast_addr_mcast() {
        let settings_file_path = "test_files/network_wrong_proto_unicast_addr_mcast.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));        
    }

    #[test]
    fn network_wrong_proto_mcast_addr_unicast() {
        let settings_file_path = "test_files/network_wrong_proto_mcast_addr_unicast.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));        
    }

    #[test]
    fn network_wrong_multicast_if() {
        let settings_file_path = "test_files/network_wrong_multicast_if.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));        
    }

    #[test]
    fn network_wrong_ipaddress_multicast_if() {
        let settings_file_path = "test_files/network_wrong_ipaddress_multicast_if.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));        
    }

    #[test]
    fn network_wrong_addrmcasttipv4_itfipv6() {
        let settings_file_path = "test_files/network_wrong_addrmcasttipv4_itfipv6.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));        
    }

    #[test]
    fn network_wrong_addrmcasttipv6_itfipv4() {
        let settings_file_path = "test_files/network_wrong_addrmcasttipv6_itfipv4.ini";
        assert_eq!(Ok(()), initialize("network-test", "1.0.0", settings_file_path));        
    }


    #[test]
    fn network_udp_ipv4_unicast() {
        let settings_file_path = "test_files/network_udp_ipv4_unicast.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }
    
    #[test]
    fn network_udp_ipv6_unicast() {
        let settings_file_path = "test_files/network_udp_ipv6_unicast.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_udp_ipv4_multicast() {
        let settings_file_path = "test_files/network_udp_ipv4_multicast.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_udp_ipv4_multicast_specific_itf() {
        let settings_file_path = "test_files/network_udp_ipv4_multicast_specific_itf.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_udp_ipv6_multicast() {
        let settings_file_path = "test_files/network_udp_ipv6_multicast.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_udp_ipv6_multicast_specific_itf() {
        let settings_file_path = "test_files/network_udp_ipv6_multicast_specific_itf.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_tcp_ipv4() {
        let settings_file_path = "test_files/network_tcp_ipv4.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn network_tcp_ipv6() {
        let settings_file_path = "test_files/network_tcp_ipv6.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }


    #[test]
    fn unix_domain_wring_protocol() {
        let settings_file_path = "test_files/unix_domain_wring_protocol.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
    }

    #[test]
    fn unix_domain_undefined_env_var() {
        let settings_file_path = "test_files/unix_domain_undefined_env_var.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
    }

    #[test]
    #[cfg(unix)]
    fn unix_domain_udp() {
        let settings_file_path = "test_files/unix_domain_udp.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }

    #[test]
    fn unix_domain_tcp() {
        let settings_file_path = "test_files/unix_domain_tcp.ini";
        assert_eq!(Ok(()), initialize("rollingfile-test", "1.0.0", settings_file_path));
        do_logs(10 * 1000);
        assert_eq!(Ok(()), finalize());
    }
}
