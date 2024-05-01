use std::fmt::Display;
use std::str::FromStr;
use rssettings::Settings;
use serde_json::{json, Map, Value};



use crate::{
    logmessage::LogMessage,
    utils::get_log_handler_common_parameters,
    utils::check_log_handler_common_parameters,
    interfaces::LogHandlerFactory, 
    interfaces::LogHandler, 
    types::LogHandlerBase, 
    types::LogMsgType, 
    types::LOG_MSG_TYPE_NUM
};



use crate::pretty_function;


const DEBUG_REDIRECTION_KEY: &str = "debug.redirection";
const INFO_REDIRECTION_KEY: &str = "info.redirection";
const WARNING_REDIRECTION_KEY: &str = "warning.redirection";
const CRITICAL_REDIRECTION_KEY: &str = "critical.redirection";
const FATAL_REDIRECTION_KEY: &str = "fatal.redirection";

const REDIRECTION_KEYS: [&str; LOG_MSG_TYPE_NUM] = [
    DEBUG_REDIRECTION_KEY,
    INFO_REDIRECTION_KEY,
    WARNING_REDIRECTION_KEY,
    CRITICAL_REDIRECTION_KEY,
    FATAL_REDIRECTION_KEY,
];

pub (self) enum Redirection {
    StdOut,
    StdErr,
    Both
}

impl Display for Redirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdOut => {
                write!(f, "{}", VALID_REDIRECTIONS[Self::StdOut as usize])
            },
            Self::StdErr => {
                write!(f, "{}", VALID_REDIRECTIONS[Self::StdErr as usize])
            },
            Self::Both => {
                write!(f, "{}", VALID_REDIRECTIONS[Self::Both as usize])
            }
        }
    }
}

const REDIRECTION_NUM: usize = Redirection::Both as usize + 1usize;

const VALID_REDIRECTIONS: [&str; REDIRECTION_NUM] = [
    "stdout", 
    "stderr",
    "both"
];

#[derive(Debug, PartialEq, Eq)]
struct ParseRedirectionError{
    error: String
}

impl ParseRedirectionError {
    fn new(s: &str) -> Self {
        Self {
            error: format!("<{}> is not a valid console redirection, valid are ({})", s, 
                VALID_REDIRECTIONS.join(", "))
        }
    }
}

impl Display for ParseRedirectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl FromStr for Redirection {
    type Err = ParseRedirectionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lower_case = s.to_lowercase();
        let mut result = Err(ParseRedirectionError::new(s));
        if s_lower_case == VALID_REDIRECTIONS[Redirection::StdOut as usize] {
            result = Ok(Redirection::StdOut);
        } else if s_lower_case == VALID_REDIRECTIONS[Redirection::StdErr as usize] {
            result = Ok(Redirection::StdErr);
        } else if s_lower_case == VALID_REDIRECTIONS[Redirection::Both as usize] {
            result = Ok(Redirection::Both);
        }

        result
    }    
}



pub (crate) struct ConsoleLogHandlerFactory {
}

impl LogHandlerFactory for ConsoleLogHandlerFactory {
    fn type_name(&self) -> &str {
        "console"
    }

    fn check_parameters(&self, settings: &Settings, log_handler_name: &str) -> Result<(), String> {
        check_log_handler_common_parameters(settings, self.type_name(), log_handler_name)?;
        
        // Check for valid redirections
        let mut redirections: Vec<String> = vec![];
        for redirection_key in REDIRECTION_KEYS {
            let redirection = settings.get(log_handler_name, redirection_key, "???".to_string());
            if redirection.error.len() > 0 {
                return Err(format!("Log handler: '{}' type: '{}' error: '{}'", log_handler_name, self.type_name(), redirection.error));
            }
            
            if let Err(parse_error)  = redirection.value.parse::<Redirection>() {
                return Err(format!("Log handler: '{}' type: '{}' error: '{}'", log_handler_name, self.type_name(), parse_error.error));
            }
            redirections.push(redirection_key.to_string());
        }

        // Check if all redirections has been set in the configuration file
        for redirection_key in REDIRECTION_KEYS {
            if !redirections.contains(&redirection_key.to_string()) {
                return Err(format!("Log handler: '{}' type: '{}' error: missing console redirection '{}'", log_handler_name, self.type_name(), redirection_key));
            }
        }

        Ok(())
    }


    fn create_log_handler(&self, settings: &Settings, log_handler_name: &str, appname: &str, appver: &str) -> Box<dyn LogHandler> {
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


        let mut redirections: [Redirection; LOG_MSG_TYPE_NUM] = [
            Redirection::StdOut,    // Debug
            Redirection::StdOut,    // Info
            Redirection::StdOut,    // Warning
            Redirection::StdErr,    // Critical
            Redirection::Both       // Fatal
        ];

        let mut idx = 0usize;
        for redirection_key in REDIRECTION_KEYS {
            let redirection = settings.get(log_handler_name, redirection_key, "both".to_string()).value;
            redirections[idx] = redirection.parse::<Redirection>().unwrap_or(Redirection::Both);
            idx = idx + 1;
        }

        Box::new(
            ConsoleLogHandler::new(log_handler_name.to_string(), 
            enabled,
            timestamp_format, 
            msg_types_enabled, 
            msg_types_text,
            message_format,
            pattern,
            appname.to_string(),
            appver.to_string(),
            redirections))
    }
}

pub struct ConsoleLogHandler {
    base: LogHandlerBase,
    redirections: [Redirection; LOG_MSG_TYPE_NUM]
}

impl ConsoleLogHandler {
    pub (self) fn new(name: String,
                enabled: bool,
                timestamp_format: String,
                msg_types_enabled: [bool; LOG_MSG_TYPE_NUM],
                msg_types_text: [String; LOG_MSG_TYPE_NUM],
                message_format: String, 
                pattern: String,
                appname: String,
                appver: String,
                redirections: [Redirection; LOG_MSG_TYPE_NUM]) -> Self {
        Self {
            base: LogHandlerBase::new(name,
                                        enabled,
                                        timestamp_format,
                                        msg_types_enabled,
                                        msg_types_text,
                                        message_format,
                                        pattern, appname, appver),
            redirections
        }
    }
}

impl LogHandler for ConsoleLogHandler {
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
        let mut config = Map::new();
        let mut base_config = self.base.get_config();
        config.append( &mut base_config);
        config.insert(String::from(DEBUG_REDIRECTION_KEY), json!(self.redirections[LogMsgType::DebugMsgType as usize].to_string()));
        config.insert(String::from(INFO_REDIRECTION_KEY), json!(self.redirections[LogMsgType::DebugMsgType as usize].to_string()));
        config.insert(String::from(WARNING_REDIRECTION_KEY), json!(self.redirections[LogMsgType::DebugMsgType as usize].to_string()));
        config.insert(String::from(CRITICAL_REDIRECTION_KEY), json!(self.redirections[LogMsgType::DebugMsgType as usize].to_string()));
        config.insert(String::from(FATAL_REDIRECTION_KEY), json!(self.redirections[LogMsgType::DebugMsgType as usize].to_string()));
        Value::Object(config)
    }

    fn set_config(&mut self, key: &str, value: &Value) -> Result<(), String> {
        if self.base.is_abaseconfig(key) {
            return self.base.set_config(key, value);
        } else {
            if !REDIRECTION_KEYS.contains(&key) {
                return Err(format!("is not valid, valid are {}", REDIRECTION_KEYS.join(",")));
            }
            match value.as_str() {
                Some(val) => {
                    match val.parse::<Redirection>() {
                        Ok(redirection) => {
                            if DEBUG_REDIRECTION_KEY == key {
                                self.redirections[LogMsgType::DebugMsgType as usize] = redirection;
                            } else if INFO_REDIRECTION_KEY == key {
                                self.redirections[LogMsgType::InfoMsgType as usize] = redirection;
                            } else if WARNING_REDIRECTION_KEY == key {
                                self.redirections[LogMsgType::WarningMsgType as usize] = redirection;
                            } else if CRITICAL_REDIRECTION_KEY == key {
                                self.redirections[LogMsgType::CriticalMsgType as usize] = redirection;
                            } else {
                                self.redirections[LogMsgType::FatalMsgType as usize] = redirection;
                            }
                        },
                        Err(parse_error) => {
                            return Err(format!("{}", parse_error));
    
                        }
                    } 
                },
                None => {
                    return Err(String::from("needs a string value"));
                }
            }
            Ok(())
        }
    }

    fn log(&mut self, msg_type: &LogMsgType, log_message: &LogMessage) {
        if self.is_enabled() && self.is_msg_type_enabled(msg_type) {
            let idx = *msg_type as usize;
            let formatted_message = log_message.formatted_message(
                                                                        self.base.get_message_format(),
                                                                        self.base.get_pattern(),
                                                                        self.base.get_appname(),
                                                                        self.base.get_appver(),
                                                                        self.base.get_timestamp_format(),
                                                                        self.base.get_msg_types_text());

            match self.redirections[idx] {
                Redirection::StdOut => {
                    println!("{}", formatted_message);
                },
                Redirection::StdErr => {
                    eprintln!("{}", formatted_message);
                }
                Redirection::Both => {
                    println!("{}", formatted_message);
                    eprintln!("{}", formatted_message);
                }
            }
        }
    }
}
