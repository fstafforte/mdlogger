use serde::Serialize;
use serde_json::{json, Map, Value};
use std::str::FromStr;
use std::fmt::Display;
use time::format_description;
use crate::{constants::{CRITICAL_ENABLED_KEY, CRITICAL_TEXT_KEY, DEBUG_ENABLED_KEY, DEBUG_TEXT_KEY, ENABLED_KEY, FATAL_ENABLED_KEY, FATAL_TEXT_KEY, INFO_ENABLED_KEY, INFO_TEXT_KEY, LOG_MESSAGE_FORMAT_KEY, PATTERN_KEY, TIMESTAMP_FORMAT_KEY, WARNING_ENABLED_KEY, WARNING_TEXT_KEY}, utils::{check_message_pattern, remove_quotes}};



pub (crate) const PLAIN_TEXT_FORMAT: &str = "plain_text";
pub (crate) const JSON_FORMAT: &str = "json";
pub (crate) const JSON_PRETTY_FORMAT: &str = "json_pretty";


pub (crate) const VALID_LOG_MESSAGE_FORMATS: [&str; 3] = [
    PLAIN_TEXT_FORMAT,
    JSON_FORMAT,
    JSON_PRETTY_FORMAT
];


const CONFIGURABLE_KEYS: [&str; 13] = [
    ENABLED_KEY,
    TIMESTAMP_FORMAT_KEY,
    DEBUG_ENABLED_KEY,
    INFO_ENABLED_KEY,
    WARNING_ENABLED_KEY,
    CRITICAL_ENABLED_KEY,
    DEBUG_TEXT_KEY,
    INFO_TEXT_KEY,
    WARNING_TEXT_KEY,
    CRITICAL_TEXT_KEY,
    FATAL_TEXT_KEY,
    LOG_MESSAGE_FORMAT_KEY,
    PATTERN_KEY,
];

#[derive(Serialize, Clone, Copy)]
pub enum LogMsgType {
    DebugMsgType,
    InfoMsgType,
    WarningMsgType,
    CriticalMsgType,
    FatalMsgType,
}


impl PartialEq for LogMsgType {
    fn eq(&self, other: &Self) -> bool {
        *self as i32 == *other as i32
    }
}

pub const LOG_MSG_TYPE_NUM: usize = LogMsgType::FatalMsgType as usize + 1usize;

pub (crate) enum LogMessageFormat {
    PlainText,
    Json,
    JsonPretty
}

pub (crate) struct LogMessageFormatErr {
    message: String
}

impl Display for LogMessageFormatErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)        
    }
}

impl FromStr for LogMessageFormat {
    type Err = LogMessageFormatErr;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lowecase = s.to_lowercase();
        if s_lowecase == PLAIN_TEXT_FORMAT {
            Ok(LogMessageFormat::PlainText)
        } else if s_lowecase == JSON_FORMAT {
            Ok(LogMessageFormat::Json)
        } else if s_lowecase == JSON_PRETTY_FORMAT {
            Ok(LogMessageFormat::JsonPretty)
        } else {
            Err(LogMessageFormatErr {message: format!("<{}> is not a valid log message format, valid are ({})",
                                    s_lowecase, VALID_LOG_MESSAGE_FORMATS.join(", "))})
        }
    }
}


pub struct LogHandlerBase {
    name: String,
    enabled: bool,
    timestamp_format: String,
    msg_types_enabled: [bool; LOG_MSG_TYPE_NUM],
    msg_types_text: [String; LOG_MSG_TYPE_NUM],
    message_format: String, 
    pattern: String,
    appname: String,
    appver: String
}

impl LogHandlerBase {
    pub fn new (name: String, 
                enabled: bool, 
                timestamp_format: String,
                msg_types_enabled: [bool; LOG_MSG_TYPE_NUM], 
                msg_types_text: [String; LOG_MSG_TYPE_NUM],
                message_format: String,
                pattern: String, appname: String, appver: String) -> Self {
        Self {
            name,
            enabled,
            timestamp_format, 
            msg_types_enabled,
            msg_types_text,
            message_format,
            pattern,
            appname,
            appver    
        }
    }

    pub fn get_name(&self) ->&String {
        &self.name
    }

    pub fn is_enabled(&self) ->bool {
        self.enabled.clone()
    }

    pub fn is_msg_type_enabled(&self, msg_type: &LogMsgType) -> bool {
        let idx = *msg_type as usize;
        let mut result = false;
        if idx < self.msg_types_enabled.len() {
            result = self.msg_types_enabled[idx].clone();
        } 

        result
    }

    pub fn get_timestamp_format(&self) ->&String {
        &self.timestamp_format
    } 


    pub fn get_pattern(&self) ->&String {
        &self.pattern
    } 

    pub fn get_appname(&self) ->&String {
        &self.appname
    }

    pub fn get_appver(&self) ->&String {
        &self.appver
    }

    pub fn get_msg_types_text(&self) -> &[String; LOG_MSG_TYPE_NUM] {
        &self.msg_types_text
    }

    pub fn get_message_format(&self) -> &String {
        &self.message_format
    }

    pub fn is_abaseconfig(&self, key: &str) -> bool {
        CONFIGURABLE_KEYS.contains(&key)
    }

    pub fn set_config(&mut self, key: &str, value: &Value) -> Result<Option<String>, String> {
        let mut error = String::new();
        if ENABLED_KEY == key {
            match value.as_bool() {
                Some(val) => {
                    self.enabled = val;
                },
                None => {
                    error = format!("{} needs a boolean value", key);
                }
            }
        } else if TIMESTAMP_FORMAT_KEY == key {
            match value.as_str() {
                Some(val) => {
                    let no_quotes_value = remove_quotes(val);
                    if  let Err(parse_error) = format_description::parse(&no_quotes_value) {
                        error = format!("{}", parse_error);
                    } else {
                        self.timestamp_format = no_quotes_value;                        
                    }    
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        } else if DEBUG_ENABLED_KEY == key {
            match value.as_bool() {
                Some(val) => {
                    self.msg_types_enabled[LogMsgType::DebugMsgType as usize] = val;
                },
                None => {
                    error = format!("{} needs a boolean value", key);
                }
            }
        } else if INFO_ENABLED_KEY == key {
            match value.as_bool() {
                Some(val) => {
                    self.msg_types_enabled[LogMsgType::InfoMsgType as usize] = val;
                },
                None => {
                    error = format!("{} needs a boolean value", key);
                }
            }
        } else if WARNING_ENABLED_KEY == key {
            match value.as_bool() {
                Some(val) => {
                    self.msg_types_enabled[LogMsgType::WarningMsgType as usize] = val;
                },
                None => {
                    error = format!("{} needs a boolean value", key);
                }
            }
        } else if CRITICAL_ENABLED_KEY == key {
            match value.as_bool() {
                Some(val) => {
                    self.msg_types_enabled[LogMsgType::CriticalMsgType as usize] = val;
                },
                None => {
                    error = format!("{} needs a boolean value", key);
                }
            }
        } else if DEBUG_TEXT_KEY == key {
            match value.as_str() {
                Some(val) => {
                    self.msg_types_text[LogMsgType::DebugMsgType as usize] = String::from(val);
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        } else if INFO_TEXT_KEY == key{
            match value.as_str() {
                Some(val) => {
                    self.msg_types_text[LogMsgType::InfoMsgType as usize] = String::from(val);
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        } else if WARNING_TEXT_KEY == key{
            match value.as_str() {
                Some(val) => {
                    self.msg_types_text[LogMsgType::WarningMsgType as usize] = String::from(val);
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }        
        } else if CRITICAL_TEXT_KEY == key{
            match value.as_str() {
                Some(val) => {
                    self.msg_types_text[LogMsgType::CriticalMsgType as usize] = String::from(val);
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        } else if FATAL_TEXT_KEY == key {
            match value.as_str() {
                Some(val) => {
                    self.msg_types_text[LogMsgType::FatalMsgType as usize] = String::from(val);
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        } else if LOG_MESSAGE_FORMAT_KEY == key {
            match value.as_str() {
                Some(val) => {
                    match val.parse::<LogMessageFormat>() {
                        Ok(_) => {
                            self.message_format = String::from(val);
                        },
                        Err(parse_error) => {
                            error = format!("{}", parse_error);
                        }
                    }
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        } else if PATTERN_KEY == key {
            match value.as_str() {
                Some(val) => {
                    if let Err(check_error) = check_message_pattern(&val.to_string()) {
                        error = check_error;
                    } else {
                        self.pattern = String::from(val);
                    }
                },
                None => {
                    error = format!("{} needs a string value", key);
                }
            }
        
        } else {
            error = format!("{} is not a valid configuration key", key);
        }

        if error.len() > 0 {
            Err(error)
        } else {
            Ok(None)
        }
    } 

    pub fn get_config(&self) -> Map<String, Value> {
        let mut config = Map::new();
        config.insert(String::from("name"), json!(self.name));
        config.insert(String::from(ENABLED_KEY), json!(self.enabled));
        config.insert(String::from(TIMESTAMP_FORMAT_KEY), json!(format!("\"{}\"", self.timestamp_format)));
        config.insert(String::from(DEBUG_ENABLED_KEY), json!(self.msg_types_enabled[LogMsgType::DebugMsgType as usize]));
        config.insert(String::from(INFO_ENABLED_KEY), json!(self.msg_types_enabled[LogMsgType::InfoMsgType as usize]));
        config.insert(String::from(WARNING_ENABLED_KEY), json!(self.msg_types_enabled[LogMsgType::WarningMsgType as usize]));
        config.insert(String::from(CRITICAL_ENABLED_KEY), json!(self.msg_types_enabled[LogMsgType::CriticalMsgType as usize]));
        config.insert(String::from(FATAL_ENABLED_KEY), json!(self.msg_types_enabled[LogMsgType::FatalMsgType as usize]));

        config.insert(String::from(DEBUG_TEXT_KEY), json!(self.msg_types_text[LogMsgType::DebugMsgType as usize]));
        config.insert(String::from(INFO_TEXT_KEY), json!(self.msg_types_text[LogMsgType::InfoMsgType as usize]));
        config.insert(String::from(WARNING_TEXT_KEY), json!(self.msg_types_text[LogMsgType::WarningMsgType as usize]));
        config.insert(String::from(CRITICAL_TEXT_KEY), json!(self.msg_types_text[LogMsgType::CriticalMsgType as usize]));
        config.insert(String::from(FATAL_TEXT_KEY), json!(self.msg_types_text[LogMsgType::FatalMsgType as usize]));
        
        config.insert(String::from(PATTERN_KEY), json!(self.pattern));
        config.insert(String::from(LOG_MESSAGE_FORMAT_KEY), json!(self.get_message_format()));
        config.insert(String::from("appname"), json!(self.appname));
        config.insert(String::from("appver"), json!(self.appver));

        config
    }
}
