use serde::Serialize;
use std::str::FromStr;
use std::fmt::Display;



pub (crate) const PLAIN_TEXT_FORMAT: &str = "plain_text";
pub (crate) const JSON_FORMAT: &str = "json";
pub (crate) const JSON_PRETTY_FORMAT: &str = "json_pretty";


pub (crate) const VALID_LOG_MESSAGE_FORMATS: [&str; 3] = [
    PLAIN_TEXT_FORMAT,
    JSON_FORMAT,
    JSON_PRETTY_FORMAT
];

#[derive(Clone, Copy, Serialize)]
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
    PlainText(&'static str),
    Json(&'static str),
    JsonPretty(&'static str)
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
            Ok(LogMessageFormat::PlainText(PLAIN_TEXT_FORMAT))
        } else if s_lowecase == JSON_FORMAT {
            Ok(LogMessageFormat::Json(JSON_FORMAT))
        } else if s_lowecase == JSON_PRETTY_FORMAT {
            Ok(LogMessageFormat::JsonPretty(JSON_PRETTY_FORMAT))
        } else {
            Err(LogMessageFormatErr {message: format!("<{}> is not a valid log message format, valid are ({})",
                                    s_lowecase, VALID_LOG_MESSAGE_FORMATS.join(", "))})
        }
    }
}


#[derive(Serialize, Clone)]
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
}
