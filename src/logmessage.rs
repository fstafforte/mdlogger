use time::UtcOffset;
use time::{format_description, OffsetDateTime, macros::format_description};
use std::thread::current;
use serde::Serialize;
use crate::utils::{PatternCheckState, END_PLACEHOLDER_TAG, 
    START_PLACEHOLDER_TAG1, START_PLACEHOLDER_TAG2,
    TIMESTAMP_UTC_PLACEHOLDER_IDX, 
    TIMESTAMP_LOC_PLACEHOLDER_IDX, 
    MSG_TYPE_PLACEHOLDER_IDX, 
    APPNAME_PLACEHOLDER_IDX,
    APPVERSION_PLACEHOLDER_IDX,
    THREAD_PLACEHOLDER_IDX,
    CATEGORY_PLACEHOLDER_IDX,
    FILE_PLACEHOLDER_IDX,
    FUNCTION_PLACEHOLDER_IDX,
    LINE_PLACEHOLDER_IDX,
    MESSAGE_PLACEHOLDER_IDX,
    VALID_MESSAGE_PLACEHOLDERS};
use crate::types::{LogMsgType, LOG_MSG_TYPE_NUM};
use crate::types::LogMessageFormat;



// Time stamp object
#[derive(Serialize)]
struct TimeStamp {
    seconds: i64,
    nanoseconds: i128,    
}

// Time stamp object implementation
impl TimeStamp {
    // Create a time stamp object represnting current time
    fn now() -> Self {
        let now_utc = OffsetDateTime::now_utc();
        Self {
            seconds: now_utc.unix_timestamp(),
            nanoseconds: now_utc.unix_timestamp_nanos()
        }
    }
}

// Local time offeset object
#[derive(Clone, Serialize)]
pub struct LocalOffset {
    hours: i8,
    minutes: i8,
    seconds: i8
}

// Local time offeset object
impl LocalOffset {
    // Create an empty local time offeset object
    pub (crate) fn new() -> Self {
        Self { hours: 0i8, minutes: 0i8, seconds: 0i8 }
    }

    // Set a local time offeset object with specific hour, minutes, seconds value
    pub (crate) fn set_hms(&mut self, hms: (i8, i8, i8)) {
        self.hours = hms.0;
        self.minutes = hms.1;
        self.seconds = hms.2;
    }
}

/// Log message object
#[derive(Serialize)]
pub struct LogMessage {
    timestamp: TimeStamp,
    local_offset: LocalOffset,
    thread_name: String,
    msg_type: LogMsgType,
    category: String,
    file: String,
    function: String,
    line: u32,
    message: String
}

/// Log message object implementation
impl LogMessage {
    /// Create a new log message object
    /// * `msg_type` log message type enumeration
    /// * `category` log message category name
    /// * `file` file name where the log message occured
    /// * `function` function name where the log message occured
    /// * `line` file line number where the log message occured
    /// * `message` user message to be logged
    /// * `local_offset` local time stamp offset when message occured
    pub fn new(msg_type: LogMsgType, 
        category: String,
        file: String,
        function: String,
        line: u32,
        message: String,
        local_offset: LocalOffset) -> Self {
        let thread_name = current().name().unwrap_or("???").to_string();
        Self {
            timestamp: TimeStamp::now(),
            local_offset,
            thread_name,
            msg_type,
            category,
            file,
            function,
            line,
            message
        }
    }

    // Return log message type enumeration
    pub (crate) fn get_msg_type(&self) -> &LogMsgType {
        &self.msg_type
    }

    // Return user message to be logged
    pub (crate) fn get_message(&self) -> &String {
        &self.message
    }

    /// Return formatted message to be logged
    /// * `message_format` log message format type (plain, json, json_pretty)
    /// * `pattern` log message format pattern
    /// * `appname` application name
    /// * `appversion` application version
    /// * `timestamp_format` log message time stamp format
    /// * `msg_types_text` log message type text
    pub fn formatted_message(&self, 
                                message_format: &String,
                                pattern: &String, 
                                appname: &String, 
                                appver: &String,
                                timestamp_format: &String,
                                msg_types_text: &[String; LOG_MSG_TYPE_NUM],) -> String {

        match message_format.parse::<LogMessageFormat>() {
            Ok(format_type) => {
                match format_type {
                    LogMessageFormat::PlainText => {
                        self.plain_text(pattern, appname, appver, timestamp_format, msg_types_text)
                    },
                    LogMessageFormat::Json => {
                        self.jsonfy()
                    },
                    LogMessageFormat::JsonPretty => {
                        self.jsonfy_pretty()
                    }
                }
            },
            Err(error) => {
                eprintln!("{}", error);
                self.plain_text(pattern, appname, appver, timestamp_format, msg_types_text)
            }
        }                                    
    }

    // Return log message as a plain text
    // * `pattern` log message format pattern
    // * `appname` application name
    // * `appversion` application version
    // * `timestamp_format` log message time stamp format
    // * `msg_types_text` log message type text
    fn plain_text(&self, 
                pattern: &String, 
                appname: &String, 
                appver: &String,
                timestamp_format: &String,
                msg_types_text: &[String; LOG_MSG_TYPE_NUM]) -> String {
        let mut result = String::from("");
        let pattern_chars: Vec<char> = pattern.chars().collect();
    
        let mut char_idx = 0usize;
        let mut state = PatternCheckState::WaitStartPlaceholderTag1;
        let mut placeholder = String::from("");
        let pattern_len = pattern_chars.len(); 

        let timestamp_nanos: i128 = (self.timestamp.seconds as i128 * 1000000000i128) + 
            (self.timestamp.nanoseconds % 1000000000i128);

        let offset_datetime = OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos).unwrap_or_else(|_e| {
            OffsetDateTime::now_utc()
        });

        let local_offset = UtcOffset::from_hms(
            self.local_offset.hours, self.local_offset.minutes, self.local_offset.seconds)
            .unwrap_or(UtcOffset::UTC);

        let ts_format = format_description::parse(timestamp_format).unwrap_or_else(|_e| {
            format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3] [offset_hour sign:mandatory]:[offset_second]").to_vec()
        });


        let mut ts_string = offset_datetime.format(&ts_format).unwrap_or_else(|e| {
            format!("{:#}", e)
        });

        while char_idx < pattern_len {
            match state {
                PatternCheckState::WaitStartPlaceholderTag1 => {
                    match pattern_chars[char_idx] {
                        START_PLACEHOLDER_TAG1 => {
                            state = PatternCheckState::WaitStartPlaceholderTag2;
                        },
                        START_PLACEHOLDER_TAG2 => {
                            state = PatternCheckState::WaitStartPlaceholderTag2Repeated;
                        },
                        END_PLACEHOLDER_TAG => {
                            state = PatternCheckState::WaitEndPlaceholderTagRepeated;
                        },
                        _ => {
                            result.push(pattern_chars[char_idx]);
                        }
                    }
                },
                PatternCheckState::WaitStartPlaceholderTag2 => {
                    match pattern_chars[char_idx] {
                        START_PLACEHOLDER_TAG1 => {
                            state = PatternCheckState::WaitStartPlaceholderTag1;
                            result.push(START_PLACEHOLDER_TAG1);
                        },
                        START_PLACEHOLDER_TAG2 => {
                            if char_idx + 1 < pattern_len {
                                state = PatternCheckState::WaitEndPlaceholderTag;
                            }
                        },
                        _ => {
                            result.push(START_PLACEHOLDER_TAG1);
                            result.push(pattern_chars[char_idx]);
                            state = PatternCheckState::WaitStartPlaceholderTag1;
                        }
                    }
                },
                PatternCheckState::WaitStartPlaceholderTag2Repeated => {
                    match pattern_chars[char_idx] {
                        START_PLACEHOLDER_TAG2 => {
                            result.push(START_PLACEHOLDER_TAG2);
                        },
                        _=> {
                            result.push(START_PLACEHOLDER_TAG2);
                            result.push(pattern_chars[char_idx]);
                            state = PatternCheckState::WaitStartPlaceholderTag1;
                        }					
                    }
    
                },
                PatternCheckState::WaitEndPlaceholderTagRepeated => {
                    match pattern_chars[char_idx] {
                        END_PLACEHOLDER_TAG => {
                            state = PatternCheckState::WaitStartPlaceholderTag1;
                        },
                        _=> {	
                            result.push(END_PLACEHOLDER_TAG);
                            state = PatternCheckState::WaitStartPlaceholderTag1;
                        }
                    }
                },
                PatternCheckState::WaitEndPlaceholderTag => {
                    match pattern_chars[char_idx] {
                        END_PLACEHOLDER_TAG => {

                            match VALID_MESSAGE_PLACEHOLDERS.iter().position(|&s| s == &placeholder) {
                                Some(index) => {
                                    match index {
                                        TIMESTAMP_UTC_PLACEHOLDER_IDX => {

                                            result.push_str(&ts_string);
                                            
                                        },
                                        TIMESTAMP_LOC_PLACEHOLDER_IDX => {
                                            ts_string = offset_datetime.replace_offset(local_offset).format(&ts_format).unwrap_or_else(|e| {
                                                format!("{:#}", e)
                                            });

                                            result.push_str(&ts_string);
                                        },
                                        MSG_TYPE_PLACEHOLDER_IDX => {
                                            let idx = self.msg_type as usize;
                                            if idx >= LOG_MSG_TYPE_NUM {
                                                result.push_str("msg_type=???");
                                            } else {

                                            }          
                                            result.push_str(&msg_types_text[idx]);
                                        },
                                        APPNAME_PLACEHOLDER_IDX => {
                                            result.push_str(appname);
                                        },
                                        APPVERSION_PLACEHOLDER_IDX => {
                                            result.push_str(appver);
                                        },
                                        THREAD_PLACEHOLDER_IDX => {
                                            result.push_str(&self.thread_name);
                                        }, 
                                        CATEGORY_PLACEHOLDER_IDX => {
                                            result.push_str(&self.category);
                                        },
                                        FILE_PLACEHOLDER_IDX => {
                                            result.push_str(&self.file);
                                        },
                                        FUNCTION_PLACEHOLDER_IDX => {
                                            result.push_str(&self.function);
                                        },
                                        LINE_PLACEHOLDER_IDX => {
                                            result.push_str(&format!("{}", self.line));
                                        },
                                        MESSAGE_PLACEHOLDER_IDX => {
                                            result.push_str(&self.message);
                                        },
                                        _=> {
                                            result.push_str(&format!("{}=???", placeholder));
                                        }
                                    }
                                }
                                None => {
                                    result.push_str(&format!("{}{}{}{}", START_PLACEHOLDER_TAG1, START_PLACEHOLDER_TAG2, placeholder, END_PLACEHOLDER_TAG));
                                }
                            }                                


                            state = PatternCheckState::WaitStartPlaceholderTag1;
                            placeholder.clear();
                        },
                        _=> {
                            if char_idx + 1 == pattern_len {
                                result.push_str(&format!("{}{}{}", START_PLACEHOLDER_TAG1, START_PLACEHOLDER_TAG2, placeholder));
                            } else {
                                placeholder.push(pattern_chars[char_idx].clone());
                            }
                        }
                    }
                },
            }
            char_idx = char_idx + 1;
        }
    
       result        
    }
   
    // Return log message as a json text
    // * `self` rference to itself
    fn jsonfy(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!("{{ \"error\": \"{}\" }}", e.to_string())
        })
    }

    // Return log message as a json pretty text
    // * `self` rference to itself
    fn jsonfy_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| {
            format!("{{ \"error\": \"{}\" }}", e.to_string())
        })
    }
}