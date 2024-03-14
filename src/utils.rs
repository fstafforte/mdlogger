use std::net::IpAddr;

use rssettings::{Settings, GLOBAL_SECTION};

use network_interface::{NetworkInterface, NetworkInterfaceConfig};


use crate::types::LogMessageFormat;
use crate::{
    constants::{
		ENABLED_KEY,
		PATTERN_KEY,
		TYPE_KEY,
		DEFAULT_PATTERN_VALUE,
		DEFAULT_CRITICAL_TEXT, 
		DEFAULT_DEBUG_TEXT, 
		DEFAULT_FATAL_TEXT, 
		DEFAULT_INFO_TEXT, 
		DEFAULT_WARNING_TEXT, 
		MSG_TYPE_ENABLED_KEYS, 
		MSG_TYPE_TEXT_KEYS,
		TIMESTAMP_FORMAT_KEY,
		DEFAULT_TIMESTAMP_FORMAT,
		LOG_MESSAGE_FORMAT_KEY,
		DEFAULT_LOG_MESSAGE_FORMAT
	}, 
    types::LOG_MSG_TYPE_NUM
};



pub (crate) enum PatternCheckState {
	WaitStartPlaceholderTag1,
	WaitStartPlaceholderTag2,
	WaitStartPlaceholderTag2Repeated,
	WaitEndPlaceholderTagRepeated,
	WaitEndPlaceholderTag
}

pub (crate) const START_PLACEHOLDER_TAG1: char = '%';
pub (crate) const START_PLACEHOLDER_TAG2: char = '{';
pub (crate) const END_PLACEHOLDER_TAG: char = '}';


pub (crate) const TIMESTAMP_UTC_PLACEHOLDER_IDX: usize = 0usize;
pub (crate) const TIMESTAMP_LOC_PLACEHOLDER_IDX: usize = TIMESTAMP_UTC_PLACEHOLDER_IDX + 1usize;
pub (crate) const MSG_TYPE_PLACEHOLDER_IDX: usize = TIMESTAMP_LOC_PLACEHOLDER_IDX + 1usize;
pub (crate) const APPNAME_PLACEHOLDER_IDX: usize  = MSG_TYPE_PLACEHOLDER_IDX +  1usize;
pub (crate) const APPVERSION_PLACEHOLDER_IDX: usize = APPNAME_PLACEHOLDER_IDX +  1usize;
pub (crate) const THREAD_PLACEHOLDER_IDX: usize = APPVERSION_PLACEHOLDER_IDX +  1usize;
pub (crate) const CATEGORY_PLACEHOLDER_IDX: usize = THREAD_PLACEHOLDER_IDX +  1usize;
pub (crate) const FILE_PLACEHOLDER_IDX: usize = CATEGORY_PLACEHOLDER_IDX +  1usize;
pub (crate) const FUNCTION_PLACEHOLDER_IDX: usize = FILE_PLACEHOLDER_IDX +  1usize;
pub (crate) const LINE_PLACEHOLDER_IDX: usize = FUNCTION_PLACEHOLDER_IDX +  1usize;
pub (crate) const MESSAGE_PLACEHOLDER_IDX: usize = LINE_PLACEHOLDER_IDX +  1usize;
const PLACEHOLDERS_NUMBER: usize = MESSAGE_PLACEHOLDER_IDX + 1usize;

pub (crate) const VALID_MESSAGE_PLACEHOLDERS: [&str; PLACEHOLDERS_NUMBER] = [
	"timestamp:utc",
	"timestamp:loc",
	"msg_type",
	"appname",
	"appvarsion",
	"thread",
	"category",
	"file",
	"function",
	"line",
	"message"			
];


pub fn check_log_handler_common_parameters(settings: &Settings,
											type_name: &str,
											log_handler_name: &str) -> Result<(), String> {
	let log_handler_type = settings.get(log_handler_name, TYPE_KEY, "???".to_string());
	if log_handler_type.error.len() > 0 {
		return Err(log_handler_type.error);
	}

	if log_handler_type.value != type_name {
		return Err(format!("Log handler: '{}' type: '{}' is not a '{}' type", log_handler_name, log_handler_type.value, type_name));
	}

	let log_handler_pattern = settings.get(log_handler_name, PATTERN_KEY, DEFAULT_PATTERN_VALUE.to_string()).value;
	check_message_pattern(&log_handler_pattern)?;

	let log_message_format = settings.get(log_handler_name, LOG_MESSAGE_FORMAT_KEY, DEFAULT_LOG_MESSAGE_FORMAT.to_string()).value;
	if let Err(parse_error) = log_message_format.parse::<LogMessageFormat>() {
		return Err(format!("Log handler: '{}' type: '{}' logg message format errore: '{}'", log_handler_name, log_handler_type.value, parse_error));
	}
	Ok(())				
}

pub fn check_message_pattern(pattern: &String)  -> Result<(), String> {
	let mut valid_placeholders: Vec<&str> = vec![];

	for placeholder in VALID_MESSAGE_PLACEHOLDERS {
		valid_placeholders.push(placeholder);
	}

	check_pattern(pattern, &valid_placeholders)
} 

pub fn check_pattern(pattern: &String, valid_placeholders: &Vec<&str>) -> Result<(), String> {
    if 0 == pattern.len() {
        return Err("Pattern is empty".to_string());
    } 
	let pattern_chars: Vec<char> = pattern.chars().collect();
    
	let mut char_idx = 0usize;
	let mut state = PatternCheckState::WaitStartPlaceholderTag1;
	let mut error = String::from("");
	let mut placeholder = String::from("");
	let pattern_len = pattern_chars.len(); 
	while char_idx < pattern_len {
		match state {
			PatternCheckState::WaitStartPlaceholderTag1 => {
				match pattern_chars[char_idx] {
					START_PLACEHOLDER_TAG1 => {
						state = PatternCheckState::WaitStartPlaceholderTag2;
						if char_idx + 1 == pattern_len {
							error = format!("Wait another '{}' char or a complete placeholder at index {}", START_PLACEHOLDER_TAG1, char_idx);
						}			
					},
					START_PLACEHOLDER_TAG2 => {
						state = PatternCheckState::WaitStartPlaceholderTag2Repeated;
					},
					END_PLACEHOLDER_TAG => {
						state = PatternCheckState::WaitEndPlaceholderTagRepeated;
					},
					_ => {
						// Remain in this state
					}
				}
			},
			PatternCheckState::WaitStartPlaceholderTag2 => {
				match pattern_chars[char_idx] {
					START_PLACEHOLDER_TAG1 => {
						state = PatternCheckState::WaitStartPlaceholderTag1;
					},
					START_PLACEHOLDER_TAG2 => {
						if char_idx + 1 == pattern_len {
							error = format!("Incoplete placeholder at index {}", char_idx);
						} else {
							state = PatternCheckState::WaitEndPlaceholderTag;
						}
					},
					_ => {
						error = format!("Waiting for '{}' or '{}' found '{}' at index {}", 
							START_PLACEHOLDER_TAG1, START_PLACEHOLDER_TAG2, pattern_chars[char_idx], char_idx);
					}
				}
			},
			PatternCheckState::WaitStartPlaceholderTag2Repeated => {
				match pattern_chars[char_idx] {
					START_PLACEHOLDER_TAG2 => {
						state = PatternCheckState::WaitStartPlaceholderTag1;
					},
					_=> {
						error = format!("Waiting for another '{}' found '{}' at index {}", 
							START_PLACEHOLDER_TAG2, pattern_chars[char_idx], char_idx);
					}					
				}

			},
			PatternCheckState::WaitEndPlaceholderTagRepeated => {
				match pattern_chars[char_idx] {
					END_PLACEHOLDER_TAG => {
						state = PatternCheckState::WaitStartPlaceholderTag1;
					},
					_=> {	
						error = format!("Missing placeholder start tag '{}{}' or another and tag '{}' at index {}", 
						START_PLACEHOLDER_TAG1, START_PLACEHOLDER_TAG2, END_PLACEHOLDER_TAG, char_idx);
					}
				}
			},
			PatternCheckState::WaitEndPlaceholderTag => {
				match pattern_chars[char_idx] {
					END_PLACEHOLDER_TAG => {
						if !valid_placeholders.contains(&&placeholder[0..]) {
							error = format!("Invalid placeholder '{}' at index {}, valid placeholder are:\n\t{}", placeholder, char_idx, valid_placeholders.join("\n\t"));
						} else {
							placeholder.clear();
							state = PatternCheckState::WaitStartPlaceholderTag1;
						}
					},
					_=> {
						if char_idx + 1 == pattern_len {
							error = format!("Missing placeholder end tag '{}' at index {}", END_PLACEHOLDER_TAG, char_idx);
						} else {
							placeholder.push(pattern_chars[char_idx]);
						}
					}
				}
			},
		}
		if error.len() > 0 {
			char_idx = pattern_len;
		}
		char_idx = char_idx + 1;
	}

	if error.len() > 0 {
		Err(error)
	} else {
		Ok(())
	}
}



fn get_global_msg_types_enabled(settings: &Settings, caller: &str) -> [bool; LOG_MSG_TYPE_NUM] {
    let mut result: [bool; LOG_MSG_TYPE_NUM] = [false, false, false, false, true];

    let mut idx  = 0usize;
    for msg_type_enable_key in MSG_TYPE_ENABLED_KEYS {
        let enabled = settings.get(GLOBAL_SECTION, msg_type_enable_key, false);
        if enabled.error.len() > 0 {
            eprintln!("'{}' warning: '{}", caller, enabled.error);
        }
        result[idx] = enabled.value;
        idx = idx + 1;
    }
    
    result
}

pub fn get_log_handler_common_parameters(enabled: &mut bool,
	pattern: &mut String,
	timestamp_format: &mut String,
	msg_types_enabled: &mut [bool; LOG_MSG_TYPE_NUM],
	msg_types_text: &mut [String; LOG_MSG_TYPE_NUM],
	message_format: &mut String,
	settings: &Settings, log_handler_name: &str, caller: &str) {
        let settings_enabled = settings.get(log_handler_name, ENABLED_KEY, false);
        if settings_enabled.error.len() > 0 {
            eprintln!("Warning: Log handler '{}', error: '{}'", log_handler_name, settings_enabled.error);
        }
		*enabled = settings_enabled.value;

        let mut log_handler_pattern = settings.get(log_handler_name, PATTERN_KEY, DEFAULT_PATTERN_VALUE.to_string());
        if log_handler_pattern.error.len() > 0 {
            log_handler_pattern.value = settings.get(GLOBAL_SECTION, PATTERN_KEY, DEFAULT_PATTERN_VALUE.to_string()).value;
        }
		*pattern = log_handler_pattern.value;

        *timestamp_format = remove_quotes(
            &settings.get(GLOBAL_SECTION, 
                TIMESTAMP_FORMAT_KEY, 
                DEFAULT_TIMESTAMP_FORMAT.to_string()).value);
       
	    
        *msg_types_enabled = get_global_msg_types_enabled(settings, caller);
        let mut idx = 0usize;
        for msg_type_enabled_key in MSG_TYPE_ENABLED_KEYS {
            let msg_type_enabled = settings.get(log_handler_name, msg_type_enabled_key, false);
            if msg_type_enabled.error.len() == 0 {
                msg_types_enabled[idx] = msg_type_enabled.value;
            }
            idx = idx + 1;
        }

        *msg_types_text = get_global_msg_types_text(settings, caller);
        idx = 0usize;
        for msg_type_text in MSG_TYPE_TEXT_KEYS {
            let msg_type_text = settings.get(log_handler_name, msg_type_text, "???".to_string());
            if msg_type_text.error.len() == 0 {
                msg_types_text[idx] = msg_type_text.value;
                idx = idx + 1;
            }
        }
        

        *message_format = settings.get(log_handler_name, LOG_MESSAGE_FORMAT_KEY, DEFAULT_LOG_MESSAGE_FORMAT.to_string()).value;

}


fn get_global_msg_types_text(settings: &Settings, caller: &str) -> [String; LOG_MSG_TYPE_NUM] {
    let mut result: [String; LOG_MSG_TYPE_NUM] = [
        DEFAULT_DEBUG_TEXT.to_string(), 
        DEFAULT_INFO_TEXT.to_string(), 
        DEFAULT_WARNING_TEXT.to_string(), 
        DEFAULT_CRITICAL_TEXT.to_string(), 
        DEFAULT_FATAL_TEXT.to_string()];

    let mut idx  = 0usize;
    for msg_type_text_key in MSG_TYPE_TEXT_KEYS {
        let text = settings.get(GLOBAL_SECTION, msg_type_text_key, result[idx].clone());
        if text.error.len() > 0 {
            eprintln!("'{}' warning: '{}", caller, text.error);
        }
        result[idx] = text.value;
        idx = idx + 1;
    }
    
    result
}

pub (crate) fn remove_quotes(s: &str) -> String {
	s.trim_matches('\"').to_string()
}

pub fn network_interface_exists(ip: &str) -> bool {
	let result: bool;
	match ip.parse::<IpAddr>() {
		Ok(ip_addr) => {
			match network_index(&ip_addr) {
				Some(_) => {
					result = true;
				},
				None => {
					result = false;
				}
			}
		},
		Err(_) => {
			result = false;
		}
	}

	result
}

pub fn network_index(ip: &IpAddr) -> Option<u32>{
    match NetworkInterface::show() {
        Ok(network_interfaces) => {
            for itf in network_interfaces {
				for idx in 0..itf.addr.len() {
					if itf.addr[idx].ip() == *ip {
						return Some(itf.index);
					}
				}
			}
			None
        },
        Err(_) => {
            None
        }
    }
}
