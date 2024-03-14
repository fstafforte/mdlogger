use crate::types::{LOG_MSG_TYPE_NUM, PLAIN_TEXT_FORMAT};

pub const ENABLED_KEY: &str = "enabled";
pub const TYPE_KEY: &str = "type";
pub const ROOT_LOG_HANDLER_KEY: &str = "root_log_handler";
pub const NEXT_KEY: &str = "next";
pub const DEFAULT_NEXT_VALUE: &str = "";
pub const PATTERN_KEY: &str = "pattern";
pub const TIMESTAMP_FORMAT_KEY: &str = "timestamp_format";
pub const DEFAULT_TIMESTAMP_FORMAT: &str = "[year]-[mont]-[day] [hour]:[minute]:[second].[subsecond digits:3] [offset_hour sign:mandatory]:[offset_second]";
pub const DEFAULT_PATTERN_VALUE: &str = "[%{timestamp:utc} %{msg_type}] %{message}";
pub const LOG_MESSAGE_FORMAT_KEY: &str = "log_message_format";
pub const DEFAULT_LOG_MESSAGE_FORMAT: &str = PLAIN_TEXT_FORMAT;

pub const DEBUG_ENABLED_KEY: &str = "debug.enabled";
pub const INFO_ENABLED_KEY: &str = "info.enabled";
pub const WARNING_ENABLED_KEY: &str = "warning.enabled";
pub const CRITICAL_ENABLED_KEY: &str = "critical.enabled";


pub const DEBUG_TEXT_KEY: &str = "debug.text";
pub const INFO_TEXT_KEY: &str = "info.text";
pub const WARNING_TEXT_KEY: &str = "warning.text";
pub const CRITICAL_TEXT_KEY: &str = "critical.text";
pub const FATAL_TEXT_KEY: &str = "fatal.text";

pub const DEFAULT_DEBUG_TEXT: &str = "Debug";
pub const DEFAULT_INFO_TEXT: &str = "Info";
pub const DEFAULT_WARNING_TEXT: &str = "Warning";
pub const DEFAULT_CRITICAL_TEXT: &str = "Critical";
pub const DEFAULT_FATAL_TEXT: &str = "Fatal";

pub const MSG_TYPE_ENABLED_KEYS: [&str; LOG_MSG_TYPE_NUM - 1usize] = [
    DEBUG_ENABLED_KEY,
    INFO_ENABLED_KEY,
    WARNING_ENABLED_KEY,
    CRITICAL_ENABLED_KEY
];

pub const MSG_TYPE_TEXT_KEYS: [&str; LOG_MSG_TYPE_NUM] = [
    DEBUG_TEXT_KEY,
    INFO_TEXT_KEY,
    WARNING_TEXT_KEY,
    CRITICAL_TEXT_KEY,
    FATAL_TEXT_KEY
];
