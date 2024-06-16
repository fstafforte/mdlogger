use crate::{logmessage::LogMessage, types::LogMsgType};
use std::result::Result;
use rssettings::Settings;
use serde_json::Value;


/// Log handler trait
pub trait LogHandler {
    fn get_name(&self) ->&String;
    fn is_enabled(&self) ->bool;
    fn is_msg_type_enabled(&self, msg_type: &LogMsgType) -> bool;
    fn get_pattern(&self) ->&String;
    fn get_config(&self) -> Value;
    fn set_config(&mut self, key: &str, value: &Value) -> Result<Option<String>, String>; 
    fn log(&mut self, msg_type: &LogMsgType, log_message: &LogMessage);
}


/// Log handler factory trait
pub trait LogHandlerFactory {
    fn type_name(&self) -> &str;
    fn check_parameters(&self, settings: &Settings, log_handler_name: &str) -> Result<(), String>;
    fn create_log_handler(&self, settings: &Settings, log_handler_name: &str, appname: &str, appver: &str) -> Box<dyn LogHandler>;
}