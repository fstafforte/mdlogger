use crate::{
    interfaces::{LogHandler, LogHandlerFactory}, logmessage::LogMessage, pretty_function, types::{LogHandlerBase, LogMsgType, LOG_MSG_TYPE_NUM}, utils::{
        check_log_handler_common_parameters, check_pattern, get_log_handler_common_parameters
    }
};
use rssettings::Settings;

use serde_json::{json, Value};
use time::{
    macros::format_description, 
    OffsetDateTime
};
use std::{ 
    fmt::Display, 
    fs::{create_dir, metadata, read_dir, remove_file, OpenOptions}, 
    path::Path, 
    result::Result, 
    str::FromStr,
    io::Write
};


const REMOVE_PREVIOUS_LOGS_KEY: &str = "remove_previous_logs";
const DEFAULT_REMOVE_PREVIOUS_LOGS: bool = true;
const DIRECTORY_KEY: &str = "directory";
const DEFAULT_DIRECTORY: &str = "./";
const BASENAME_KEY: &str = "basename";
const EXTENSION_KEY: &str = "extension"; 
const MAXSIZE_KEY: &str = "maxsize";
const SIZEUM_KEY: &str = "sizeum";
const DEPTH_KEY: &str = "depth";




const SIZEUM_BYTE: &str = "B";
const SIZEUM_KILOBYTE: &str = "KB";
const SIZEUM_MEGABYTE: &str = "MB";
const SIZEUM_GIGABYTE: &str = "GB";
const SIZEUM_TERABYTE: &str = "TB";


const VALID_SIZEUMS: [&str; 5] = [
    SIZEUM_BYTE,
    SIZEUM_KILOBYTE,
    SIZEUM_MEGABYTE,
    SIZEUM_GIGABYTE,
    SIZEUM_TERABYTE
];


const APPNAME_BASENAME_PLACEHOLDER: &str = "appname";
const DATETIMEUTC_BASENAME_PLACEHOLDER: &str = "datetime:utc";
const DATETIMELOC_BASENAME_PLACEHOLDER: &str = "datetime:loc";

const BASENAME_APPNAME_PLACEHOLDER_IDX: usize = 0usize;
const BASENAME_DATETIMEUTC_PLACEHOLDER_IDX: usize = BASENAME_APPNAME_PLACEHOLDER_IDX + 1usize;
const BASENAME_DATETIMELOC_PLACEHOLDER_IDX: usize = BASENAME_DATETIMEUTC_PLACEHOLDER_IDX + 1usize;
const BASENAME_PLACEHOLDER_NUM: usize = BASENAME_DATETIMELOC_PLACEHOLDER_IDX + 1usize;
pub (crate) const VALID_BASENAME_PLACEHOLDERS: [&str; BASENAME_PLACEHOLDER_NUM] = [
    APPNAME_BASENAME_PLACEHOLDER, 
    DATETIMEUTC_BASENAME_PLACEHOLDER, 
    DATETIMELOC_BASENAME_PLACEHOLDER
];

enum SizeUm {
    B(u64),
    KB(u64),
    MB(u64),
    GB(u64),
    TB(u64)
}

impl SizeUm {
    fn unwrap(&self) -> u64 {
        match self {
            Self::B(value) => value.clone(),
            Self::KB(value) => value.clone(),
            Self::MB(value) => value.clone(),
            Self::GB(value) => value.clone(),
            Self::TB(value) => value.clone()
        }
    }
}

struct SizeUmFormatError {
    message: String
}

impl Display for SizeUmFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl FromStr for SizeUm {
    type Err = SizeUmFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_uppercase = s.to_uppercase();
        let result: Result<Self, Self::Err>; 
        if SIZEUM_BYTE == s_uppercase {
            result = Ok(Self::B(1u64))
        } else if SIZEUM_KILOBYTE == s_uppercase {
            result = Ok(Self::KB(1024u64))
        } else if SIZEUM_MEGABYTE == s_uppercase {
            result =  Ok(Self::MB(1024u64 * 1024u64))
        } else if SIZEUM_GIGABYTE == s_uppercase {
            result = Ok(Self::GB(1024u64 * 1024u64 * 1024u64))
        } else if SIZEUM_TERABYTE == s_uppercase {
            result =  Ok(Self::TB(1024u64 * 1024u64 * 1024u64 * 1024u64))
        } else {
            result = Err(SizeUmFormatError { message: format!("'{s}' is not a valid user measure value valid are: ({})",
                VALID_SIZEUMS.join(", ")) });
        }
        result        
    }
}


pub (crate) struct RollingFileLogHandlerFactory {

}

impl RollingFileLogHandlerFactory {
    fn replace_basename_placeholder(&self, log_handler_name: &str, 
                                    type_name: &str, basename: &mut String, 
                                    appname: &str) {
        let mut idx = 0usize;
        for valid_placeholder in VALID_BASENAME_PLACEHOLDERS {
            let placeholder = format!("%{{{}}}", valid_placeholder);
            if basename.contains(&placeholder) {
                match idx {
                    BASENAME_APPNAME_PLACEHOLDER_IDX => {
                        *basename = basename.replace(&placeholder, appname);
                    },
                    BASENAME_DATETIMEUTC_PLACEHOLDER_IDX => {
                        let datetime = OffsetDateTime::now_utc();
                        let ts_format = format_description!("[year][month][day]_[hour][minute][second]_[offset_hour sign:mandatory][offset_second]").to_vec();
                        let ts_string = datetime.format(&ts_format).unwrap_or_else(|e| {
                            format!("{:#}", e)
                        });
                        *basename = basename.replace(&placeholder, &ts_string);
                    },
                    BASENAME_DATETIMELOC_PLACEHOLDER_IDX => {
                        let datetime = OffsetDateTime::now_local().unwrap_or_else(|error| {
                            eprintln!("Log handler '{}' type '{}' error: {} utc time ussed", log_handler_name, type_name, error);
                            OffsetDateTime::now_utc()
                        });
                        let ts_format = format_description!("[year][month][day]_[hour][minute][second]_[offset_hour sign:mandatory][offset_second]").to_vec();
                        let ts_string = datetime.format(&ts_format).unwrap_or_else(|e| {
                            format!("{:#}", e)
                        });
                        *basename = basename.replace(&placeholder, &ts_string);
                    },
                    _ => {}                    
                }
                idx = idx + 1;
            }
        }
    }
}

impl LogHandlerFactory for RollingFileLogHandlerFactory {
    fn type_name(&self) -> &str {
        "file"
    }

    fn check_parameters(&self, settings: &Settings, log_handler_name: &str) -> Result<(), String> {
        check_log_handler_common_parameters(settings, self.type_name(), log_handler_name)?;
        
        let basename = settings.get(log_handler_name, BASENAME_KEY, "".to_string());
        if basename.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", log_handler_name, self.type_name(), basename.error));
        }

        if 0 == basename.value.len() {
            return Err(format!("Log handler: '{}' type: '{}' error: missing or empty '{}'", log_handler_name, self.type_name(), BASENAME_KEY));
        }

        let mut valid_placeholders: Vec<&str> = vec![];
        for placeholder in VALID_BASENAME_PLACEHOLDERS {
            valid_placeholders.push(placeholder);
        }
        check_pattern(&basename.value, &valid_placeholders)?;

        let maxsize = settings.get(log_handler_name, MAXSIZE_KEY, -1i128);
        if maxsize.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", 
                        log_handler_name, self.type_name(), maxsize.error));
        }
        if maxsize.value <= 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}' has to be greather than 0",
                        log_handler_name, self.type_name(), MAXSIZE_KEY));
        }

        let sizeum = settings.get(log_handler_name, SIZEUM_KEY, "".to_string());
        if sizeum.error.len() > 0 {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}'", log_handler_name, self.type_name(), sizeum.error));
        }
        if let Err(parse_error) = sizeum.value.parse::<SizeUm>() {
            return Err(format!("Log handler: '{}' type: '{}' error: '{}' {}",
                log_handler_name, self.type_name(), SIZEUM_KEY, parse_error));
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
        
        let remove_previous_logs = settings.get(log_handler_name, REMOVE_PREVIOUS_LOGS_KEY, DEFAULT_REMOVE_PREVIOUS_LOGS).value;
        let directory = settings.get(log_handler_name, DIRECTORY_KEY, DEFAULT_DIRECTORY.to_string()).value;
        let mut basename = settings.get(log_handler_name, BASENAME_KEY, APPNAME_BASENAME_PLACEHOLDER.to_string()).value;
        let mut extension = settings.get(log_handler_name, EXTENSION_KEY, "".to_string()).value;
        
        self.replace_basename_placeholder(log_handler_name, 
                                            self.type_name(), 
                                            &mut basename, appname);


        if !extension.starts_with(".") {
            extension = format!(".{}", extension);
        }
        
        let base_maxsize = settings.get(log_handler_name, MAXSIZE_KEY, 1024u64).value;
        let sizeum = settings.get(log_handler_name, SIZEUM_KEY, SIZEUM_MEGABYTE.to_string()).value;
        let factor : u64;
        match sizeum.parse::<SizeUm>() {
            Ok(um) => {
                factor = um.unwrap();
            },
            Err(_) => {
                factor = 1024u64;
            }
        }
        let maxsize = base_maxsize * factor;
        let depth = settings.get(log_handler_name, DEPTH_KEY, 3u32).value;


        let dir_path = Path::new(&directory);
        if dir_path.exists() && remove_previous_logs {
            if let Ok(files) = read_dir(dir_path) {
                for file in files {
                    if let Ok(dir_entry) = file {
                        if let Ok(filedata) = dir_entry.metadata() {
                            if filedata.is_file() {
                                if let Err(ioerror) = remove_file(dir_entry.path()) {
                                    eprintln!("Cannot remove '{}': {:#}", 
                                        dir_entry.path().as_os_str().to_str().unwrap_or(""),
                                        ioerror);
                                }
                            }
                        } 
                    }
                }
            }
        } else if !dir_path.exists() {
            if let Err(ioerror) = create_dir(dir_path) {
                eprintln!("Cannot create directory '{}': {:#} '{}' disabled", 
                dir_path.as_os_str().to_str().unwrap_or(""), ioerror, log_handler_name);
                enabled = false;
            }
        }

        Box::new(
            RollingFileLogHandler::new(log_handler_name.to_string(), 
            enabled,
            timestamp_format, 
            msg_types_enabled, 
            msg_types_text,
            message_format,
            pattern,
            appname.to_string(),
            appver.to_string(),
            directory,
            basename,
            extension,
            maxsize,
            base_maxsize,
            sizeum,
            depth))
    }
}

struct RollingFileLogHandler {
    base: LogHandlerBase,
    directory: String,
    basename: String,
    extension: String,
    maxsize: u64,
    base_maxsize: u64,
    sizeum: String,
    depth: u32,
    current_depth: u32,
}

impl RollingFileLogHandler{
    fn new(name: String,
        enabled: bool,
        timestamp_format: String,
        msg_types_enabled: [bool; LOG_MSG_TYPE_NUM],
        msg_types_text: [String; LOG_MSG_TYPE_NUM],
        message_format: String, 
        pattern: String,
        appname: String,
        appver: String,
        directory: String,
        basename: String,
        extension: String,
        maxsize: u64,
        base_maxsize: u64,
        sizeum: String,    
        depth: u32
    ) -> Self {
        Self {
            base: LogHandlerBase::new(name,
                                    enabled,
                                    timestamp_format,
                                    msg_types_enabled,
                                    msg_types_text,
                                    message_format,
                                    pattern, appname, appver),
            directory,
            basename,
            extension,
            maxsize,
            base_maxsize,
            sizeum,
            depth,
            current_depth: 0
        }
    }

    fn get_current_file_name(&self) -> String {
        let result: String;
        if 0 == self.current_depth {
            result = format!("{}/{}{}", self.directory, self.basename, self.extension);
        } else {
            result = format!("{}/{}_{}{}", self.directory, self.basename, self.current_depth, self.extension);
        }

        result
    }
}


impl LogHandler for RollingFileLogHandler {
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
        let mut config = self.base.get_config();
        config.insert(String::from(DIRECTORY_KEY), json!(self.directory));
        config.insert(String::from(BASENAME_KEY), json!(self.basename));
        config.insert(String::from(EXTENSION_KEY), json!(self.extension));
        config.insert(String::from(MAXSIZE_KEY), json!(self.base_maxsize));
        config.insert(String::from(SIZEUM_KEY), json!(self.sizeum));


        Value::Object(config)
    }

    fn set_config(&mut self, key: &str, value: &Value) -> Result<(), String> {
        if self.base.is_abaseconfig(key) {
            self.base.set_config(key, value)?;
        } else {
        }    
        Ok(())
    }

    fn log(&mut self, msg_type: &LogMsgType, log_message: &LogMessage) {
        if self.is_enabled() && self.is_msg_type_enabled(msg_type) {
            let formatted_message = log_message.formatted_message(
                self.base.get_message_format(),
                self.base.get_pattern(),
                self.base.get_appname(),
                self.base.get_appver(),
                self.base.get_timestamp_format(),
                self.base.get_msg_types_text());
            let mut current_file_name = self.get_current_file_name();
            let mut filepath = Path::new(&current_file_name);
            if filepath.exists() {
                let filemetadata = metadata(filepath);
                if let Ok(filedata) = filemetadata {
                    if filedata.len() + formatted_message.len() as u64 > self.maxsize {
                        self.current_depth = (self.current_depth  + 1) % self.depth;
                        if 0 == self.current_depth {
                            if let Err(ioerror) = remove_file(filepath) {
                                eprintln!("Log hamdler '{}',  cannot remove '{}': {:#}, log redirected to stdout", 
                                self.get_name(), filepath.as_os_str().to_str().unwrap_or(&current_file_name), 
                                ioerror);
                            }
                        }
                        current_file_name = self.get_current_file_name();
                        filepath = Path::new(&current_file_name);
                    }
                }
            }
            match OpenOptions::new().create(true).write(true).append(true).open(filepath){
                Ok(mut file) => {
                    if let Err(ioerror) = writeln!(file, "{}", formatted_message) {
                        eprintln!("Log hamdler '{}',  cannot open '{}': {:#}, log redirected to stdout", 
                                self.get_name(), filepath.as_os_str().to_str().unwrap_or(&current_file_name), 
                                ioerror);
                        println!("{}", formatted_message);
                    }
                },
                Err(ioerror) => {
                    eprintln!("Cannot open '{}': {:#}, log redirected to stdout", 
                            current_file_name, ioerror);
                    println!("{}", formatted_message);
                }
            }
        }
    }


}