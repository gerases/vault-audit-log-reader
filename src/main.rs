use clap::{Arg, Command};
use colored::Colorize;
use dns_lookup::lookup_addr;
use log::{debug, error, info};
use num_cpus;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::Once;
use std::thread::JoinHandle;
use termcolor::{ColorChoice, StandardStream};
use termcolor_json::to_writer;

static INIT: Once = Once::new();

const CHUNK_SIZE: usize = 8;
const MIN_BYTES_PER_THREAD: u64 = 2_000;

#[derive(Serialize, Deserialize, Debug)]
struct Request<'a> {
    id: &'a str,
    actor: &'a str,
    time: &'a str,
    path: &'a str,
    operation: &'a str,
    clnt_tok: &'a str,
    accsr_tok: &'a str,
    tok_issue: &'a str,
    tok_type: &'a str,
    remote_address: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response<'a> {
    remote_address: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct LogEntry<'a> {
    event_type: &'a str,
    request: Request<'a>,
}

#[derive(Debug, Clone)]
struct Cli {
    output_raw: bool,
    responses_only: bool,
    // start_time: Option<String>,
    // end_time: Option<String>,
    // track: Option<Vec<String>>,
    single_thread: bool,
    log_file: String,
}

macro_rules! debug_msg {
    ($msg:expr) => {{
        let location = std::panic::Location::caller();
        debug!("{}:{}: {}", location.file(), location.line(), $msg);
    }};
}

pub fn init_logger() {
    INIT.call_once(|| {
        env_logger::init();
    });
}

fn ok_msg(msg: String) {
    info!("{}", msg.green());
}

fn err_msg(msg: String) {
    error!("ERROR: {}", msg.red());
}

fn actor(auth: &Value) -> String {
    match auth.get("metadata") {
        Some(value) => match value.get("role_name") {
            Some(role_name) => role_name.as_str().unwrap().to_string(),
            None => value.get("username").unwrap().as_str().unwrap().to_string(),
        },
        None => auth
            .get("display_name")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
    }
}

fn resolve_ip_to_hostname(ip: IpAddr) -> Result<String, Box<dyn std::error::Error>> {
    let hostname = lookup_addr(&ip)?;
    Ok(hostname)
}

fn format_ipv4_addr(remote_addr: Option<&Value>) -> String {
    match remote_addr {
        Some(value) => match value.as_str() {
            Some(addr_str) => {
                let addr: IpAddr = addr_str.parse().unwrap_or_else(|error| {
                    err_msg(format!("Couldn't parse '{addr_str}': {error}").into());
                    "0.0.0.0".parse().unwrap()
                });
                match resolve_ip_to_hostname(addr) {
                    Ok(hostname) => hostname,
                    Err(_) => format!("Can't resolve '{}'", addr_str.to_string()),
                }
            }
            None => String::from("Can't convert to string"),
        },
        None => String::from("Remote addr missing"),
    }
}

fn format_hmacs(json_obj: &mut Value) {
    match json_obj {
        Value::Object(map) => {
            for (_, elem) in map.iter_mut() {
                format_hmacs(elem);
            }
        }
        Value::Array(arr) => {
            for elem in arr.iter_mut() {
                format_hmacs(elem);
            }
        }
        Value::String(s) => {
            if s.starts_with("hmac-sha256:") {
                let replaced = s.replace("hmac-sha256:", "");
                *s = replaced.chars().take(10).collect();
            }
        }
        _ => {
            // do nothing for everything else
        }
    }
}

fn split_into_ranges(num_bytes: u64, num_ranges: usize) -> Vec<std::ops::Range<u64>> {
    if num_bytes == 0 || num_ranges == 0 {
        return Vec::new(); // No ranges requested
    }

    let chunk_size: u64 = num_bytes / num_ranges as u64;
    let remainder: u64 = num_bytes % num_ranges as u64;

    (0..if num_bytes > num_ranges as u64 {
        num_ranges
    } else {
        1
    })
        .scan(0, |start, i| {
            // Calculate the end of the current range
            let end = *start + chunk_size + if i < remainder as usize { 1 } else { 0 };
            // Create the range and update the start for the next iteration
            let range = *start..end;
            *start = end; // Update the state (the starting point for the next range)
                          // Return the current range wrapped in Some, so it will be yielded
            Some(range)
        })
        .collect()
}

fn find_beginning_of_line(file: &mut File, start_pos: u64) -> std::io::Result<u64> {
    let mut buffer = [0; CHUNK_SIZE];
    let mut seek_pos = start_pos;

    loop {
        let read_size = std::cmp::min(seek_pos as usize, CHUNK_SIZE);
        seek_pos = seek_pos.saturating_sub(read_size as u64);
        if seek_pos == 0 {
            debug_msg!("Got to the beginning of the file");
            break;
        }
        file.seek(SeekFrom::Start(seek_pos))?;
        file.read_exact(&mut buffer[..read_size])?;
        for i in (0..read_size).rev() {
            if buffer[i] == b'\n' {
                debug_msg!(format!("Found new line in the buffer at position {i}"));
                debug_msg!(format!(
                    "The buffer contains {:?}",
                    buffer.into_iter().map(|n| n as char).collect::<Vec<_>>()
                ));
                debug_msg!(format!("Start position is {start_pos}"));
                debug_msg!(format!("Seek position is {seek_pos}"));
                let line_start = seek_pos + i as u64 + 1;
                debug_msg!(format!("Line start is {seek_pos} + {i} + 1 = {line_start}"));
                return Ok(line_start);
            }
        }
    }

    return Ok(seek_pos);
}

fn read_lines(cli_args: &Cli, range: std::ops::Range<u64>) -> std::io::Result<Vec<String>> {
    let mut file = File::open(&cli_args.log_file)?;

    let line_start = match find_beginning_of_line(&mut file, range.start) {
        Ok(line_start) => {
            debug_msg!(format!("Line starts at pos {line_start}"));
            line_start
        }
        Err(err) => return Err(err),
    };

    debug_msg!(format!("Reading from pos={line_start}"));
    file.seek(SeekFrom::Start(line_start))?;
    let reader = BufReader::new(file);

    let byte_limit: u64 = range.count().try_into().unwrap();
    let mut num_bytes_read: u64 = 0;
    // Collect N lines from the current position
    let lines: Vec<String> = reader
        .lines()
        .take_while(|line| {
            if let Ok(ref line) = line {
                if num_bytes_read >= byte_limit {
                    return false;
                }
                num_bytes_read += line.len() as u64 + 1;
                true
            } else {
                false
            }
        })
        .collect::<Result<_, _>>()?;

    Ok(lines)
}

fn filter_lines(cli_args: &Cli, lines: Vec<String>) -> std::io::Result<Vec<Value>> {
    let result = lines
        .into_iter()
        .filter_map(|line| match serde_json::from_str(&line) {
            Ok(mut json) => {
                format_hmacs(&mut json);
                Some(json)
            }
            Err(e) => {
                err_msg(format!(
                    "Failed to convert the following line to JSON: '{line}': {e}"
                ));
                None
            }
        })
        .filter(|json_value: &Value| {
            let event_type = json_value.get("type").unwrap();
            if cli_args.responses_only && event_type != "response" {
                return false;
            }

            let mut stdout = StandardStream::stdout(ColorChoice::Auto);

            if cli_args.output_raw {
                to_writer(&mut stdout, &json_value).unwrap();
                return false;
            }

            let raw_auth = json_value.get("auth").unwrap();
            let raw_request = json_value.get("request").unwrap();
            // let raw_response = json_value.get("response").unwrap();

            let request = Request {
                id: raw_request.get("id").unwrap().as_str().unwrap(),
                time: json_value.get("time").unwrap().as_str().unwrap(),
                tok_issue: raw_auth.get("token_issue_time").unwrap().as_str().unwrap(),
                actor: &actor(raw_auth),
                tok_type: raw_auth.get("token_type").unwrap().as_str().unwrap(),
                clnt_tok: raw_auth.get("client_token").unwrap().as_str().unwrap(),
                accsr_tok: raw_auth.get("accessor").unwrap().as_str().unwrap(),
                path: raw_request.get("path").unwrap().as_str().unwrap(),
                operation: raw_request.get("operation").unwrap().as_str().unwrap(),
                remote_address: &format_ipv4_addr(raw_request.get("remote_address")),
            };

            let log_entry = LogEntry {
                request: request,
                event_type: json_value.get("type").unwrap().as_str().unwrap(),
            };

            to_writer(&mut stdout, &log_entry).unwrap_or_else(|error| {
                err_msg(format!("Couldn't write a json line to the screen: {error}").into());
            });

            return true;
        })
        .collect::<Vec<Value>>();

    return Ok(result);
}

fn process(cli_args: Cli) -> std::io::Result<()> {
    let logical_cores = num_cpus::get();
    let metadata = std::fs::metadata(&cli_args.log_file)?;
    let file_size = metadata.len();
    let num_threads = if cli_args.single_thread {
        1
    } else {
        std::cmp::min(
            (file_size / MIN_BYTES_PER_THREAD).max(1) as usize,
            logical_cores,
        )
    };
    debug_msg!(format!("Number of threads is {num_threads}"));
    let ranges = split_into_ranges(file_size, num_threads);
    let mut handles: Vec<JoinHandle<usize>> = vec![];
    ranges.into_iter().for_each(|range| {
        let cli_args = cli_args.clone();
        let handle = std::thread::spawn(move || {
            let thread_id = std::thread::current().id();
            debug_msg!(format!(
                "Thread={:?}; Processing range {:?}",
                thread_id, range
            ));
            let lines = read_lines(&cli_args, range.clone()).unwrap();
            let result = filter_lines(&cli_args, lines);
            let result = match result {
                Ok(lines) => lines.len(),
                Err(err) => {
                    err_msg(format!(
                        "can't process byte range {} thru {} of {}: {err}",
                        range.start, range.end, cli_args.log_file
                    ));
                    0
                }
            };
            result
        });
        handles.push(handle);
    });

    let thread_count = handles.len();
    let sum: usize = handles
        .into_iter()
        .map(|handle| handle.join().expect("Error in thread"))
        .sum();

    ok_msg(format!("Count of threads: {}", thread_count));
    ok_msg(format!("Count of lines: {}", sum));

    Ok(())
}

fn parse_args() -> Cli {
    let matches = Command::new("Read vault audit log")
        .version("1.0")
        .arg(
            Arg::new("single-thread")
                .short('S')
                .long("single-thread")
                .action(clap::ArgAction::SetTrue)
                .help("Limit to a single thread"),
        )
        .arg(
            Arg::new("responses-only")
                .short('R')
                .long("responses-only")
                .action(clap::ArgAction::SetTrue)
                .help("Limit to responses only"),
        )
        .arg(
            Arg::new("track")
                .short('t')
                .long("track")
                .help("HMAC values to track in the log")
                .num_args(1..)
                .value_name("HMAC"),
        )
        .arg(
            Arg::new("start-time")
                .short('s')
                .long("start-time")
                .help("Specify beginning time (e.g. 2024-08-16T18:10:16Z)"),
        )
        .arg(
            Arg::new("end-time")
                .short('e')
                .long("end-time")
                .help("Specify end time (e.g. 2024-08-16T18:10:16Z)"),
        )
        .arg(
            Arg::new("raw")
                .short('r')
                .long("raw")
                .action(clap::ArgAction::SetTrue)
                .help("Print unabridged entries"),
        )
        .arg(
            Arg::new("log_file").required(true).value_name("LOG_FILE"), // This is how it will be referred to in the help message
        )
        .get_matches();

    Cli {
        log_file: matches.get_one::<String>("log_file").unwrap().clone(),
        single_thread: matches.get_flag("single-thread"),
        output_raw: matches.get_flag("raw"),
        responses_only: matches.get_flag("responses-only"),
        // start_time: matches.get_one::<String>("start-time").cloned(),
        // end_time: matches.get_one::<String>("end-time").cloned(),
        // track: matches
        //     .get_many::<String>("track")
        //     .map(|values| values.cloned().collect()),
    }
}

fn main() {
    init_logger();
    let args: Cli = parse_args();
    let _ = process(args.clone());
    debug_msg!(format!("The arguments are: {:?}", args));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::{tempfile, NamedTempFile};

    #[test]
    fn test_find_beginning_of_line() -> std::io::Result<()> {
        // Create a temporary file with known content
        init_logger();

        let mut file = tempfile()?; // This creates a temporary file that will be cleaned up after the test
        let contents = "First line\nSecond line\nThird line\n";
        write!(file, "{contents}")?;

        // Test case 1: Start from the very beginning
        file.seek(SeekFrom::Start(0))?;
        let start_pos = find_beginning_of_line(&mut file, 0)?;
        assert_eq!(start_pos, 0);

        // Test case 2: Start from the middle of "Second line"
        file.seek(SeekFrom::Start(15))?;
        let start_pos = find_beginning_of_line(&mut file, 15)?;
        assert_eq!(start_pos, 11);

        // Test case 3: Start from the middle of "Third line"
        file.seek(SeekFrom::Start(28))?;
        let start_pos = find_beginning_of_line(&mut file, 28)?;
        assert_eq!(start_pos, 23);

        // Test case 4: Start from the end of "Third line"
        let end_pos = file.seek(SeekFrom::End(-1))?;
        let start_pos = find_beginning_of_line(&mut file, end_pos)?;
        assert_eq!(start_pos, 23);

        Ok(())
    }

    fn assert_read_lines(cli: &Cli, range: std::ops::Range<u64>, expected: &[&str]) {
        let result = read_lines(cli, range);
        match result {
            Ok(lines) => assert_eq!(lines, expected),
            Err(e) => panic!("Test failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_read_some_lines() -> std::io::Result<()> {
        // Create a temporary file with known content
        init_logger();

        let mut file = NamedTempFile::new()?;
        let contents = "First line\nSecond line\nThird line\n";
        write!(file, "{contents}")?;

        let cli = Cli {
            log_file: file.path().to_str().unwrap().to_string(),
            single_thread: false,
            output_raw: false,
            responses_only: false,
            // start_time: String::from("").into(),
            // end_time: String::from("").into(),
            // track: vec![].into(),
        };

        // Test case 1: start at byte 0 and request 1 byte. Should still give
        // us the whole of the first line.
        assert_read_lines(&cli, 0..1, &["First line"]);

        // Test case 3: start at byte 0 and request 11 bytes (up to and
        // including the \n of the first line). Should still give us the whole
        // of the first line.
        assert_read_lines(&cli, 0..11, &["First line"]);

        // // Test case 3: start at byte 0 and request 12 bytes (first byte of
        // // line 2). Should still give us lin1 and line 2.
        assert_read_lines(&cli, 0..12, &["First line", "Second line"]);

        // // Test case 4: start at byte 30 (end of line 3) and request 100 bytes
        // // (well past the end of line 3). Should still give us all of line 3.
        assert_read_lines(&cli, 30..130, &["Third line"]);

        Ok(())
    }

    #[test]
    fn test_split_into_ranges() {
        // Create a temporary file with known content
        init_logger();

        assert_eq!(split_into_ranges(0, 0), vec![]);
        assert_eq!(split_into_ranges(1, 0), vec![]);
        assert_eq!(split_into_ranges(0, 1), vec![]);
        assert_eq!(split_into_ranges(100, 3), vec![0..34, 34..67, 67..100]);
        assert_eq!(split_into_ranges(1, 3), vec![0..1]);
    }

    mod test_format_hmacs {
        use super::*;

        #[test]
        fn test_format_hmacs_on_string() {
            let mut json_value = json!("hmac-sha256:1234567890abcdef");
            format_hmacs(&mut json_value);
            assert_eq!(json_value, json!("1234567890"));
        }

        #[test]
        fn test_format_hmacs_on_nested_object() {
            let mut json_value = json!({
                "key": "hmac-sha256:1234567890abcdef",
                "nested": {
                    "hmac": "hmac-sha256:abcdef1234567890"
                }
            });
            format_hmacs(&mut json_value);
            assert_eq!(
                json_value,
                json!({
                    "key": "1234567890",
                    "nested": {
                        "hmac": "abcdef1234"
                    }
                })
            );
        }

        #[test]
        fn test_format_hmacs_on_array() {
            let mut json_value = json!([
                "hmac-sha256:abcdef1234567890",
                "hmac-sha256:9876543210abcdef"
            ]);
            format_hmacs(&mut json_value);
            assert_eq!(json_value, json!(["abcdef1234", "9876543210"]));
        }

        #[test]
        fn test_format_hmacs_no_change_for_non_hmac_string() {
            let mut json_value = json!("some other string");
            format_hmacs(&mut json_value);
            assert_eq!(json_value, json!("some other string"));
        }

        #[test]
        fn test_format_hmacs_no_change_for_non_string_value() {
            let mut json_value = json!(123);
            format_hmacs(&mut json_value);
            assert_eq!(json_value, json!(123));
        }
    }
}
