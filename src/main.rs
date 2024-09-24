use chrono::{DateTime, ParseResult, Utc};
use clap::{ArgAction, Parser};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Cell, ColumnConstraint, Table, Width};
use dns_lookup::lookup_addr;
use log::LevelFilter;
use log::{debug, error, info};
use num_cpus;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;
use termcolor::{ColorChoice, StandardStream};
use termcolor_json::to_writer;

type SharedQueue<T> = Arc<Mutex<HashSet<T>>>;
type SharedMap<T1, T2> = Arc<Mutex<HashMap<T1, T2>>>;

static INIT: Once = Once::new();

// Human-friendly length of HMAC values
const HMAC_LEN: usize = 10;
// Hmac prefix
const HMAC_PFX: &str = "hmac:";
const CHUNK_SIZE: usize = 8;
const MIN_BYTES_PER_THREAD: u64 = 2_000;

#[derive(Serialize, Deserialize, Debug)]
struct Request<'a> {
    time: &'a str,
    id: &'a str,
    path: &'a str,
    actor: &'a str,
    operation: &'a str,
    clnt_tok:       &'a str,
    accsr_tok:      &'a str,
    tok_issue:      &'a str,
    remote_address: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct LogEntry<'a> {
    event_type: &'a str,
    response: Value,
    request: Request<'a>,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "Read vault audit log", version = "1.0")]
struct CliArgs {
    /// Limit to a request with a given id
    #[arg(long = "id", value_name = "Request-Id", help = "filter by request id")]
    id: Option<String>,

    /// Limit to requests with a given client id
    #[arg(
        long = "client-id",
        value_name = "Client-Id",
        help = "filter by client id"
    )]
    client_id: Option<String>,

    /// Limit to a single thread
    #[arg(short = 'S', long = "single-thread", action = ArgAction::SetTrue)]
    single_thread: bool,

    /// Include requests too
    #[arg(short = 'R', long = "include-requests", action = ArgAction::SetTrue)]
    include_requests: bool,

    /// Show only the summary
    #[arg(long = "summary", action = ArgAction::SetTrue)]
    summary: bool,

    /// HMAC values to track in the log
    #[arg(
        short = 't',
        long = "track",
        conflicts_with = "summary",
        value_name = "HMAC",
        num_args = 1..

    )]
    track: Option<Vec<String>>,

    /// Specify beginning time (e.g. 2024-08-16T18:10:16Z)
    #[arg(short = 's', long = "start-time")]
    start_time: Option<String>,

    /// Specify end time (e.g. 2024-08-16T18:10:16Z)
    #[arg(short = 'e', long = "end-time")]
    end_time: Option<String>,

    /// Print unabridged entries
    #[arg(short = 'r', long = "raw", action = ArgAction::SetTrue, conflicts_with = "summary")]
    raw: bool,

    /// Vault path
    #[arg(
        short = 'p',
        long = "path",
        conflicts_with = "summary",
        value_name = "VAULT_PATH"
    )]
    path: Option<String>,

    /// Log file
    #[arg(short = 'f', long = "file", value_name = "LOG_FILE", required = true)]
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

pub fn init_logger() {
    INIT.call_once(|| {
        let mut builder = env_logger::Builder::new();
        // Set the default log level to `Info`
        let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        builder.filter(None, log_level.parse().unwrap_or(LevelFilter::Info));
        // Initialize the logger
        builder.init();
    });
}

fn ok_msg(msg: String) {
    info!("{}", msg.green());
}

fn err_msg(msg: String) {
    error!("ERROR: {}", msg.red());
}

fn err_msg_with_exit(msg: String) {
    err_msg(msg);
    std::process::exit(1);
}

fn parse_timestamp(timestamp: &str) -> ParseResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(timestamp).map(|parsed_dt| parsed_dt.with_timezone(&Utc))
}

fn _str_from_json<'a>(event_json: &'a Value, keys: &[&str], print_error: bool) -> String {
    let mut current_val = event_json;
    for key in keys {
        current_val = match current_val.get(*key) {
            Some(json) => json,
            None => {
                if print_error {
                    err_msg(format!("Missing key: {key}"));
                }
                return String::new();
            }
        }
    }

    match current_val {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        _ => {
            if print_error {
                err_msg(format!(
                    "Invalid value for key path: {:?}; current_val={:?}",
                    keys, current_val
                ));
            }
            String::new()
        }
    }
}

fn str_from_json<'a>(event_json: &'a Value, keys: &[&str]) -> String {
    _str_from_json(event_json, keys, true)
}

fn str_from_json_no_err<'a>(event_json: &'a Value, keys: &[&str]) -> String {
    _str_from_json(event_json, keys, false)
}

fn within_time_bounds<F>(timestamp_str: &Option<String>, checker: F) -> bool
where
    F: Fn(&chrono::DateTime<chrono::Utc>) -> bool,
{
    if let Some(time_str) = timestamp_str {
        match parse_timestamp(&time_str) {
            Ok(time) => checker(&time),
            Err(_) => {
                err_msg(format!("Can't parse {time_str}"));
                false
            }
        }
    } else {
        true // If no timestamp is provided, consider it always valid
    }
}

fn actor(json_event: &Value) -> String {
    match json_event.get("auth") {
        Some(auth_json) => match auth_json.get("metadata") {
            Some(value) => match value.get("role_name") {
                Some(role_name) => role_name.as_str().unwrap().to_string(),
                None => str_from_json(&value, &["username"]).to_string(),
            },
            None => str_from_json(auth_json, &["display_name"]).to_string(),
        },
        None => {
            err_msg(format!("Can't get auth section for request_id={}", id(&json_event)).into());
            "".to_string()
        }
    }
}

fn id(json_event: &Value) -> String {
    match json_event.get("id") {
        Some(id) => return id.to_string(),
        None => {
            err_msg(format!("Can't get id out of {:?}", json_event));
            "".to_string()
        }
    }
}

fn format_id(id: &str) -> String {
    return id.chars().take(8).collect();
}

fn format_hmac(token: &str) -> String {
    let replaced = token.replace(HMAC_PFX_LONG, "");
    // the string 'hmac:' is 5 letters
    return replaced.chars().take(HMAC_LEN).collect();
}

fn tokens(event_json: &Value) -> String {
    let auth_token = format_hmac(&str_from_json_no_err(
        &event_json,
        &["auth", "client_token"],
    ));
    let auth_accessor = format_hmac(&str_from_json_no_err(&event_json, &["auth", "accessor"]));
    let common = format!("ath-tok:{auth_token}\nath-acc:{auth_accessor}");
    match str_from_json_no_err(&event_json, &["response", "auth", "accessor"]).len() {
        0 => {
            let req_client_token =
                format_hmac(&str_from_json(&event_json, &["request", "client_token"]));
            let req_accessor = format_hmac(&str_from_json(
                &event_json,
                &["request", "client_token_accessor"],
            ));
            return format!("{common}\nreq-tok:{req_client_token}\nreq-acc:{req_accessor}");
        }
        _ => {
            return common;
        }
    }
}

fn col2idx(table: &Table, title: &str) -> usize {
    // Get the index of a column by title
    let header = table.header().unwrap();
    for (idx, col) in header.cell_iter().enumerate() {
        if col.content() == title {
            return idx;
        }
    }
    err_msg_with_exit(format!("Can't find a header column with title='{title}'"));
    return 0;
}

#[allow(dead_code)]
fn resolve_ip_to_hostname(ip: IpAddr) -> Result<String, Box<dyn std::error::Error>> {
    let hostname = lookup_addr(&ip)?;
    Ok(hostname)
}

#[allow(dead_code)]
fn format_ipv4_addr(remote_addr: &str) -> String {
    if remote_addr == "" {
        return String::from("Remote addr missing");
    }

    let addr: IpAddr = remote_addr.parse().unwrap_or_else(|error| {
        err_msg(format!("Couldn't parse '{remote_addr}': {error}").into());
        "0.0.0.0".parse().unwrap()
    });

    return match resolve_ip_to_hostname(addr) {
        Ok(hostname) => hostname,
        Err(_) => format!("Can't resolve '{}'", remote_addr),
    };
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

fn read_lines(cli_args: &CliArgs, range: std::ops::Range<u64>) -> std::io::Result<Vec<String>> {
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
    let lines: Vec<Value> = reader
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
        .filter_map(|line| {
            match line {
                Ok(line) => match serde_json::from_str(&line) {
                    Ok(json) => Some(json),
                    Err(e) => {
                        eprintln!("Failed to parse JSON: {}", e); // Log or handle the error
                        None
                    }
                },
                Err(e) => {
                    eprintln!("Failed to read line: {}", e); // Log or handle the error
                    None
                }
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

            let raw_auth = json_value.get("auth");
            let raw_request = json_value.get("request");
            let raw_response = json_value.get("response");

            to_writer(&mut stdout, &json_value).unwrap();

            return true;
        })
        .collect::<Vec<Value>>();

    Ok(lines)
}

fn filter(
    cli_args: &CliArgs,
    lines: Vec<String>,
    summary: SharedMap<String, usize>,
) -> std::io::Result<Vec<Value>> {
    let mut tracked_hmacs: HashSet<String> = match &cli_args.track {
        Some(hmacs) => hmacs.iter().map(|x| x.to_string()).collect(),
        None => HashSet::new(),
    };

    let result = lines
        .into_iter()
        .filter_map(|line| match serde_json::from_str(&line) {
            Ok(json) => Some(json),
            Err(e) => {
                err_msg(format!(
                    "Failed to convert the following line to JSON: '{line}': {e}"
                ));
                None
            }
        })
        .filter(|event_json: &Value| {
            let event_type = str_from_json(&event_json, &["type"]);
            let mut summary = summary.lock().unwrap();
            let vault_path = str_from_json(&event_json, &["request", "path"]);
            let err = str_from_json_no_err(&event_json, &["error"]);

            // The summary should capture all of the events before any
            // filtering. If requests are included, then only the path in the
            // request events should be counted. This is to prevent
            // double-counting by looking at both the request and the
            // response.
            let should_update_summary =
                !cli_args.include_requests || event_type.as_str() == "request";
            if should_update_summary {
                *summary.entry(vault_path.to_string()).or_insert(0) += 1;
            }

            if event_type == "request" {
                // if an error exists in a request,
                // show it even if it was not requested
                if !cli_args.include_requests && err == "" {
                    return false;
                }
            }
            if !tracked_hmacs.is_empty() && !track_hmacs(&event_json, &mut tracked_hmacs) {
                return false;
            }
            if let Some(path) = &cli_args.path {
                if !vault_path.starts_with(path) {
                    return false;
                }
            }
            let event_time_str = str_from_json(&event_json, &["time"]);
            let event_time = match parse_timestamp(&event_time_str) {
                Ok(time) => time,
                Err(err) => {
                    err_msg(format!("Can't parse {event_time_str}: {err}"));
                    return false;
                }
            };
            if !within_time_bounds(&cli_args.start_time, |start_time| &event_time >= start_time) {
                return false;
            }
            if !within_time_bounds(&cli_args.end_time, |end_time| &event_time <= end_time) {
                return false;
            }
            if let Some(id) = &cli_args.id {
                let req_id = str_from_json(&event_json, &["request", "id"]);
                if !req_id.starts_with(id) {
                    return false;
                }
            }
            if let Some(cli_client_id) = &cli_args.client_id {
                let client_id = str_from_json_no_err(&event_json, &["request", "client_id"]);
                if !client_id.starts_with(&*cli_client_id) {
                    return false;
                }
            }
            return true;
        })
        .collect::<Vec<Value>>();
    return Ok(result);
}

fn process(cli_args: &CliArgs) -> std::io::Result<()> {
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
    let mut handles: Vec<JoinHandle<()>> = vec![];
    let queue: SharedQueue<Value> = Arc::new(Mutex::new(HashSet::new()));
    let summary: SharedMap<String, usize> = Arc::new(Mutex::new(HashMap::new()));
    ranges.into_iter().for_each(|range| {
        let queue_clone = Arc::clone(&queue);
        let summary_clone = Arc::clone(&summary);
        let cli_args_clone = cli_args.clone();
        let handle = std::thread::spawn(move || {
            let thread_id = std::thread::current().id();
            debug_msg!(format!(
                "Thread={:?}; Processing range {:?}",
                thread_id, range
            ));
            let mut queue = queue_clone.lock().unwrap();
            let lines = read_lines(&cli_args_clone, range.clone()).unwrap();
            let filtered = filter(&cli_args_clone, lines, summary_clone).unwrap();
            queue.extend(filtered);
        });
        handles.push(handle);
    });

    let thread_count = handles.len();
    ok_msg(format!("Threads: {}", thread_count));
    for handle in handles {
        handle.join().unwrap_or_else(|error| {
            err_msg(format!("Error waiting for thread to join: {:?}", error));
        });
    }
    debug_msg!(format!("Count of lines: {}", queue.lock().unwrap().len()));

    output(&cli_args, &queue, &summary);

    Ok(())
}

fn show_summary(summary: &SharedMap<String, usize>) {
    let mut sorted_vec: Vec<(String, usize)> = summary
        .lock()
        .unwrap()
        .iter()
        .map(|(k, &v)| (k.clone(), v))
        .collect();

    sorted_vec.sort_by(|a, b| b.1.cmp(&a.1));

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Path", "NumReq"]);
    for (path, count) in sorted_vec.into_iter().take(10) {
        table.add_row(vec![Cell::new(path), Cell::new(count)]);
    }
    println!("{table}");
}

fn output(cli_args: &CliArgs, queue: &SharedQueue<Value>, summary: &SharedMap<String, usize>) {
    let json_events = queue.lock().unwrap();
    if json_events.is_empty() {
        err_msg("Nothing found matching the criteria".to_string());
        return;
    }

    if cli_args.summary {
        show_summary(summary);
        return;
    }

    let mut sorted_vec: Vec<&Value> = json_events.iter().collect();
    sorted_vec.sort_by(|a, b| {
        let a_time = parse_timestamp(&str_from_json(&a, &["time"]));
        let b_time = parse_timestamp(&str_from_json(&b, &["time"]));
        match (a_time, b_time) {
            (Ok(a_time), Ok(b_time)) => a_time.cmp(&b_time), // Compare the actual timestamps
            (Err(_), Ok(_)) => std::cmp::Ordering::Less,     // Treat errors as "earlier"
            (Ok(_), Err(_)) => std::cmp::Ordering::Greater,  // Treat errors as "later"
            (Err(_), Err(_)) => std::cmp::Ordering::Equal,   // Both failed to parse
        }
    });

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);

    for event_json in sorted_vec {
        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        if cli_args.raw {
            to_writer(&mut stdout, &event_json).unwrap();
            println!("");
            continue;
        }

        let mut headers = vec![
            "ReqId", "ClientId", "Time", "Src IP", "Actor", "Tokens", "Op", "Path",
        ];
        if cli_args.include_requests {
            headers.insert(0, "Type");
        }
        table.set_header(headers);
        let mut row = vec![
            Cell::new(&format_id(&str_from_json(&event_json, &["request", "id"]))),
            Cell::new(&format_id(&str_from_json_no_err(
                &event_json,
                &["request", "client_id"],
            ))),
            Cell::new(&str_from_json(&event_json, &["time"])),
            Cell::new(&str_from_json(&event_json, &["request", "remote_address"])),
            Cell::new(&actor(&event_json)),
            Cell::new(&tokens(&event_json)),
            Cell::new(&str_from_json(&event_json, &["request", "operation"])),
            Cell::new(&str_from_json(&event_json, &["request", "path"])),
        ];

        let event_type = str_from_json(&event_json, &["type"]);
        if cli_args.include_requests {
            row.insert(
                0,
                Cell::new(match event_type.as_str() {
                    "request" => "req".to_string(),
                    "response" => "rsp".to_string(),
                    &_ => {
                        err_msg("Unexpected type: {}".into());
                        "".to_string()
                    }
                }),
            );
        }

        table.add_row(row);
    }

    if !cli_args.raw {
        if cli_args.include_requests {
            table
                .column_mut(col2idx(&table, "Type"))
                .unwrap()
                .set_constraint(ColumnConstraint::Absolute(Width::Fixed(3)));
        }
        table
            .column_mut(col2idx(&table, "Time"))
            .unwrap()
            .set_constraint(ColumnConstraint::Absolute(Width::Fixed(12)));
        // path
        table
            .column_mut(col2idx(&table, "Path"))
            .unwrap()
            .set_constraint(ColumnConstraint::Absolute(Width::Fixed(35)));
        println!("{table}");
    }

    ok_msg(format!("Found {} events", json_events.len()));
}

fn track_hmacs(event: &Value, tracked_tokens: &mut HashSet<String>) -> bool {
    // Given an event (request/response) and a list of tokens to track:
    //
    // 1. Get all the HMAC values in the event
    // 2. If any of tokens in the list of tokens to track (tracked_tokens)
    //    are present in the list of found HMAC values from step 1, merge
    //    the two lists and return the new set.
    let mut hmac_values: HashSet<String> = HashSet::new();

    // Find all hmac values in this event
    fn find_hmac_values(
        event: &Value,
        hmac_values: &mut HashSet<String>,
        include_keys: &HashSet<&str>,
    ) {
        match event {
            Value::Object(map) => {
                for (key, val) in map.iter() {
                    match val {
                        Value::Object(_) => find_hmac_values(val, hmac_values, include_keys),
                        Value::String(s) => {
                            if include_keys.contains(key.as_str()) && s.starts_with(HMAC_PFX_LONG) {
                                hmac_values.insert(s.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                // do nothing for everything else
            }
        }
    }

    let include_keys: HashSet<&str> = HashSet::from([
        "token",
        "accessor",
        "ciphertext",
        "plaintext",
        "client_token",
        "client_token_accessor",
    ]);
    find_hmac_values(event, &mut hmac_values, &include_keys);

    if hmac_values.iter().any(|hmac| {
        tracked_tokens.iter().any(|token| {
            // remove the prefix from the tokens before
            // comparing them
            let _hmac = hmac.replace(HMAC_PFX_LONG, "");
            let _token = token.replace(HMAC_PFX_LONG, "");
            _hmac.starts_with(&_token)
        })
    }) {
        tracked_tokens.extend(hmac_values);
        return true;
    }

    return false;
}

fn main() {
    init_logger();
    let cli_args = CliArgs::parse();
    // let args: Cli = parse_args();
    match process(&cli_args) {
        Ok(_) => {}
        Err(err) => err_msg(err.to_string()),
    }
    debug_msg!(format!("The arguments are: {:?}", cli_args));
}

// {{{ TESTS
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::{tempfile, NamedTempFile};

    #[test]
    fn test_find_beginning_of_line() -> std::io::Result<()> {
        // uncomment to enable logging in testing
        // init_logger();

        // Create a temporary file with known content
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

    fn assert_filter_lines(file_path: &str, range: std::ops::Range<u64>, expected: &[&str]) {
        let result = filter_lines(file_path, range);
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
            include_requests: false,
            summary: false,
            path: None,
            start_time: String::from("").into(),
            end_time: String::from("").into(),
            track: None,
        };

        // Test case 1: start at byte 0 and request 1 byte. Should still give
        // us the whole of the first line.
        assert_filter_lines(file.path().to_str().unwrap(), 0..1, &["First line"]);

        // Test case 3: start at byte 0 and request 11 bytes (up to and
        // including the \n of the first line). Should still give us the whole
        // of the first line.
        assert_filter_lines(file.path().to_str().unwrap(), 0..11, &["First line"]);

        // Test case 3: start at byte 0 and request 12 bytes (first byte of
        // line 2). Should still give us lin1 and line 2.
        assert_filter_lines(
            file.path().to_str().unwrap(),
            0..12,
            &["First line", "Second line"],
        );

        // Test case 4: start at byte 30 (end of line 3) and request 100 bytes
        // (well past the end of line 3). Should still give us all of line 3.
        assert_filter_lines(file.path().to_str().unwrap(), 30..130, &["Third line"]);

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
            let mut event_json = json!("hmac-sha256:1234567890abcdef");
            format_hmacs(&mut event_json);
            assert_eq!(event_json, json!("hmac-sha256:1234567890"));
        }

        #[test]
        fn test_format_hmacs_on_nested_object() {
            let mut event_json = json!({
                "key": "hmac-sha256:1234567890abcdef",
                "nested": {
                    "hmac": "hmac-sha256:abcdef1234567890"
                }
            });
            format_hmacs(&mut event_json);
            assert_eq!(
                event_json,
                json!({
                    "key": "hmac-sha256:1234567890",
                    "nested": {
                        "hmac": "hmac-sha256:abcdef1234"
                    }
                })
            );
        }

        #[test]
        fn test_format_hmacs_on_array() {
            let mut event_json = json!([
                "hmac-sha256:abcdef1234567890",
                "hmac-sha256:9876543210abcdef"
            ]);
            format_hmacs(&mut event_json);
            assert_eq!(
                event_json,
                json!(["hmac-sha256:abcdef1234", "hmac-sha256:9876543210"])
            );
        }

        #[test]
        fn test_format_hmacs_no_change_for_non_hmac_string() {
            let mut event_json = json!("some other string");
            format_hmacs(&mut event_json);
            assert_eq!(event_json, json!("some other string"));
        }

        #[test]
        fn test_format_hmacs_no_change_for_non_string_value() {
            let mut event_json = json!(123);
            format_hmacs(&mut event_json);
            assert_eq!(event_json, json!(123));
        }
    }

    mod test_track_hmacs {
        use super::*;

        #[test]
        fn when_extra_tokens_present() {
            let hmac_str = format!("{HMAC_PFX_LONG}:123456789");
            let tracked_tok = format!("{hmac_str}a");
            let event_json = json!({
                "token": tracked_tok,
                "accessor": format!("{hmac_str}b"),
                "plaintext": format!("{hmac_str}c"),
                "client_token_accessor": format!("{hmac_str}d"),
                "key1": {
                     "ciphertext": format!("{hmac_str}e"),
                     "client_token": format!("{hmac_str}f")
                }
            });
            let mut tracked_hmacs: HashSet<String> = HashSet::new();
            tracked_hmacs.insert(tracked_tok.to_string());

            // all of the HMACs should be found
            let mut expected: HashSet<String> = HashSet::new();
            ('a'..='f').for_each(|chr| {
                let hmac_str = format!("{hmac_str}{chr}");
                expected.insert(hmac_str.to_string());
            });

            let result = track_hmacs(&event_json, &mut tracked_hmacs);
            assert_eq!(tracked_hmacs, expected);
            assert_eq!(result, true);
        }

        #[test]
        fn when_nothing_extra_found() {
            // This token is not related to any of the tokens in the request.
            // So the tracked tokens set should not expand.
            let tracked_tok = format!("hmac:abcdef");
            let hmac_str = "hmac:123456789";
            let event_json = json!({
                "token": format!("{hmac_str}a"),
                "accessor": format!("{hmac_str}b"),
                "plaintext": format!("{hmac_str}c"),
                "client_token_accessor": format!("{hmac_str}d"),
                "key1": {
                     "ciphertext": format!("{hmac_str}e"),
                     "client_token": format!("{hmac_str}f")
                }
            });

            let mut tracked_hmacs: HashSet<String> = HashSet::new();
            tracked_hmacs.insert(tracked_tok.to_string());
            track_hmacs(&event_json, &mut tracked_hmacs);

            // all of the HMACs should be found
            let mut expected: HashSet<String> = HashSet::new();
            ('a'..='f').for_each(|chr| {
                let hmac_str = format!("{hmac_str}{chr}");
                expected.insert(hmac_str.to_string());
            });

            let result = track_hmacs(&event_json, &mut tracked_hmacs);
            assert_eq!(tracked_hmacs, [tracked_tok].into());
            assert_eq!(result, false);
        }
    }

    mod test_get_str_from_json {
        use super::*;

        #[test]
        fn with_first_level_key() {
            let event_json = json!({
                "key": "value",
            });

            assert_eq!(str_from_json(&event_json, &["key"]), "value");
        }

        #[test]
        fn with_second_level_key() {
            let event_json = json!({
                "key1": {
                    "key2": "value",
                }
            });

            assert_eq!(str_from_json(&event_json, &["key1", "key2"]), "value");
        }

        #[test]
        fn with_missing_first_level_key() {
            let event_json = json!({
                "key": "value"
            });

            assert_eq!(str_from_json(&event_json, &["wrong"]), "");
        }

        #[test]
        fn with_missing_second_level_key() {
            let event_json = json!({
                "key1": {
                    "key2": "value",
                }
            });

            assert_eq!(str_from_json(&event_json, &["key1", "wrong"]), "");
        }
    }
}
// }}}
