use chrono::{DateTime, ParseResult, Utc};
use clap::{ArgAction, Parser};
use colored::{Color, ColoredString, Colorize};
use comfy_table::{presets::UTF8_FULL, Cell, ColumnConstraint, Table, Width};
use dns_lookup::lookup_addr;
use log::{debug, error, info, trace, Level, LevelFilter};
use num_cpus;
use num_format::{Locale, ToFormattedString};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;
use std::time::Instant;
use termcolor::{ColorChoice, StandardStream};
use termcolor_json::to_writer;

type SharedQueue<T> = Arc<Mutex<HashSet<T>>>;
type SharedSummary = Arc<Mutex<Summary>>;

static INIT: Once = Once::new();
const MAX_SUMMARY_LINES: usize = 10;
// Human-friendly length of HMAC values
const HMAC_LEN: usize = 10;
// Hmac prefix
const HMAC_PFX_LONG: &str = "hmac-sha256:";
const MIN_BYTES_PER_THREAD: u64 = 2_000;

// Define a new trait
pub trait NumFormat {
    fn fmt(&self) -> String;
}

impl NumFormat for usize {
    fn fmt(&self) -> String {
        self.to_formatted_string(&Locale::en)
    }
}

// Define a new trait for custom colorization
pub trait CustomColors {
    fn brown(&self) -> ColoredString;
    fn grey(&self) -> ColoredString;
}

// Implement the BrownColorize trait for the `&str` type
impl CustomColors for str {
    fn brown(&self) -> ColoredString {
        self.color(Color::TrueColor {
            r: 194,
            g: 90,
            b: 0,
        })
    }

    fn grey(&self) -> ColoredString {
        self.color(Color::TrueColor {
            r: 104,
            g: 104,
            b: 104,
        })
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "Read vault audit log", version = "1.0")]
struct CliArgs {
    /// Limit to a request with a given id
    #[arg(long = "id", value_name = "Request-Id", help = "filter by request id")]
    id: Option<String>,

    /// Limit to requests with a given client id
    #[arg(
        long = "actor",
        value_name = "user_id",
        conflicts_with = "summary",
        help = "id of the actor (e.g. username or role name)"
    )]
    actor: Option<String>,

    /// Limit to requests with a given client id
    #[arg(
        long = "client-id",
        value_name = "Client-Id",
        help = "filter by client id"
    )]
    client_id: Option<String>,

    /// Specify number of workers
    #[arg(short = 'T', long = "threads")]
    threads: Option<usize>,

    /// Include requests too
    #[arg(short = 'R', long = "include-requests", action = ArgAction::SetTrue)]
    include_requests: bool,

    /// Show the date of the first and last log entries
    #[arg(long = "show-date-range", action = ArgAction::SetTrue)]
    show_date_range: bool,

    /// Show only the summary
    #[arg(long = "summary", action = ArgAction::SetTrue)]
    summary: bool,

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

#[derive(Debug, Clone)]
struct Summary {
    count_by_path: HashMap<String, usize>,
    total_events: usize,
}

impl Summary {
    fn new() -> Self {
        Summary {
            count_by_path: HashMap::new(),
            total_events: 0,
        }
    }
}

macro_rules! debug_msg {
    ($msg:expr) => {{
        let location = std::panic::Location::caller();
        debug!("{}:{}: {}", location.file(), location.line(), $msg);
    }};
}

pub fn init_logger(level: Option<&str>) {
    INIT.call_once(|| {
        let mut builder = env_logger::Builder::new();
        let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| {
            match level {
                Some(level) => level.to_string(),
                // Set the default log level to `Info`
                None => "info".to_string(),
            }
        });
        builder.filter(None, log_level.parse().unwrap_or(LevelFilter::Info));
        //builder.format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()));
        builder.format(|buf, record| match record.level() {
            Level::Info => writeln!(buf, "{}", record.args()),
            _ => writeln!(buf, "{}: {}", record.level(), record.args()),
        });
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
                    err_msg(format!("Missing key: {key}, event_json={:?}", event_json));
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
                err_msg(format!("Can't parse '{time_str}' as time"));
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

fn split_into_ranges(filename: &str, num_ranges: usize) -> io::Result<Vec<std::ops::Range<u64>>> {
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);

    let file_size = reader.seek(SeekFrom::End(0))?;
    if file_size == 0 || num_ranges == 0 {
        return Ok(Vec::new()); // No ranges requested
    }

    // Go to the beginning of the file
    reader.seek(SeekFrom::Start(0))?;

    let chunk_size: u64 = file_size / num_ranges as u64;
    let mut cur_start = 0;
    let mut ranges = Vec::new();

    trace!(
        "{:?}: Splitting {file_size} bytes into {num_ranges} ranges of {chunk_size} bytes",
        std::thread::current().id(),
    );
    for _ in 0..num_ranges {
        let mut cur_end = cur_start + chunk_size;
        if cur_start >= file_size {
            trace!(
                "{:?}: start={cur_start} >= last_byte ({}), end={cur_end}",
                std::thread::current().id(),
                file_size - 1,
            );
            return Ok(ranges);
        }
        if cur_end >= file_size {
            trace!(
                "{:?}: start={cur_start}, end={cur_end} >= last_byte ({})",
                std::thread::current().id(),
                file_size - 1,
            );
            ranges.push(cur_start..file_size);
            return Ok(ranges);
        }

        // Seek to the approximate end and find the next new line char
        reader.seek(SeekFrom::Start(cur_end))?;

        // Read until next new line
        let mut buffer = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            // No newline found, just go from current_start to the end of the file
            ranges.push(cur_start..file_size);
            break;
        }
        trace!(
            "{:?}: read {bytes_read} bytes, the buffer contains {:?}",
            std::thread::current().id(),
            buffer.into_iter().map(|n| n as char).collect::<Vec<_>>()
        );

        // It's -1 because if for example we started reading on byte 4 and read 2 bytes, our
        // position should be 5: byte 4 + byte 5. If we just add 4 and 2 it's 6, which is wrong.
        cur_end += (bytes_read - 1) as u64;
        trace!(
            "{:?}: range: start={cur_start}, end={cur_end}",
            std::thread::current().id(),
        );
        ranges.push(cur_start..cur_end);

        cur_start = cur_end + 1;
    }

    Ok(ranges)
}

fn read_range(log_file: &str, range: std::ops::Range<u64>) -> std::io::Result<Vec<String>> {
    let mut file = File::open(log_file)?;

    let line_start = range.start;

    trace!("{}", format!("Reading from pos={line_start}"));
    file.seek(SeekFrom::Start(line_start))?;
    let reader = BufReader::new(file);

    let byte_limit: u64 = (range.count() as u64) + 1;
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

fn filter(
    cli_args: &CliArgs,
    lines: &Vec<String>,
    summary: &mut Summary,
) -> std::io::Result<Vec<Value>> {
    let start = Instant::now();
    debug_msg!(format!(
        "Filtering thread {:?} is starting",
        std::thread::current().id()
    )
    .yellow());

    let mut count: usize = 0;
    let result = lines
        .into_iter()
        .filter_map(|line| {
            count += 1;
            match serde_json::from_str(&line) {
                Ok(json) => Some(json),
                Err(e) => {
                    err_msg(format!(
                        "Failed to convert the following line to JSON: '{line}': {e}"
                    ));
                    None
                }
            }
        })
        .filter(|event_json: &Value| {
            let event_type = str_from_json(&event_json, &["type"]);
            let vault_path = str_from_json(&event_json, &["request", "path"]);
            let err = str_from_json_no_err(&event_json, &["error"]);

            if event_type == "request" {
                // if an error exists in a request,
                // show it even if it was not requested
                if !cli_args.include_requests && err == "" {
                    return false;
                }
            }
            if let Some(path) = &cli_args.path {
                if !vault_path.contains(path) {
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
            if let Some(cli_actor) = &cli_args.actor {
                let actor = str_from_json_no_err(&event_json, &["actor"]);
                if !actor.starts_with(&*cli_actor) {
                    return false;
                }
            }
            // TODO: TEST!
            let should_update_summary =
                cli_args.summary || !cli_args.include_requests || event_type.as_str() == "request";
            if should_update_summary {
                *summary
                    .count_by_path
                    .entry(vault_path.to_string())
                    .or_insert(0) += 1;
            }
            // Don't process anything else because only the summary will be shown. Forgetting this
            // simple idea was why the performance was so myseriously bad.
            if cli_args.summary {
                return false;
            }
            return true;
        })
        .collect::<Vec<Value>>();

    summary.total_events = count;

    let end = Instant::now();
    debug_msg!(format!(
        "Filter thread thread={:?} finished in {:?}",
        std::thread::current().id(),
        end - start,
    )
    .yellow());
    return Ok(result);
}

fn process(cli_args: &CliArgs) -> std::io::Result<()> {
    let logical_cores = num_cpus::get();
    let metadata = std::fs::metadata(&cli_args.log_file)?;
    let file_size = metadata.len();
    let num_threads = if let Some(threads) = cli_args.threads {
        if threads > logical_cores {
            println!(
                "Warning: number of threads ({}) exceed logical cores ({}), capping to {}",
                threads, logical_cores, logical_cores
            );
        }
        std::cmp::min(logical_cores, threads)
    } else {
        std::cmp::min(
            (file_size / MIN_BYTES_PER_THREAD).max(1) as usize,
            logical_cores,
        )
    };
    debug_msg!(format!("Number of threads is {num_threads}"));

    // Use mpsc channel for communication between threads
    let (tx, rx) = mpsc::channel::<(Vec<Value>, Summary)>();
    let start = Instant::now();
    let ranges = split_into_ranges(cli_args.log_file.as_str(), num_threads).unwrap();
    let end = Instant::now();
    debug_msg!(format!("Range processing finished in {:?}", end - start,));
    let mut handles: Vec<JoinHandle<()>> = vec![];
    let summary: Summary = Summary::new();
    ranges.into_iter().for_each(|range| {
        let mut summary = summary.clone();
        let cli_args_clone = cli_args.clone();
        let tx = tx.clone();
        let handle = std::thread::spawn(move || {
            let thread_id = std::thread::current().id();
            // TODO: move inside filter potentially
            debug_msg!(format!(
                "Thread={:?} will process {:?} bytes ({}) {}",
                thread_id,
                range,
                if range.end - range.start >= 1_000_000 {
                    (range.end - range.start) as f64 / 1_000_000.0 // in MB
                } else {
                    (range.end - range.start) as f64 / 1_000.0 // in KB
                },
                if range.end - range.start >= 1_000_000 {
                    "MB"
                } else {
                    "KB"
                },
            )
            .yellow());
            let lines = read_range(&cli_args_clone.log_file, range.clone()).unwrap();
            let filtered = filter(&cli_args_clone, &lines, &mut summary).unwrap();
            tx.send((filtered, summary)).unwrap();
        });
        handles.push(handle);
    });

    drop(tx);

    ok_msg(format!("Threads: {}", handles.len()));

    let mut handles: Vec<JoinHandle<()>> = vec![];
    let global_queue: SharedQueue<Value> = Arc::new(Mutex::new(HashSet::new()));
    let global_summary: SharedSummary = Arc::new(Mutex::new(Summary::new()));

    let start = Instant::now();
    for (queue, summary) in rx {
        let global_queue_clone = Arc::clone(&global_queue);
        let global_summary_clone = Arc::clone(&global_summary);
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            debug_msg!(format!(
                "Post-processing thread {:?} begins working on {} lines and {} summary entries",
                std::thread::current().id(),
                queue.len(),
                summary.count_by_path.len(),
            )
            .brown());
            global_queue_clone.lock().unwrap().extend(queue);
            for (key, val) in summary.count_by_path {
                *global_summary_clone
                    .lock()
                    .unwrap()
                    .count_by_path
                    .entry(key)
                    .or_insert(0) += val;
            }
            global_summary_clone.lock().unwrap().total_events += summary.total_events;

            let end = Instant::now();
            debug_msg!(format!(
                "Post-processing thread {:?} finished in {:?}",
                std::thread::current().id(),
                end - start,
            )
            .brown());
        });
        handles.push(handle);
    }

    for handle in handles {
        debug_msg!(format!("Reaped thread={:?}", handle.thread().id()).cyan());
        handle.join().unwrap_or_else(|error| {
            err_msg(format!("Error waiting for thread to join: {:?}", error));
        });
    }
    let end = Instant::now();
    debug_msg!(format!("All of post-filtering finished in {:?}", end - start).green());

    if !cli_args.summary {
        debug_msg!(format!(
            "Count of lines: {}",
            global_queue.lock().unwrap().len().fmt()
        ))
    };
    output(&cli_args, &global_queue, &global_summary);
    Ok(())
}

fn show_summary(summary: &SharedSummary) {
    let mut sorted_vec: Vec<(String, usize)> = summary
        .lock()
        .unwrap()
        .count_by_path
        .iter()
        .map(|(k, &v)| (k.clone(), v))
        .collect();

    sorted_vec.sort_by(|a, b| b.1.cmp(&a.1));

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Path", "NumReq"]);

    // let num_records = sorted_vec.len();
    // let earliest = str_from_json_no_err(sorted_vec.first(), &["time"]);

    let mut total_filtered: usize = 0;
    for (index, (path, count)) in sorted_vec.into_iter().enumerate() {
        if index <= MAX_SUMMARY_LINES {
            table.add_row(vec![Cell::new(path), Cell::new(count)]);
        }
        total_filtered += count;
    }

    println!("{table}");
    ok_msg(format!(
        "Number of un-filtered records: {}",
        summary.lock().unwrap().total_events.fmt()
    ));
    ok_msg(format!(
        "Number of filtered records: {}",
        total_filtered.fmt()
    ))
}

fn output(cli_args: &CliArgs, queue: &SharedQueue<Value>, summary: &SharedSummary) {
    if cli_args.summary {
        show_summary(summary);
        return;
    }

    let json_events = queue.lock().unwrap();
    if json_events.is_empty() {
        err_msg("Nothing found matching the criteria".to_string());
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
            "ReqId",
            "ClientId",
            "Time",
            "Src IP",
            "Actor/\nEntity",
            "Tokens",
            "Op",
            "Path",
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
            Cell::new(format!(
                "{}/\n{}",
                actor(&event_json),
                format_id(&str_from_json_no_err(&event_json, &["auth", "entity_id"])),
            )),
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

    ok_msg(format!("Found {} events", json_events.len().fmt()));
}

fn get_last_line(filename: &str) -> std::io::Result<String> {
    const BUFSIZE: usize = 512;
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    let mut buf = [0; BUFSIZE];

    let file_size = reader.seek(SeekFrom::End(0))?;
    if file_size == 0 {
        return Ok("".to_string());
    }

    let mut seek_pos = reader.seek(SeekFrom::End(-1))?;
    trace!("Initial seek_pos={seek_pos}");
    'outer: loop {
        let read_size = std::cmp::min(seek_pos, BUFSIZE as u64);
        trace!("buf size = {}", read_size);
        seek_pos = seek_pos.saturating_sub(read_size);
        if seek_pos == 0 {
            trace!("Got to the beginning of the file");
        };
        reader.seek(SeekFrom::Start(seek_pos))?;
        trace!("Current seek position={}", seek_pos);
        reader.read_exact(&mut buf[..read_size as usize])?;
        // Let's say we're at the end of the file:
        //
        // Let's say the buf contains: line1\nline2\nline3\n
        //
        // If we now search for a new line iteration in the buffer starting
        // from 0, we'll find the newline after line1. But what we need is
        // the one after line2 (first new line to left of line3).
        //
        // So we need to iterate from read_size to 0 (or right to left).
        // This is what .rev() does. And when we iteratate that way, we'll
        // first get to the \n after line2.
        for i in (0..read_size).rev() {
            trace!("i={}", i);
            if i == 0 {
                trace!(
                    "Nothing found in seek_pos={} through 0",
                    reader.stream_position()?
                );
                break;
            }
            // if the next byte to the left is '\n', break.
            if buf[(i as usize) - 1] == b'\n' {
                trace!(
                    "The buffer contains: {:?}",
                    buf.iter()
                        .take(read_size as usize)
                        .map(|c| *c as char)
                        .collect::<String>()
                );
                trace!(
                    "Found new line at seek_pos={}+{}={}",
                    seek_pos,
                    i,
                    seek_pos + i
                );
                reader.seek(SeekFrom::Start(seek_pos + i))?;
                break 'outer;
            }
        }

        if seek_pos == 0 {
            trace!("No new line found");
            reader.seek(SeekFrom::Start(0))?;
            break;
        }
    }

    let mut line = String::new();
    trace!("Reading line at seek_pos={}...", reader.stream_position()?,);
    reader.read_line(&mut line)?;
    trace!("... line='{}'", line,);
    Ok(line)
}

fn parse_json_line(line: &str) -> std::io::Result<Value> {
    match serde_json::from_str(line) {
        Ok(json) => Ok(json),
        Err(e) => {
            err_msg(format!(
                "Failed to convert the following line to JSON: '{line}': {e}"
            ));
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}

fn show_date_range(filename: &str) -> std::io::Result<()> {
    // Output the time of the first and last records
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let first_line_json = parse_json_line(&line).unwrap();

    let last_line = get_last_line(&filename).unwrap();
    let last_line_json = parse_json_line(&last_line).unwrap();

    println!(
        "Earliest record: {}",
        str_from_json(&first_line_json, &["time"])
    );
    println!(
        "Latest record:   {}",
        str_from_json(&last_line_json, &["time"])
    );

    Ok(())
}

fn main() {
    init_logger(Some("info"));
    let cli_args = CliArgs::parse();
    let start = Instant::now();
    if cli_args.show_date_range {
        show_date_range(&cli_args.log_file).unwrap();
        return;
    }

    match process(&cli_args) {
        Ok(_) => {
            let end = Instant::now();
            debug_msg!(format!("main() finished in {:?}", end - start).green());
        }
        Err(err) => err_msg(err.to_string()),
    }
    debug_msg!(format!("The arguments are: {:?}", cli_args).grey());
}

// {{{ TESTS
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_get_last_line() -> std::io::Result<()> {
        init_logger(Some("trace"));

        let mut file = NamedTempFile::new()?;
        let contents = "First line\nSecond line\nThird line\n";
        write!(file, "{contents}")?;
        let filename = file.path().to_str().unwrap();
        assert_eq!(get_last_line(filename).unwrap(), "Third line\n".to_string());

        let mut file = NamedTempFile::new()?;
        let contents = "First line";
        write!(file, "{contents}")?;
        let filename = file.path().to_str().unwrap();
        assert_eq!(get_last_line(filename).unwrap(), "First line".to_string());

        let mut file = NamedTempFile::new()?;
        let contents = "F";
        write!(file, "{contents}")?;
        let filename = file.path().to_str().unwrap();
        assert_eq!(get_last_line(filename).unwrap(), "F".to_string());

        let mut file = NamedTempFile::new()?;
        let contents = "";
        write!(file, "{contents}")?;
        let filename = file.path().to_str().unwrap();
        assert_eq!(get_last_line(filename).unwrap(), "".to_string());

        let mut file = NamedTempFile::new()?;
        let contents = "\n".to_string();
        write!(file, "{contents}")?;
        let filename = file.path().to_str().unwrap();
        assert_eq!(get_last_line(filename).unwrap(), "\n".to_string());

        Ok(())
    }

    #[test]
    fn test_read_range() -> std::io::Result<()> {
        init_logger(None);

        // Create a temporary file with known content
        let mut file = NamedTempFile::new()?;
        let contents = "First1line\nSecond2line\nThird3line\n";
        write!(file, "{contents}")?;
        let filename = file.path().to_str().unwrap();

        // Start at byte 0 and request 2 bytes. Should return the whole
        // first line.
        assert_eq!(read_range(filename, 0..1).unwrap(), &["First1line"]);
        // bytes representing all of First1line
        assert_eq!(read_range(filename, 0..10).unwrap(), &["First1line"]);
        // Start at byte 10 (eol of line 1) and request 2 bytes. Should return the whole
        // second line. The empty string is because the first position was
        // a newline.
        assert_eq!(read_range(filename, 10..11).unwrap(), &["", "Second2line"]);
        assert_eq!(
            read_range(filename, 0..1000).unwrap(),
            &["First1line", "Second2line", "Third3line"]
        );

        Ok(())
    }

    #[test]
    fn test_split_into_ranges() -> std::io::Result<()> {
        init_logger(Some("trace"));
        let mut file = NamedTempFile::new()?;
        let contents = "First1line\nSecond2line\nThird3line\n";
        write!(file, "{contents}")?;
        let path = file.path().to_str().unwrap();

        assert_eq!(split_into_ranges(path, 0).unwrap(), vec![]);
        assert_eq!(split_into_ranges(path, 1).unwrap(), vec![0..34]);
        assert_eq!(split_into_ranges(path, 2).unwrap(), vec![0..22, 23..34]);
        assert_eq!(split_into_ranges(path, 3).unwrap(), vec![0..22, 23..34]);
        assert_eq!(
            split_into_ranges(path, 10).unwrap(),
            vec![0..10, 11..22, 23..33]
        );

        Ok(())
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
    mod test_filter {
        use super::*;

        fn response() -> Value {
            let mut response = request();
            let response_data = json!({
                "response": {
                    "status": "success",
                    "data": {
                        "message": "Operation completed"
                    }
                }
            });

            // Check if `json_value` is an object and add the new data
            if let Some(obj) = response.as_object_mut() {
                obj.extend(response_data.as_object().unwrap().clone());
                obj.insert("type".to_string(), Value::String("response".to_string()));
            }

            return response;
        }

        fn request() -> Value {
            let event_json = json!({
                "time": "2024-08-15T03:07:05.192602684Z",
                "type": "request",
                "auth": {
                    "client_token": "hmac-sha256:client-token",
                    "accessor": "hmac-sha256:accessor",
                    "display_name": "display-name",
                    "entity_id": "entity-id"
                },
                "request": {
                    "id": "id",
                    "client_id": "client-id",
                    "operation": "read",
                    "client_token": "client-token",
                    "client_token_accessor": "client-token-accessor",
                    "path": "some-path",
                    "remote_address": "1.1.1.1"
                }
            });

            return event_json;
        }

        fn get_default_args() -> CliArgs {
            CliArgs {
                id: None,
                client_id: None,
                threads: None,
                // don't need it for this test
                log_file: "not a file".to_string(),
                raw: false,
                include_requests: false,
                summary: false,
                path: None,
                start_time: None,
                end_time: None,
            }
        }

        #[test]
        fn test_default_when_request() {
            init_logger(None);
            let cli = get_default_args();
            let request = request();
            let mut summary: HashMap<String, usize> = HashMap::new();
            let lines: Vec<String> = vec![request.to_string()];
            let filtered = filter(&cli, &lines, &mut summary).unwrap();
            assert_eq!(filtered, Vec::<Value>::new());
        }

        #[test]
        fn test_default_when_response() {
            init_logger(None);
            let cli = get_default_args();
            let response = response();
            let lines: Vec<String> = vec![response.to_string()];

            let mut summary: HashMap<String, usize> = HashMap::new();
            let filtered = filter(&cli, &lines, &mut summary).unwrap();
            let mut sum_expected = HashMap::new();
            sum_expected.insert("some-path".to_string(), 1);

            assert_eq!(filtered, vec![response]);
            // assert_eq!(summary, sum_expected);
        }

        #[test]
        fn test_with_requests_included() {
            init_logger(None);
            let mut cli = get_default_args();
            cli.include_requests = true;
            let request = request();
            let lines: Vec<String> = vec![request.to_string()];

            let mut summary: HashMap<String, usize> = HashMap::new();
            let filtered = filter(&cli, &lines, &mut summary).unwrap();
            let mut sum_expected = HashMap::new();
            sum_expected.insert("some-path".to_string(), 1);

            assert_eq!(filtered, vec![request]);
            assert_eq!(summary, sum_expected);
        }

        #[test]
        fn test_with_1_req_and_two_responses() {
            init_logger(None);

            // Test that when requests are present, only their paths are counted
            let mut cli = get_default_args();
            cli.include_requests = true;

            let request = request();
            let response_1 = response();
            let response_2 = response();

            let lines: Vec<String> = vec![
                request.to_string(),
                response_1.to_string(),
                response_2.to_string(),
            ];
            let mut summary: HashMap<String, usize> = HashMap::new();
            let filtered = filter(&cli, &lines, &mut summary).unwrap();
            let mut sum_expected = HashMap::new();
            sum_expected.insert("some-path".to_string(), 1);

            assert_eq!(filtered, vec![request, response_1, response_2]);
            assert_eq!(summary, sum_expected);
        }

        #[test]
        fn test_with_two_responses() {
            init_logger(None);
            // Test that when only responses are present, all of them
            // contribute to the by-path count.
            let cli = get_default_args();
            let request = request();
            let response_1 = response();
            let response_2 = response();

            let lines: Vec<String> = vec![
                request.to_string(), // this should be filtered out because
                // include_requests is absent
                response_1.to_string(),
                response_2.to_string(),
            ];
            let mut summary: HashMap<String, usize> = HashMap::new();
            let filtered = filter(&cli, &lines, &mut summary).unwrap();
            let mut sum_expected = HashMap::new();
            sum_expected.insert("some-path".to_string(), 2);

            assert_eq!(filtered, vec![response_1, response_2]);
            assert_eq!(summary, sum_expected);
        }
    }
}
// }}}
