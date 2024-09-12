use colored::Colorize;
use log::{debug, error};
use num_cpus;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::Once;
use std::thread::JoinHandle;

static INIT: Once = Once::new();

const CHUNK_SIZE: usize = 8;
const MIN_BYTES_PER_THREAD: u64 = 2_000;

pub fn init_logger() {
    INIT.call_once(|| {
        env_logger::init();
    });
}

macro_rules! debug_msg {
    ($msg:expr) => {{
        let location = std::panic::Location::caller();
        debug!("{}:{}: {}", location.file(), location.line(), $msg);
    }};
}

fn err_msg(msg: String) {
    error!("ERROR: {}", msg.red());
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

fn filter_lines(file_path: &str, range: std::ops::Range<u64>) -> std::io::Result<Vec<Value>> {
    let mut file = File::open(file_path)?;

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
                // debug_msg!(format!(
                //     "Read '{line}', bytes_read={num_bytes_read}, byte_limit={byte_limit}"
                // ));
                true
            } else {
                false
            }
        })
        .map(|line| {
            Ok(serde_json::from_str(&line.unwrap())?)
        })
        .collect::<Result<Vec<Value>, serde_json::Error>>()?; // Collect results into a vector and handle errors

    return Ok(lines);
}

fn process(file_path: &str, use_threads: &String) -> std::io::Result<()> {
    let logical_cores = num_cpus::get();
    let metadata = std::fs::metadata(file_path)?;
    let file_size = metadata.len();
    let num_threads = if use_threads == "no" {
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
    ranges.into_iter().for_each(|range| {
        let file_path = file_path.to_string();
        let handle = std::thread::spawn(move || {
            let thread_id = std::thread::current().id();
            debug_msg!(format!(
                "Thread={:?}; Processing range {:?}",
                thread_id, range
            ));
            let result = filter_lines(&file_path, range.clone());
            let _ = match result {
                Ok(lines) => println!("Read {} lines", lines.len()),
                Err(err) => err_msg(format!(
                    "can't process byte range {} thru {} of {file_path}: {err}",
                    range.start, range.end
                )),
            };
        });
        handles.push(handle);
    });

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

fn main() {
    init_logger();

    let args: Vec<String> = env::args().collect();
    // Check if there are enough arguments
    if args.len() < 3 {
        err_msg("usage: <FILE> <USE-THREADS>".into());
    } else {
        let fname = &args[1];
        let use_threads = &args[2];
        let _ = process(fname, use_threads);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
