use colored::Colorize;
use log::{debug, error};
use std::env;
use std::fs::File;
use std::io::Read;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::Once;

static INIT: Once = Once::new();

const CHUNK_SIZE: usize = 8;

pub fn init_logger() {
    INIT.call_once(|| {
        env_logger::init();
    });
}

fn debug_msg(msg: String) {
    debug!("{}", msg);
}

fn err_msg(msg: String) {
    error!("{}", msg.red());
}

fn find_beginning_of_line(file: &mut File, start_pos: u64) -> std::io::Result<u64> {
    let mut buffer = [0; CHUNK_SIZE];
    let mut seek_pos = start_pos;

    loop {
        let read_size = std::cmp::min(seek_pos as usize, CHUNK_SIZE);
        seek_pos = seek_pos.saturating_sub(read_size as u64);
        if seek_pos == 0 {
            debug_msg("Got to the beginning of the file".into());
            break;
        }
        file.seek(SeekFrom::Start(seek_pos))?;
        file.read_exact(&mut buffer[..read_size])?;
        for i in (0..read_size).rev() {
            if buffer[i] == b'\n' {
                debug_msg(format!(
                    "Found new line in the buffer at position {i}"
                ));
                debug_msg(format!(
                    "The buffer contains {:?}",
                    buffer.into_iter().map(|n| n as char).collect::<Vec<_>>()
                ));
                debug_msg(format!("Start position is {start_pos}").into());
                debug_msg(format!("Seek position is {seek_pos}").into());
                let line_start = seek_pos + i as u64 + 1;
                debug_msg(format!(
                    "Line start is {seek_pos} + {i} + 1 = {line_start}"
                ));
                return Ok(line_start);
            }
        }
    }

    return Ok(seek_pos);
}

fn read_some_lines(file_path: &str, start_pos: u64, n: usize) -> std::io::Result<Vec<String>> {
    let mut file = File::open(file_path)?;

    let line_start = match find_beginning_of_line(&mut file, start_pos) {
        Ok(line_start) => {
            debug_msg(format!("Line starts at pos {line_start}"));
            line_start
        }
        Err(err) => return Err(err),
    };

    debug_msg(format!("Reading from pos={line_start}"));
    file.seek(SeekFrom::Start(line_start))?;
    let reader = BufReader::new(file);

    // Collect N lines from the current position
    let lines: Vec<String> = reader
        .lines()
        .take(n) // Limit to N lines
        .collect::<Result<_, _>>()?; // Collect results into a vector and handle errors

    return Ok(lines);
}

fn main() {
    init_logger();

    let args: Vec<String> = env::args().collect();
    // Check if there are enough arguments
    if args.len() < 4 {
        debug_msg("usage: <FILE> <START_POS> <NUM_LINES>".into());
    } else {
        let fname = &args[1];
        let pos: u64 = args[2].parse().unwrap();
        let num_lines: usize = args[3].parse().unwrap();

        let result = read_some_lines(fname, pos, num_lines);
        match result {
            Ok(lines) => println!("{:?}", lines),
            Err(err) => err_msg(format!("Couldn't find the beginning of the line: {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::tempfile;

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
}
