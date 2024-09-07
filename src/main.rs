use std::fs::File;
use std::io::{self, BufRead, Seek, SeekFrom, BufReader};
use std::io::Read;
use std::env;
use colored::Colorize;
use log::{debug, error};


fn debug_msg(msg: String) {
    debug!("{}", msg);
}

fn err_msg(msg: String) {
    error!("{}", msg.red());
}

fn find_beginning_of_line(file: &mut File, start_pos: u64) -> std::io::Result<u64> {
    let mut buffer = [0; 1];
    let mut cur_pos = start_pos;

    loop {
        file.seek(SeekFrom::Start(cur_pos))?;

        // TODO: replace single char read with reading a chunk (for
        // performance)
        match file.read_exact(&mut buffer) {
            Ok(_) => {}, // do nothing, this just means the result is in
                         // buffer[0]
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Seek past last char"));
            },
            Err(e) => return Err(e),
        };

        if buffer[0] == b'\n' {
            // Ignore the newline if this is the first iteration because it
            // means we're standing at the end of a line and we still need to
            // find its beginning.
            if cur_pos == start_pos {
                cur_pos -= 1;
                continue
            }
            debug_msg("Found break at pos={cur_pos}".into());
            // Increment cur pos because we're currently on the newline
            // (end of the previous line). We need to be on the next char.
            cur_pos += 1;
            break;
        }
        cur_pos = cur_pos.checked_sub(1).unwrap_or(0);
        if cur_pos == 0 {
            debug_msg("Got to the beginning of the file".into());
            break;
        }
    }

    return Ok(cur_pos);
}

fn read_some_lines(file_path: &str, start_pos: u64, n: usize) -> std::io::Result<Vec<String>> {
    let mut file = File::open(file_path)?;

    let line_start = match find_beginning_of_line(&mut file, start_pos) {
        Ok(line_start) => {
            debug_msg(format!("Line starts at pos {line_start}"));
            line_start
        },
        Err(err) => {
            return Err(err)
        },
    };

    debug_msg(format!("Reading from pos={line_start}"));
    file.seek(SeekFrom::Start(line_start))?;
    let reader = BufReader::new(file);

    // Collect N lines from the current position
    let lines: Vec<String> = reader
        .lines()
        .take(n)  // Limit to N lines
        .collect::<Result<_, _>>()?;  // Collect results into a vector and handle errors

    return Ok(lines);
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    // Check if there are enough arguments
    if args.len() < 4 {
        debug_msg("usage: <FILE> <START_POS> <NUM_LINES>".into());
    } else {
        let fname =  &args[1];
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
    use tempfile::tempfile;
    use std::io::{Write, SeekFrom, Seek};

    #[test]
    fn test_find_beginning_of_line() -> std::io::Result<()> {
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

        // Test case 5: Start at EOF
        file.seek(SeekFrom::End(0))?;
        let end_pos = file.seek(SeekFrom::End(0))?;
        let start_pos = find_beginning_of_line(&mut file, end_pos);
        assert_eq!(start_pos.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);

        Ok(())
    }
}
