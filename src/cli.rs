use clap::{ArgAction, Parser};

#[derive(Parser, Debug, Clone)]
#[command(name = "Read vault audit log", version = "1.0")]
pub struct CliArgs {
    /// Limit to a request with a given id
    #[arg(long = "id", value_name = "Request-Id", help = "filter by request id")]
    pub id: Option<String>,

    /// Limit to requests with a given client id
    #[arg(
        long = "actor",
        value_name = "user_id",
        conflicts_with = "summary",
        help = "id of the actor (e.g. username or role name)"
    )]
    pub actor: Option<String>,

    /// Limit to requests with a given client id
    #[arg(
        long = "client-id",
        value_name = "Client-Id",
        help = "filter by client id"
    )]
    pub client_id: Option<String>,

    /// Specify number of workers
    #[arg(short = 'T', long = "threads")]
    pub threads: Option<usize>,

    /// Include requests too
    #[arg(short = 'R', long = "include-requests", action = ArgAction::SetTrue)]
    pub include_requests: bool,

    /// Show the date of the first and last log entries
    #[arg(long = "show-date-range", action = ArgAction::SetTrue)]
    pub show_date_range: bool,

    /// Show only the summary
    #[arg(long = "summary", action = ArgAction::SetTrue)]
    pub summary: bool,

    /// Specify beginning time (e.g. 2024-08-16T18:10:16Z)
    #[arg(short = 's', long = "start-time")]
    pub start_time: Option<String>,

    /// Specify end time (e.g. 2024-08-16T18:10:16Z)
    #[arg(short = 'e', long = "end-time")]
    pub end_time: Option<String>,

    /// Print unabridged entries
    #[arg(short = 'r', long = "raw", action = ArgAction::SetTrue, conflicts_with = "summary")]
    pub raw: bool,

    /// Vault path
    #[arg(
        short = 'p',
        long = "path",
        conflicts_with = "summary",
        value_name = "VAULT_PATH"
    )]
    pub path: Option<String>,

    /// Log file
    #[arg(short = 'f', long = "file", value_name = "LOG_FILE", required = true)]
    pub log_file: String,
}

