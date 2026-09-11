use clap::Parser;
use easy_sshca::{cli, memory, protocol::ErrorDetail};
use prost::Message;
use tonic::Code;

/// How a failure is reported: process exit code plus the JSON error fields.
struct Failure {
    exit_code: i32,
    reason: String,
    request_id: String,
}

impl Failure {
    fn classify(error: &anyhow::Error) -> Self {
        if let Some(status) = error.downcast_ref::<tonic::Status>() {
            let detail = ErrorDetail::decode(status.details()).ok();
            return Self {
                exit_code: match status.code() {
                    Code::InvalidArgument | Code::AlreadyExists | Code::NotFound => 2,
                    Code::Unauthenticated => 3,
                    Code::PermissionDenied => 4,
                    Code::Unavailable
                    | Code::FailedPrecondition
                    | Code::ResourceExhausted
                    | Code::DeadlineExceeded
                    | Code::Aborted => 5,
                    _ => 1,
                },
                reason: detail
                    .as_ref()
                    .map_or("RPC_ERROR".into(), |detail| detail.reason.clone()),
                request_id: detail.map(|detail| detail.request_id).unwrap_or_default(),
            };
        }
        if let Some(local) = error.downcast_ref::<easy_sshca::error::Error>() {
            return Self {
                exit_code: match local.code {
                    Code::InvalidArgument => 2,
                    Code::Unauthenticated => 3,
                    Code::PermissionDenied => 4,
                    _ => 1,
                },
                reason: local.reason.into(),
                request_id: String::new(),
            };
        }
        if error.downcast_ref::<tonic::transport::Error>().is_some() {
            return Self {
                exit_code: 5,
                reason: "UNAVAILABLE".into(),
                request_id: String::new(),
            };
        }
        Self {
            exit_code: 2,
            reason: "INPUT_ERROR".into(),
            request_id: String::new(),
        }
    }
}

fn print_json_error(reason: &str, request_id: &str) {
    println!(
        "{}",
        serde_json::json!({
            "version": 1,
            "error": {"reason": reason, "request_id": request_id},
        })
    );
}

fn init_tracing() {
    use tracing_subscriber::prelude::*;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::filter::Targets::new()
                .with_target("easy_sshca", tracing::Level::INFO),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .json(),
        )
        .init();
}

fn run(cli: cli::Cli, server_start: bool) -> anyhow::Result<()> {
    if server_start {
        memory::protect()?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cli::run(cli))
}

fn main() {
    // Argument parsing has not happened yet, so detect JSON mode by inspection.
    let json = std::env::args_os().any(|arg| arg == "--json");
    if let Err(error) = memory::disable_dumps() {
        if json {
            print_json_error(error.reason, "");
        } else {
            eprintln!("error: {error}");
        }
        std::process::exit(1);
    }
    let cli = cli::Cli::try_parse().unwrap_or_else(|error| {
        if json && error.use_stderr() {
            print_json_error("INVALID_INPUT", "");
            std::process::exit(2);
        }
        error.exit()
    });
    let json = cli.json;
    let server_start = cli.command.is_server_start();
    init_tracing();
    if server_start {
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "Server starting");
    }
    let Err(error) = run(cli, server_start) else {
        return;
    };
    let failure = Failure::classify(&error);
    if server_start {
        tracing::error!(reason = %failure.reason, "Server failed");
    }
    if json {
        print_json_error(&failure.reason, &failure.request_id);
    } else {
        eprintln!("error: {error}");
        for cause in error.chain().skip(1) {
            eprintln!("  caused by: {cause}");
        }
    }
    std::process::exit(failure.exit_code);
}
