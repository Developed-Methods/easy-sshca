use clap::Parser;
fn main() {
    if let Err(error) = easy_sshca::memory::disable_dumps() {
        if std::env::args_os().any(|arg| arg == "--json") {
            println!(
                "{}",
                serde_json::json!({"version":1,"error":{"reason":error.reason,"request_id":""}})
            );
        } else {
            eprintln!("error: {error}");
        }
        std::process::exit(1);
    }
    let cli = match easy_sshca::cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if error.use_stderr() && std::env::args_os().any(|arg| arg == "--json") {
                println!(
                    "{}",
                    serde_json::json!({"version":1,"error":{"reason":"INVALID_INPUT","request_id":""}})
                );
                std::process::exit(2);
            }
            error.exit();
        }
    };
    let json = cli.json;
    let server_start = matches!(
        &cli.command,
        easy_sshca::cli::Action::Server {
            command: easy_sshca::cli::Server::Start { .. }
        }
    );
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::new("easy_sshca=info"))
        .init();
    if server_start {
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "Server starting");
    }
    let result = if server_start {
        easy_sshca::memory::protect()
    } else {
        Ok(())
    }
    .map_err(anyhow::Error::from)
    .and_then(|()| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
    })
    .and_then(|runtime| runtime.block_on(easy_sshca::cli::run(cli)));
    if let Err(e) = result {
        let (code, reason, request) = if let Some(s) = e.downcast_ref::<tonic::Status>() {
            use prost::Message;
            let detail = easy_sshca::protocol::ErrorDetail::decode(s.details()).ok();
            (
                match s.code() {
                    tonic::Code::InvalidArgument
                    | tonic::Code::AlreadyExists
                    | tonic::Code::NotFound => 2,
                    tonic::Code::Unauthenticated => 3,
                    tonic::Code::PermissionDenied => 4,
                    tonic::Code::Unavailable
                    | tonic::Code::FailedPrecondition
                    | tonic::Code::ResourceExhausted
                    | tonic::Code::DeadlineExceeded
                    | tonic::Code::Aborted => 5,
                    _ => 1,
                },
                detail
                    .as_ref()
                    .map(|x| x.reason.clone())
                    .unwrap_or_else(|| "RPC_ERROR".into()),
                detail.map(|x| x.request_id).unwrap_or_default(),
            )
        } else if let Some(d) = e.downcast_ref::<easy_sshca::error::Error>() {
            (
                match d.code {
                    tonic::Code::InvalidArgument => 2,
                    tonic::Code::Unauthenticated => 3,
                    tonic::Code::PermissionDenied => 4,
                    _ => 1,
                },
                d.reason.to_string(),
                String::new(),
            )
        } else if e.downcast_ref::<tonic::transport::Error>().is_some() {
            (5, "UNAVAILABLE".into(), String::new())
        } else {
            (2, "INPUT_ERROR".into(), String::new())
        };
        if server_start {
            tracing::error!(reason = %reason, "Server failed");
        }
        if json {
            println!(
                "{}",
                serde_json::json!({"version":1,"error":{"reason":reason,"request_id":request}})
            );
        } else {
            eprintln!("error: {e}");
            for cause in e.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
        }
        std::process::exit(code);
    }
}
