use std::{fmt::{Debug, Display}, fs::Permissions, os::unix::fs::PermissionsExt, process};

use chrono::Utc;
use clap::Parser;
use easy_sshca::{start_web_server::StartWebServerConfig, web_client::{ErrorResponse, SignRequest, WebAuth, WebClient, WebClientError}};
use easy_sshca::{config::{assert_validname, SignDuration}, ssh_keygen, totp::TotpSecret};
use http_app::StatusCode;
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,

    #[arg(short('c'), long)]
    server_cert_path: Option<String>,
    #[arg(short('a'), long)]
    server_addr: Option<String>,

    #[arg(short('k'), long)]
    api_key: Option<String>,

    #[arg(short('n'), long)]
    client_name: Option<String>,
}

#[derive(Debug, Parser)]
enum Command {
    StartServer {
        config_path: Option<String>
    },
    GenKey {
        path: Option<String>,
        #[arg(short('s'), long)]
        stdout: bool,
        #[arg(short('C'), long)]
        comment: Option<String>,
    },
    PubKey { target: String },
    Sign {
        target: String,
        user: Option<String>,
        #[arg(short('f'), long)]
        file: Option<String>,
        #[arg(short('t'), long)]
        totp: Option<String>,
        #[arg(short('d'), long)]
        duration: Option<SignDuration>,
    },
    PrepareTotp {
        output: Option<String>,
        #[arg(short('i'), long)]
        issuer: Option<String>,
    },
}

impl Args {
    pub async fn cert_path(&self, home: &str) -> String {
        let path = if let Some(path) = &self.server_cert_path {
            path.to_string()
        } else if let Ok(path) = dotenv::var("SSH_CA_CERT_PATH") {
            path
        } else if let Ok(true) = tokio::fs::try_exists("easysshca-api.crt").await {
            "easysshca-api.crt".to_string()
        } else if home == "./" {
            format!("{}/easysshca-api.crt", home)
        } else {
            format!("{}/.easysshca/api.crt", home)
        };

        if !path.ends_with(".crt") {
            let with_crt = format!("{}.crt", path.trim_end_matches(".key"));
            if let Ok(true) = tokio::fs::try_exists(&with_crt).await {
                return with_crt;
            }
        }

        path
    }

    pub async fn api_key(&self, home: &str) -> Option<String> {
        let home_path = if home == "./" {
            format!("{}/easysshca-apikey.txt", home)
        } else {
            format!("{}/.easysshca/apikey", home)
        };

        if let Some(key) = &self.api_key {
            Some(value_or_file(key).await.crit("failed to read path for api_key option"))
        } else if let Ok(key) = dotenv::var("API_KEY") {
            Some(value_or_file(&key).await.crit("failed to read path for API_KEY envar"))
        } else if let Ok(true) = tokio::fs::try_exists(&home_path).await {
            Some(tokio::fs::read_to_string(home_path).await.crit("failed to read api key from p home path"))
        } else {
            None
        }
    }

    pub async fn client_name(&self) -> Option<String> {
        if self.client_name.is_some() {
            self.client_name.clone()
        } else if let Ok(client_name) = dotenv::var("SSH_CA_CLIENT_NAME") {
            Some(client_name)
        } else if let Ok(client_name) = dotenv::var("HOST") {
            Some(client_name)
        } else {
            tokio::fs::read_to_string("/etc/hostname").await.ok()
        }
    }

    pub fn api_addr(&self) -> Option<String> {
        if self.server_addr.is_some() {
            self.server_addr.clone()
        } else {
            dotenv::var("SSH_CA_API_ADDR").ok()
        }
    }
}

#[tokio::main]
async fn main() {
    let home = dotenv::var("HOME")
        .unwrap_or_else(|_| "./".to_string());

    let args = Args::parse();
    let cert_path = args.cert_path(&home).await;
    let api_addr = args.api_addr();

    match &args.command {
        Command::StartServer { config_path } => {
            tracing_subscriber::fmt().init();

            let config_path = match config_path {
                Some(v) => Some(v.clone()),
                None => dotenv::var("CONFIG_PATH").ok(),
            }.crit("no config path set");

            let handle = StartWebServerConfig {
                config_path,
            }.start().await.crit("failed to start server");

            tracing::info!("server running");
            let _ = handle.await;
        }
        Command::GenKey { path, comment, stdout  } => {
            let cmt = comment.as_ref().map(|v| v.as_str()).unwrap_or("");
            let private = ssh_keygen::generate_ed25519(cmt).await.crit("failed to generate_ed25519");
            let privkey = private.to_openssh(ssh_key::LineEnding::LF).crit("failed to serialize private key");

            if *stdout {
                print!("{}", privkey.as_str());
                return;
            }

            let path = path.clone().unwrap_or_else(|| format!("{}/.ssh/id_ed25519", home));
            match tokio::fs::try_exists(&path).await {
                Ok(false) => {}
                Ok(true) => crit(format!("cannot override existing key at: {}", path)),
                Err(error) => crit(format!("failed to check if key already exists: {:?}", error)),
            };

            let pubkey = private.public_key().to_openssh().crit("failed to serialize public key");

            tokio::fs::write(format!("{}.pub", path), pubkey).await.crit("failed to write public key");
            tokio::fs::write(&path, privkey).await.crit("failed to write private key");
            tokio::fs::set_permissions(&path, Permissions::from_mode(0o600)).await.crit("failed to file permissions");

            eprintln!("Key written to: {}", path);
            return;
        }
        Command::PubKey { target } => {
            if assert_validname(target).is_err() {
                crit(format!("invalid target: {:?}", target));
            }

            let host = api_addr.crit("missing api address for server");
            let cert = read_cert(&cert_path).await;
            let client = WebClient::new(&cert, host).crit("failed to setup web client");

            let result = client.pubkey(target).await.crit("failed to get pub-key");
            println!("{}", result);
        }
        Command::Sign { target, user, file, totp, duration } => {
            if assert_validname(target).is_err() {
                crit(format!("invalid target: {:?}", target));
            }

            let user = user.clone()
                .unwrap_or_else(|| dotenv::var("USER").crit("missing $USER"));

            if assert_validname(&user).is_err() {
                crit(format!("invalid user: {:?}", user));
            }

            let host = api_addr.crit("missing api address for server");
            let cert = read_cert(&cert_path).await;
            let mut client = WebClient::new(&cert, host).crit("failed to setup web client");

            client.set_auth(WebAuth {
                api_key: args.api_key(&home).await.crit("missing api_key"),
                client_name: args.client_name().await.crit("missing client_name"),
            });

            let file = if let Some(file) = file {
                if !file.ends_with(".pub") {
                    format!("{}.pub", file)
                } else {
                    file.to_string()
                }
            } else {
                let mut dir = tokio::fs::read_dir(format!("{}/.ssh", home)).await.crit("failed to read .ssh dir");

                'find: {
                    while let Ok(Some(folder)) = dir.next_entry().await {
                        let name = folder.file_name();
                        let Some(filename) = name.to_str() else { continue };
                        if filename.ends_with(".pub") && filename.contains("ed25519") {
                            break 'find format!("{}/.ssh/{}", home, filename);
                        }
                    }

                    crit("Could not find suitable ssh key to sign");
                }
            };

            let pubkey = tokio::fs::read_to_string(&file).await.crit("failed to read pubkey from disk");

            let cert_res = client.sign(SignRequest {
                target,
                user: &user,
                totp: totp.as_ref().map(|v| v.as_str()),
                pubkey: &pubkey,
                duration: duration.unwrap_or_default(),
            }).await;

            let cert = match cert_res {
                Ok(v) => v,
                Err(WebClientError::ResponseError(ErrorResponse { status: StatusCode::UNAUTHORIZED, response }))
                    if response == "totp required\n" => {

                    println!("TOTP Code required:");
                    let mut reader = BufReader::new(tokio::io::stdin()).lines();
                    let value = reader.next_line().await.crit("failed to read next line").crit("closed before totp input");

                    client.sign(SignRequest {
                        target,
                        user: &user,
                        totp: Some(value.trim()),
                        pubkey: &pubkey,
                        duration: duration.unwrap_or_default(),
                    }).await.crit("sign failed")
                }
                Err(error) => crit(format!("failed to sign cert: {:?}", error)),
            };

            let cert_path = format!("{}-cert.pub", file.trim_end_matches(".pub"));
            tokio::fs::write(&cert_path, cert.cert).await.crit("failed to write data");
            eprintln!("wrote cert to {:?}", cert_path);
            if let Some(expires_at) = cert.expires_at {
                eprint!("Expires at: {} ", expires_at);
                let seconds_left = expires_at.timestamp() - Utc::now().timestamp();
                if seconds_left < 60 {
                    eprintln!("(in {} seconds)", seconds_left);
                }
                else if seconds_left < 3600 {
                    eprintln!("(in {} minutes)", seconds_left / 60);
                } else if seconds_left < 86400 {
                    eprintln!("(in {} hours)", seconds_left / 3600);
                } else {
                    eprintln!("(in {} days)", seconds_left / 86400);
                }
            }
        }
        Command::PrepareTotp { issuer, output } => {
            let issuer = issuer.as_ref().map(|v| v.as_str()).unwrap_or("easy-ssh-ca");

            let mut rand = Hc128Rng::from_os_rng();
            let mut bytes = vec![0u8; 32];
            rand.fill_bytes(&mut bytes);

            let totp_secret = TotpSecret::new(issuer.to_string(), bytes);
            qr2term::print_qr(totp_secret.to_string()).crit("failed to draw qr code");

            let mut reader = BufReader::new(tokio::io::stdin()).lines();
            let mut count = 0;

            loop {
                print!("Confirm TOTP Code: ");

                let Some(value) = reader.next_line().await.crit("failed to read next line") else { return };

                let code = totp_secret.get_code();
                if value.trim() == code {
                    println!("Success");
                    break;
                }

                count += 1;
                if count > 5 {
                    qr2term::print_qr(totp_secret.to_string()).crit("failed to draw qr code");
                    count = 0;
                }
            }

            if let Some(output) = output {
                tokio::fs::write(&output, totp_secret.to_string()).await.crit("failed to write totp secret to file");
                println!("wrote secret to: {}", output);
            } else {
                println!("secret:\n{}", totp_secret);
            }
        }
    }
}

async fn value_or_file(s: &str) -> Result<String, std::io::Error> {
    let s = s.trim();
    if let Some(path) = s.strip_prefix("file:") {
        return tokio::fs::read_to_string(path.trim()).await;
    }
    Ok(s.to_string())
}

async fn read_cert(path: &str) -> Vec<u8> {
    match tokio::fs::read(path).await {
        Ok(v) => v,
        Err(error) => crit(format!("Failed to read: {}\nerror: {:?}", path, error)),
    }
}

pub trait FailHelper {
    type T;

    fn crit(self, msg: &str) -> Self::T;
}

impl<S> FailHelper for Option<S> {
    type T = S;

    fn crit(self, msg: &str) -> Self::T {
        match self {
            Some(v) => v,
            None => {
                eprintln!("------FAILURE------\n{}", msg);
                process::exit(1);
            }
        }
    }
}

impl<S, E: Debug> FailHelper for Result<S, E> {
    type T = S;

    fn crit(self, msg: &str) -> Self::T {
        match self {
            Ok(v) => v,
            Err(error) => {
                eprintln!("------FAILURE------\n{}\nError: {:?}", msg, error);
                process::exit(1);
            }
        }
    }
}

fn crit<M: Display>(msg: M) -> ! {
    eprintln!("------FAILURE------\n{}", msg);
    process::exit(1);
}

