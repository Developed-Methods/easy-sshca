pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod http;
pub mod memory;
pub mod server;
pub mod signing;
pub mod storage;
pub mod protocol {
    tonic::include_proto!("easysshca.v1");
    impl std::fmt::Debug for Command {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Command([redacted])")
        }
    }
    impl std::fmt::Debug for Reply {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Reply([redacted])")
        }
    }
}

mod tls;
