use super::server_database::{DatabaseError, ServerDatabase};
use super::web_server::WebServer;
use http_app::{HttpServer, HttpServerSettings, HttpTls};
use tokio::task::JoinHandle;

pub struct StartWebServerConfig {
    pub database_path: String,
}

impl StartWebServerConfig {
    pub async fn start(self) -> Result<JoinHandle<()>, DatabaseError> {
        let database = ServerDatabase::open(self.database_path).await?;
        let config = database.load_config().await?;

        let listen_addr = config.listen_addr;
        let web = WebServer::new(database);
        let server = HttpServer::new(
            web,
            HttpServerSettings {
                tls: Some(HttpTls::WithBytes {
                    cert: config.tls_cert,
                    key: config.tls_key,
                }),
                ..Default::default()
            },
        );

        server.start(listen_addr).await?;
        Ok(tokio::spawn(std::future::pending()))
    }
}
