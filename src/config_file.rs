use serde::{Serialize, de::DeserializeOwned};

pub async fn read_config<T: DeserializeOwned>(path: &str) -> Option<T> {
    if !tokio::fs::try_exists(path).await.unwrap_or(false) {
        return None;
    }

    let content = tokio::fs::read(path).await.ok()?;

    if path.ends_with(".yml") || path.ends_with(".yaml") {
        if let Ok(data) = serde_yml::from_slice(&content) {
            return Some(data);
        }
    }

    serde_json::from_slice(&content).ok()
}

pub async fn write_config<T: Serialize>(path: &str, data: &T) -> Result<(), std::io::Error> {
    let content = if path.ends_with(".yml") || path.ends_with(".yaml") {
        serde_yml::to_string(data).unwrap()
    } else {
        serde_json::to_string(data).unwrap()
    };

    tokio::fs::write(path, content).await
}
