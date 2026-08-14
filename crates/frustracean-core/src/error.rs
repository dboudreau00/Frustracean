use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Plain(String),

    #[error("unsupported binary format: {0}")]
    UnsupportedFormat(String),

    #[error("address {va:#x} is not mapped to any section")]
    UnmappedAddress { va: u64 },

    #[error("signature rule {id}: {reason}")]
    BadRule { id: String, reason: String },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(feature = "analysis")]
    #[error("binary parse error: {0}")]
    Parse(#[from] goblin::error::Error),

    #[cfg(feature = "analysis")]
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[cfg(feature = "analysis")]
    #[error("decode error at {ip:#x}: {reason}")]
    Decode { ip: u64, reason: String },
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub fn plain(msg: impl Into<String>) -> Self {
        Error::Plain(msg.into())
    }
}
