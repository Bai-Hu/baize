use thiserror::Error;

/// 中间件客户端错误
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("connection error: {0}")]
    Connection(String),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("user decision required: {0}")]
    UserDecision(String),

    #[error("server error: {0}")]
    Server(String),

    #[error("{0}")]
    Other(String),
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;
