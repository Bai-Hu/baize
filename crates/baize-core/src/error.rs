use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("user decision required: {0}")]
    NeedUserDecision(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("storage error: {0}")]
    Storage(String, #[source] Option<rusqlite::Error>),

    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Storage(e.to_string(), Some(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_format() {
        let e = Error::Validation("bad input".to_string());
        assert_eq!(format!("{}", e), "validation error: bad input");

        let e = Error::NotFound("thing".to_string());
        assert!(format!("{}", e).contains("thing"));

        let e = Error::PermissionDenied("no access".to_string());
        assert!(format!("{}", e).contains("no access"));
    }

    #[test]
    fn error_from_rusqlite() {
        let rusqlite_err = rusqlite::Error::InvalidColumnIndex(999);
        let e: Error = rusqlite_err.into();
        match e {
            Error::Storage(msg, Some(_)) => assert!(msg.contains("999")),
            _ => panic!("expected Storage with source"),
        }
    }

    #[test]
    fn error_from_anyhow() {
        let e: Error = anyhow::anyhow!("something broke").into();
        match e {
            Error::Internal(err) => assert!(err.to_string().contains("something broke")),
            _ => panic!("expected Internal"),
        }
    }
}
