use objc2_foundation::NSError;

#[derive(Debug, Clone)]
pub struct VzError {
    message: String,
}

impl VzError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        VzError {
            message: message.into(),
        }
    }

    pub(crate) fn from_ns_error(err: &NSError) -> Self {
        VzError {
            message: err.localizedDescription().to_string(),
        }
    }
}

impl std::fmt::Display for VzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VzError {}

pub type Result<T> = std::result::Result<T, VzError>;
