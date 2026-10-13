use std::fmt;

/// Why an authentication step did not give an answer.
#[derive(Debug)]
pub enum AuthError {
    /// The person cancelled.
    Cancelled,
    /// Nobody answered in time.
    Timeout,
    /// This way is not available now (no window, no device in reach). The
    /// caller may try another.
    Unavailable(String),
    /// The device or the person said no.
    Denied,
    /// Not allowed, and not by anyone's choice: an expired device, a device the
    /// vault does not know.
    Refused(String),
    /// An answer that does not verify: wrong request, wrong key, too late.
    BadDecision(&'static str),
    /// Three wrong passwords.
    TooManyTries,
    Vault(vahta_vault::Error),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Cancelled => f.write_str("cancelled"),
            AuthError::Timeout => f.write_str("no answer in time"),
            AuthError::Unavailable(why) => f.write_str(why),
            AuthError::Denied => f.write_str("refused on the device"),
            AuthError::Refused(why) => f.write_str(why),
            AuthError::BadDecision(why) => write!(f, "the device's answer does not verify ({why})"),
            AuthError::TooManyTries => f.write_str("too many wrong passwords; nothing was done"),
            AuthError::Vault(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<vahta_vault::Error> for AuthError {
    fn from(e: vahta_vault::Error) -> AuthError {
        AuthError::Vault(e)
    }
}
