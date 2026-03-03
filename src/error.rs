use thiserror::Error;

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("OAuth2 error: {0}")]
    OAuth2Error(String),

    #[error("Failed to open browser: {0}")]
    BrowserError(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Invalid state parameter in OAuth callback")]
    InvalidState,

    #[error("Missing authorization code in OAuth callback")]
    MissingAuthCode,

    #[error("OpenID configuration error: {0}")]
    OidcConfigError(String),

    #[error("Token exchange failed: {0}")]
    TokenExchangeError(String),

    #[error("Invalid server URL: {0}")]
    InvalidServerUrl(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("Token store error: {0}")]
    TokenStoreError(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

pub type Result<T> = std::result::Result<T, CredentialError>;
