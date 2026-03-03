use crate::error::{CredentialError, Result};
use crate::oauth::perform_oauth_flow;
use crate::token_store::{StoredToken, TokenStore};
use serde::Serialize;
use std::io::{self, Read, Write};
use tracing::{debug, info, warn};

/// Docker credential helper response format
#[derive(Debug, Serialize)]
pub struct Credentials {
    #[serde(rename = "ServerURL")]
    pub server_url: String,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Secret")]
    pub secret: String,
}

/// Handle the 'get' command - retrieve credentials for a server
pub async fn handle_get() -> Result<()> {
    info!("Handling 'get' command");

    // Read server URL from stdin
    let server_url = read_server_url_from_stdin()?;
    debug!("Server URL: {}", server_url);

    // Validate that this is an ICR registry
    if !is_icr_registry(&server_url) {
        return Err(CredentialError::InvalidServerUrl(format!(
            "Not an IBM Cloud Container Registry: {}",
            server_url
        )));
    }

    // Create token store for this registry
    let token_store = TokenStore::new(server_url.clone());

    // Try to get a valid token from the store (will refresh if needed)
    let access_token = match token_store.get_valid_token().await? {
        Some(token) => {
            info!("Using cached/refreshed token for {}", server_url);
            token
        }
        None => {
            info!(
                "No valid token found, performing OAuth2 authentication for {}",
                server_url
            );

            // Perform OAuth2 flow to get new tokens
            let token_response = perform_oauth_flow().await?;

            // Store the tokens for future use
            let stored_token = StoredToken::new(
                token_response.access_token.clone(),
                token_response.refresh_token,
                token_response.expires_in.unwrap_or(3600),
            );

            if let Err(e) = token_store.store_token(&stored_token) {
                warn!("Failed to store token: {}", e);
                // Continue anyway, we have the token
            }

            token_response.access_token
        }
    };

    // Create credentials response
    let credentials = Credentials {
        server_url,
        username: "iambearer".to_string(),
        secret: access_token,
    };

    // Write credentials to stdout as JSON
    write_credentials_to_stdout(&credentials)?;

    info!("Successfully provided credentials");
    Ok(())
}

/// Read server URL from stdin
fn read_server_url_from_stdin() -> Result<String> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let server_url = buffer.trim().to_string();

    if server_url.is_empty() {
        return Err(CredentialError::InvalidServerUrl(
            "Empty server URL".to_string(),
        ));
    }

    Ok(server_url)
}

/// Write credentials to stdout as JSON
fn write_credentials_to_stdout(credentials: &Credentials) -> Result<()> {
    let json = serde_json::to_string(credentials)?;
    io::stdout().write_all(json.as_bytes())?;
    io::stdout().flush()?;
    Ok(())
}

/// Check if the server URL is an IBM Cloud Container Registry
fn is_icr_registry(server_url: &str) -> bool {
    let normalized = server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // Check if it ends with .icr.io or is exactly icr.io
    normalized.ends_with(".icr.io") || normalized == "icr.io" || normalized.starts_with("icr.io:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_icr_registry() {
        assert!(is_icr_registry("icr.io"));
        assert!(is_icr_registry("us.icr.io"));
        assert!(is_icr_registry("https://icr.io"));
        assert!(is_icr_registry("de.icr.io"));
        assert!(is_icr_registry("eu-central.icr.io"));

        assert!(!is_icr_registry("docker.io"));
        assert!(!is_icr_registry("gcr.io"));
        assert!(!is_icr_registry("example.com"));
    }

    #[test]
    fn test_credentials_serialization() {
        let creds = Credentials {
            server_url: "icr.io".to_string(),
            username: "iambearer".to_string(),
            secret: "test_token".to_string(),
        };

        let json = serde_json::to_string(&creds).unwrap();
        // Verify correct field names in JSON (ServerURL not ServerUrl)
        assert!(
            json.contains("\"ServerURL\""),
            "JSON should contain ServerURL field"
        );
        assert!(
            json.contains("\"Username\""),
            "JSON should contain Username field"
        );
        assert!(
            json.contains("\"Secret\""),
            "JSON should contain Secret field"
        );
        assert!(
            json.contains("\"iambearer\""),
            "JSON should contain iambearer value"
        );
        assert!(
            json.contains("\"test_token\""),
            "JSON should contain test_token value"
        );
    }
}
