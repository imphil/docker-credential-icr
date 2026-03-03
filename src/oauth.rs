use crate::error::{CredentialError, Result};
use crate::oidc::{OidcConfiguration, fetch_oidc_config};
use crate::server::start_callback_server;
use rand::Rng;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, info};
use url::Url;

pub const CLIENT_ID: &str = "bx";
pub const CLIENT_SECRET: &str = "bx";

#[derive(Debug, Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
}

/// Perform complete OAuth2 authorization flow and return token response
pub async fn perform_oauth_flow() -> Result<TokenResponse> {
    info!("Starting OAuth2 authorization flow");

    // Step 1: Fetch OIDC configuration
    let config = fetch_oidc_config().await?;

    // Step 2: Generate random state for CSRF protection
    let state = generate_state();
    debug!("Generated state: {}", state);

    // Step 3: Start callback server. The server finds its own port and returns it.
    let (bound_port, callback_rx) = start_callback_server(state.clone()).await?;
    let redirect_uri = format!("http://localhost:{}/", bound_port);
    info!("Using redirect URI: {}", redirect_uri);

    // Step 4: Build authorization URL with actual bound port
    let auth_url = build_authorization_url(&config, &redirect_uri, &state)?;
    info!("Opening browser for authentication...");
    debug!("Authorization URL: {}", auth_url);

    // Step 5: Open browser after server is ready
    open_browser(&auth_url)?;

    // Step 6: Wait for authorization code from callback
    let callback_result = callback_rx
        .await
        .map_err(|_| CredentialError::ServerError("Callback channel closed".to_string()))??;
    info!("Received authorization code");

    // Step 7: Exchange authorization code for tokens
    let token_response =
        exchange_code_for_token(&config, &callback_result.code, &redirect_uri).await?;

    info!("Successfully obtained access token");
    Ok(token_response)
}

/// Build the OAuth2 authorization URL
fn build_authorization_url(
    config: &OidcConfiguration,
    redirect_uri: &str,
    state: &str,
) -> Result<String> {
    let mut url = Url::parse(&config.authorization_endpoint).map_err(|e| {
        CredentialError::OAuth2Error(format!("Invalid authorization endpoint: {}", e))
    })?;

    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("state", state);

    Ok(url.to_string())
}

/// Generate a random state parameter for CSRF protection
fn generate_state() -> String {
    rand::thread_rng().gen_ascii_chars().take(32).collect()
}

/// Open the authorization URL in the default browser
fn open_browser(url: &str) -> Result<()> {
    webbrowser::open(url)
        .map_err(|e| CredentialError::BrowserError(format!("Failed to open browser: {}", e)))?;
    Ok(())
}

/// Exchange authorization code for tokens
async fn exchange_code_for_token(
    config: &OidcConfiguration,
    code: &str,
    redirect_uri: &str,
) -> Result<TokenResponse> {
    info!("Exchanging authorization code for access token");
    debug!("Token endpoint: {}", config.token_endpoint);

    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("code", code);
    params.insert("grant_type", "authorization_code");
    params.insert("redirect_uri", redirect_uri);
    params.insert("client_id", CLIENT_ID);
    params.insert("client_secret", CLIENT_SECRET);

    let response = client
        .post(&config.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| CredentialError::TokenExchangeError(format!("Request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(CredentialError::TokenExchangeError(format!(
            "HTTP {}: {}",
            status, error_text
        )));
    }

    let token_response: TokenResponse = response.json().await.map_err(|e| {
        CredentialError::TokenExchangeError(format!("Failed to parse response: {}", e))
    })?;

    debug!("Successfully exchanged code for token");
    if token_response.refresh_token.is_some() {
        debug!("Received refresh token");
    }
    Ok(token_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_state() {
        let state1 = generate_state();
        let state2 = generate_state();

        assert_eq!(state1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(state1, state2); // Should be random
    }

    #[test]
    fn test_build_authorization_url() {
        let config = OidcConfiguration {
            authorization_endpoint: "https://example.com/authorize".to_string(),
            token_endpoint: "https://example.com/token".to_string(),
            issuer: "https://example.com".to_string(),
        };

        let url = build_authorization_url(&config, "http://localhost:8080/", "test_state").unwrap();

        assert!(url.contains("client_id=bx"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2F"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("state=test_state"));
    }
}

// Made with Bob
