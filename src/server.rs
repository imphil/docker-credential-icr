use crate::error::{CredentialError, Result};
use axum::{
    Router,
    extract::Query,
    response::{Html, IntoResponse},
    routing::get,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize)]
pub struct AuthCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub struct CallbackResult {
    pub code: String,
    pub state: String,
}

/// Start a local HTTP server to handle OAuth2 callback and return the bound port
/// Automatically finds an available port and returns it along with a receiver for the callback result
pub async fn start_callback_server(
    expected_state: String,
) -> Result<(u16, tokio::sync::oneshot::Receiver<Result<CallbackResult>>)> {
    info!("Starting OAuth callback server");

    let (tx, rx) = oneshot::channel::<Result<CallbackResult>>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let expected_state = Arc::new(expected_state);

    let app = Router::new().route(
        "/",
        get({
            let tx = Arc::clone(&tx);
            let expected_state = Arc::clone(&expected_state);
            move |query: Query<AuthCallback>| handle_callback(query, tx, expected_state)
        }),
    );

    // Port 0 lets the operating system find an available port.
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));

    debug!("Binding server to {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| CredentialError::ServerError(format!("Failed to bind: {}", e)))?;

    // Get the actual bound port
    let bound_port = listener
        .local_addr()
        .map_err(|e| CredentialError::ServerError(format!("Failed to get local address: {}", e)))?
        .port();

    info!("Server listening on http://127.0.0.1:{}", bound_port);

    // Spawn server in background
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            warn!("Server error: {}", e);
        }
    });

    Ok((bound_port, rx))
}

async fn handle_callback(
    Query(callback): Query<AuthCallback>,
    tx: Arc<Mutex<Option<oneshot::Sender<Result<CallbackResult>>>>>,
    expected_state: Arc<String>,
) -> impl IntoResponse {
    debug!("Received OAuth callback");

    let result = process_callback(callback, &expected_state);

    // Send result through channel
    if let Some(sender) = tx.lock().await.take() {
        let _ = sender.send(result);
    }

    // Return HTML response to browser (IBM Carbon-inspired design)
    Html(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>IBM Cloud Authentication</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: 'IBM Plex Sans', 'Helvetica Neue', Arial, sans-serif;
                    background-color: #f4f4f4;
                    color: #161616;
                    line-height: 1.5;
                    display: flex;
                    min-height: 100vh;
                    align-items: center;
                    justify-content: center;
                    padding: 1rem;
                }
                .container {
                    background: #ffffff;
                    max-width: 640px;
                    width: 100%;
                    padding: 3rem 2rem;
                    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
                }
                .icon-container {
                    width: 48px;
                    height: 48px;
                    background-color: #24a148;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-bottom: 1.5rem;
                }
                .icon-container svg {
                    width: 24px;
                    height: 24px;
                    fill: #ffffff;
                }
                h1 {
                    font-size: 2rem;
                    font-weight: 400;
                    color: #161616;
                    margin-bottom: 1rem;
                    letter-spacing: 0;
                }
                p {
                    font-size: 0.875rem;
                    color: #525252;
                    margin-bottom: 0.75rem;
                    line-height: 1.43;
                }
                .divider {
                    height: 1px;
                    background-color: #e0e0e0;
                    margin: 2rem 0 1.5rem 0;
                }
                .footer {
                    font-size: 0.75rem;
                    color: #8d8d8d;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon-container">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
                        <path d="M13 24l-9-9 1.414-1.414L13 21.171 26.586 7.586 28 9 13 24z"/>
                    </svg>
                </div>
                <h1>Authentication successful</h1>
                <p>You have successfully authenticated with IBM Cloud Container Registry.</p>
                <p>You can now close this window.</p>
                <div class="divider"></div>
                <p class="footer">IBM Cloud Container Registry credential helper</p>
            </div>
        </body>
        </html>
        "#,
    )
}

fn process_callback(callback: AuthCallback, expected_state: &str) -> Result<CallbackResult> {
    // Check for OAuth errors
    if let Some(error) = callback.error {
        let description = callback
            .error_description
            .unwrap_or_else(|| "No description".to_string());
        return Err(CredentialError::OAuth2Error(format!(
            "{}: {}",
            error, description
        )));
    }

    // Validate state parameter
    let state = callback.state.ok_or(CredentialError::InvalidState)?;

    if state != expected_state {
        warn!(
            "State mismatch: expected '{}', got '{}'",
            expected_state, state
        );
        return Err(CredentialError::InvalidState);
    }

    // Extract authorization code
    let code = callback.code.ok_or(CredentialError::MissingAuthCode)?;

    debug!("Successfully processed OAuth callback");

    Ok(CallbackResult { code, state })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_callback_success() {
        let callback = AuthCallback {
            code: Some("test_code".to_string()),
            state: Some("test_state".to_string()),
            error: None,
            error_description: None,
        };

        let result = process_callback(callback, "test_state");
        assert!(result.is_ok());

        let callback_result = result.unwrap();
        assert_eq!(callback_result.code, "test_code");
        assert_eq!(callback_result.state, "test_state");
    }

    #[test]
    fn test_process_callback_invalid_state() {
        let callback = AuthCallback {
            code: Some("test_code".to_string()),
            state: Some("wrong_state".to_string()),
            error: None,
            error_description: None,
        };

        let result = process_callback(callback, "expected_state");
        assert!(result.is_err());
    }

    #[test]
    fn test_process_callback_missing_code() {
        let callback = AuthCallback {
            code: None,
            state: Some("test_state".to_string()),
            error: None,
            error_description: None,
        };

        let result = process_callback(callback, "test_state");
        assert!(result.is_err());
    }

    #[test]
    fn test_process_callback_oauth_error() {
        let callback = AuthCallback {
            code: None,
            state: None,
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
        };

        let result = process_callback(callback, "test_state");
        assert!(result.is_err());
    }
}

// Made with Bob
