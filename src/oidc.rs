use crate::error::{CredentialError, Result};
use serde::Deserialize;
use tracing::{debug, info};

const OIDC_CONFIG_URL: &str = "https://iam.cloud.ibm.com/identity/.well-known/openid-configuration";

#[derive(Debug, Deserialize, Clone)]
pub struct OidcConfiguration {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub issuer: String,
}

/// Fetch OpenID Connect configuration from IBM Cloud IAM
pub async fn fetch_oidc_config() -> Result<OidcConfiguration> {
    info!("Fetching OpenID configuration from IBM Cloud IAM");
    debug!("OIDC config URL: {}", OIDC_CONFIG_URL);

    let client = reqwest::Client::new();
    let response =
        client.get(OIDC_CONFIG_URL).send().await.map_err(|e| {
            CredentialError::OidcConfigError(format!("Failed to fetch config: {}", e))
        })?;

    if !response.status().is_success() {
        return Err(CredentialError::OidcConfigError(format!(
            "HTTP error: {}",
            response.status()
        )));
    }

    let config: OidcConfiguration = response
        .json()
        .await
        .map_err(|e| CredentialError::OidcConfigError(format!("Failed to parse config: {}", e)))?;

    info!("Successfully fetched OIDC configuration");
    debug!("Authorization endpoint: {}", config.authorization_endpoint);
    debug!("Token endpoint: {}", config.token_endpoint);

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_oidc_config() {
        // This is an integration test that requires network access
        // In a real scenario, you might want to mock this
        let result = fetch_oidc_config().await;
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(!config.authorization_endpoint.is_empty());
        assert!(!config.token_endpoint.is_empty());
        assert!(config.authorization_endpoint.contains("identity"));
        assert!(config.token_endpoint.contains("token"));
    }
}

// Made with Bob
