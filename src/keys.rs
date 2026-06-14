// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::discovery::discovery_decoding_key;
use crate::{AuthzooError, RoleConfig};
use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey};
use tracing::info;

pub(crate) fn resolving_decoding_key(
    role: &RoleConfig,
    token: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, AuthzooError> {
    match role.validation_key.as_deref() {
        Some(validation_key) => decoding_key_for_algorithm(validation_key, algorithm),
        None => {
            info!(
                role = %role.name,
                issuer = %role.issuer,
                "role.validation-key not configured; attempting issuer-based validation key discovery"
            );
            discovery_decoding_key(role, token, algorithm)
        }
    }
}

fn decoding_key_for_algorithm(
    validation_key: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, AuthzooError> {
    let decoding_key = match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if looks_like_pem(validation_key) {
                return Err(anyhow::anyhow!(
                    "refusing to validate HMAC token with PEM validation key; issuer token algorithm was '{algorithm:?}'"
                )
                .into());
            }
            DecodingKey::from_secret(validation_key.as_bytes())
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(validation_key.as_bytes())
            .context("failed to parse RSA validation key")?,
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(validation_key.as_bytes())
            .context("failed to parse EC validation key")?,
        Algorithm::EdDSA => DecodingKey::from_ed_pem(validation_key.as_bytes())
            .context("failed to parse EdDSA validation key")?,
    };
    Ok(decoding_key)
}

fn looks_like_pem(value: &str) -> bool {
    value.trim_start().starts_with("-----BEGIN ")
}
