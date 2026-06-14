// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::keys::resolving_decoding_key;
use crate::{AuthzooError, Config, RoleConfig, ValidatedClaims};
use anyhow::Context;
use jsonwebtoken::{Validation, decode, decode_header};
use std::collections::{BTreeMap, HashSet};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct TokenValidator {
    roles: BTreeMap<String, RoleConfig>,
}

impl TokenValidator {
    pub fn new(roles: Vec<RoleConfig>) -> Result<Self, AuthzooError> {
        let mut names = HashSet::new();
        let mut roles_by_name = BTreeMap::new();

        for role in roles {
            role.validate()?;
            if !names.insert(role.name.clone()) {
                return Err(AuthzooError::DuplicateRole(role.name));
            }
            roles_by_name.insert(role.name.clone(), role);
        }

        Ok(Self {
            roles: roles_by_name,
        })
    }

    pub fn roles(&self) -> &BTreeMap<String, RoleConfig> {
        &self.roles
    }

    pub fn ensure_roles_exist<'a, I>(&self, role_names: I) -> Result<(), AuthzooError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        for role_name in role_names {
            if !self.roles.contains_key(role_name) {
                return Err(AuthzooError::UnknownRole(role_name.to_string()));
            }
        }
        Ok(())
    }

    pub fn validate(&self, token: &str) -> Vec<String> {
        self.roles
            .iter()
            .filter_map(|(name, role)| match validate_token_for_role(role, token) {
                Ok(_) => Some(name.clone()),
                Err(error) => {
                    debug!(
                        role = %name,
                        error = %error,
                        "token did not match role"
                    );
                    None
                }
            })
            .collect()
    }
}

impl TryFrom<Config> for TokenValidator {
    type Error = AuthzooError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        Self::new(config.roles)
    }
}

fn validate_token_for_role(
    role: &RoleConfig,
    token: &str,
) -> Result<ValidatedClaims, AuthzooError> {
    let algorithm = decode_header(token)
        .with_context(|| format!("failed to decode token header for role '{}'", role.name))?
        .alg;
    if !role.allows_algorithm(algorithm) {
        return Err(AuthzooError::AlgorithmNotAllowed {
            role: role.name.clone(),
            algorithm,
        });
    }

    debug!(
        role = %role.name,
        issuer = %role.issuer,
        audience = %role.audience,
        algorithm = ?algorithm,
        "validating source token for role assumption"
    );

    let decoding_key = resolving_decoding_key(role, token, algorithm)?;
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&[&role.audience]);
    validation.set_issuer(&[&role.issuer]);

    let decoded =
        decode::<ValidatedClaims>(token, &decoding_key, &validation).map_err(|source| {
            AuthzooError::TokenValidation {
                role: role.name.clone(),
                source,
            }
        })?;
    decoded.claims.require_claims(&role.claims)?;

    debug!(
        role = %role.name,
        subject = %decoded.claims.subject(),
        "role assumption succeeded"
    );

    Ok(decoded.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClaimRequirement, JwtAlgorithm};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        organization_slug: &'a str,
        pipeline_slug: &'a str,
    }

    #[test]
    fn matches_role_when_signature_registered_claims_and_role_claims_match() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        let token = test_token("builder", "my-org", "release");

        assert_eq!(
            validator.validate(&token),
            vec!["buildkite-release".to_string()]
        );
    }

    #[test]
    fn omits_role_when_claims_do_not_match() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        let token = test_token("builder", "my-org", "other");

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn returns_only_roles_whose_claims_match() {
        let validator = TokenValidator::new(vec![
            RoleConfig {
                name: "other".to_string(),
                claims: BTreeMap::from([(
                    "pipeline_slug".to_string(),
                    ClaimRequirement::Equals("other".to_string()),
                )]),
                ..buildkite_role()
            },
            buildkite_role(),
        ])
        .unwrap();
        let token = test_token("builder", "my-org", "release");

        assert_eq!(
            validator.validate(&token),
            vec!["buildkite-release".to_string()]
        );
    }

    #[test]
    fn validates_duplicate_role_names() {
        let error = TokenValidator::new(vec![buildkite_role(), buildkite_role()]).unwrap_err();

        assert_eq!(error.to_string(), "duplicate role 'buildkite-release'");
    }

    #[test]
    fn reports_unknown_role_references() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();

        let error = validator.ensure_roles_exist(["missing"]).unwrap_err();

        assert_eq!(error.to_string(), "unknown role 'missing'");
    }

    fn buildkite_role() -> RoleConfig {
        RoleConfig {
            name: "buildkite-release".to_string(),
            issuer: "https://agent.buildkite.com".to_string(),
            audience: "reposnake".to_string(),
            validation_key: Some("shared-secret".to_string()),
            algorithms: vec![JwtAlgorithm::Hs256],
            claims: BTreeMap::from([
                (
                    "organization_slug".to_string(),
                    ClaimRequirement::Equals("my-org".to_string()),
                ),
                (
                    "pipeline_slug".to_string(),
                    ClaimRequirement::Equals("release".to_string()),
                ),
                (
                    "sub".to_string(),
                    ClaimRequirement::AnyOf(vec!["builder".to_string(), "release-bot".to_string()]),
                ),
            ]),
        }
    }

    fn test_token(subject: &str, organization_slug: &str, pipeline_slug: &str) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: subject,
                iss: "https://agent.buildkite.com",
                aud: "reposnake",
                exp,
                organization_slug,
                pipeline_slug,
            },
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap()
    }
}
