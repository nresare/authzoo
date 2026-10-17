// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::keys::resolving_decoding_key;
use crate::{AuthzooError, Config, RoleConfig, ValidatedClaims};
use anyhow::Context;
use jsonwebtoken::{Validation, decode, decode_header};
use std::collections::{BTreeMap, HashSet};
use tracing::{debug, info};

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

    /// Validate a token against one role, preserving the reason for rejection.
    pub fn validate_for_role(
        &self,
        role_name: &str,
        token: &str,
    ) -> Result<ValidatedClaims, AuthzooError> {
        let role = self
            .roles
            .get(role_name)
            .ok_or_else(|| AuthzooError::UnknownRole(role_name.to_string()))?;
        validate_token_for_role(role, token)
    }

    pub fn validate(&self, token: &str) -> Vec<String> {
        self.roles
            .iter()
            .filter_map(|(name, role)| match validate_token_for_role(role, token) {
                Ok(_) => Some(name.clone()),
                Err(error) => {
                    info!(
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
    if let Err(error) = decoded.claims.require_claims(&role.claims) {
        debug!(
            role = %role.name,
            error = %error,
            "token signature and registered claims are valid, but role claims did not match"
        );
        return Err(error);
    }

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
    fn validates_one_role_and_returns_its_claims() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        let token = test_token("builder", "my-org", "release");
        let claims = validator
            .validate_for_role("buildkite-release", &token)
            .unwrap();
        assert_eq!(claims.subject(), "builder");
    }

    #[test]
    fn reports_unknown_role_when_validating_token() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        assert!(matches!(
            validator.validate_for_role("missing", "not-a-token"),
            Err(AuthzooError::UnknownRole(role)) if role == "missing"
        ));
    }

    #[test]
    fn preserves_token_validation_failures() {
        use jsonwebtoken::errors::ErrorKind;
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        let token = test_token("builder", "my-org", "release");
        let claims = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(&token)
            .unwrap()
            .claims;
        for (claim, value, expected) in [
            ("exp", serde_json::json!(1), ErrorKind::ExpiredSignature),
            (
                "iss",
                serde_json::json!("wrong-issuer"),
                ErrorKind::InvalidIssuer,
            ),
            (
                "aud",
                serde_json::json!("wrong-audience"),
                ErrorKind::InvalidAudience,
            ),
        ] {
            let mut claims = claims.clone();
            claims[claim] = value;
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(b"shared-secret"),
            )
            .unwrap();
            let error = validator
                .validate_for_role("buildkite-release", &token)
                .unwrap_err();
            assert!(
                matches!(error, AuthzooError::TokenValidation { source, .. }
                if source.kind() == &expected),
                "unexpected error for {claim}"
            );
        }
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"wrong-secret"),
        )
        .unwrap();
        assert!(
            matches!(validator.validate_for_role("buildkite-release", &token),
            Err(AuthzooError::TokenValidation { source, .. })
                if source.kind() == &ErrorKind::InvalidSignature)
        );
        assert!(
            validator
                .validate_for_role("buildkite-release", "not-a-token")
                .unwrap_err()
                .to_string()
                .contains("failed to decode token header")
        );
        let token = encode(
            &Header::new(Algorithm::HS384),
            &claims,
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap();
        assert!(matches!(
            validator.validate_for_role("buildkite-release", &token),
            Err(AuthzooError::AlgorithmNotAllowed {
                algorithm: Algorithm::HS384,
                ..
            })
        ));
    }

    #[test]
    fn omits_role_when_claims_do_not_match() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        let token = test_token("builder", "my-org", "other");

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn reports_the_claim_that_did_not_match_after_token_validation() {
        let validator = TokenValidator::new(vec![buildkite_role()]).unwrap();
        let token = test_token("builder", "my-org", "other");

        let error = validator
            .validate_for_role("buildkite-release", &token)
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "claim 'pipeline_slug' must satisfy equals 'release'"
        );
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

    fn groups_role() -> RoleConfig {
        RoleConfig {
            name: "release-approvers".to_string(),
            issuer: "https://issuer.example".to_string(),
            audience: "artifact-service".to_string(),
            validation_key: Some("shared-secret".to_string()),
            algorithms: vec![JwtAlgorithm::Hs256],
            claims: BTreeMap::from([(
                "groups".to_string(),
                ClaimRequirement::contains("release-approvers"),
            )]),
        }
    }

    fn groups_token(groups: serde_json::Value) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "sub": "someone",
                "iss": "https://issuer.example",
                "aud": "artifact-service",
                "exp": exp,
                "groups": groups,
            }),
            &EncodingKey::from_secret(b"shared-secret"),
        )
        .unwrap()
    }

    #[test]
    fn contains_matches_an_array_holding_the_exact_value() {
        let validator = TokenValidator::new(vec![groups_role()]).unwrap();
        let token = groups_token(serde_json::json!(["readers", "release-approvers"]));

        assert_eq!(
            validator.validate(&token),
            vec!["release-approvers".to_string()]
        );
    }

    #[test]
    fn contains_does_not_match_an_element_that_only_contains_the_value() {
        let validator = TokenValidator::new(vec![groups_role()]).unwrap();
        let token = groups_token(serde_json::json!(["release-approvers-readonly"]));

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn contains_does_not_match_a_value_that_is_a_prefix_of_the_requirement() {
        let validator = TokenValidator::new(vec![groups_role()]).unwrap();
        let token = groups_token(serde_json::json!(["release"]));

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn contains_does_not_treat_a_string_claim_as_a_one_element_array() {
        let validator = TokenValidator::new(vec![groups_role()]).unwrap();
        let token = groups_token(serde_json::json!("release-approvers"));

        assert!(
            validator.validate(&token).is_empty(),
            "a string-valued claim must not satisfy a contains requirement"
        );
    }

    #[test]
    fn contains_does_not_match_when_the_claim_is_absent() {
        let validator = TokenValidator::new(vec![groups_role()]).unwrap();
        let token = groups_token(serde_json::Value::Null);

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn contains_ignores_non_string_array_elements() {
        let validator = TokenValidator::new(vec![groups_role()]).unwrap();
        let token = groups_token(serde_json::json!([1, true, {"name": "release-approvers"}]));

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn equals_still_does_not_match_an_array_claim() {
        // Existing requirement forms keep their meaning: only a contains requirement looks inside
        // an array.
        let role = RoleConfig {
            claims: BTreeMap::from([(
                "groups".to_string(),
                ClaimRequirement::equals("release-approvers"),
            )]),
            ..groups_role()
        };
        let validator = TokenValidator::new(vec![role]).unwrap();
        let token = groups_token(serde_json::json!(["release-approvers"]));

        assert!(validator.validate(&token).is_empty());
    }

    #[test]
    fn reports_an_unmet_contains_requirement() {
        let token = groups_token(serde_json::json!(["readers"]));

        let error = validate_token_for_role(&groups_role(), &token).unwrap_err();

        assert_eq!(
            error.to_string(),
            "claim 'groups' must satisfy contains 'release-approvers'"
        );
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
