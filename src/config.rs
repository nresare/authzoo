// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::AuthzooError;
use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    #[serde(rename = "role", default)]
    pub roles: Vec<RoleConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RoleConfig {
    pub name: String,
    pub audience: String,
    pub issuer: String,
    pub validation_key: Option<String>,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<JwtAlgorithm>,
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimRequirement>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum JwtAlgorithm {
    #[serde(rename = "HS256")]
    Hs256,
    #[serde(rename = "HS384")]
    Hs384,
    #[serde(rename = "HS512")]
    Hs512,
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ClaimRequirement {
    Equals(String),
    AnyOf(Vec<String>),
    Detailed(DetailedClaimRequirement),
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DetailedClaimRequirement {
    pub any_of: Vec<String>,
}

impl RoleConfig {
    pub fn validate(&self) -> Result<(), AuthzooError> {
        if self.name.is_empty() {
            return Err(AuthzooError::EmptyRoleName);
        }
        if self.audience.is_empty() {
            return Err(AuthzooError::EmptyAudience(self.name.clone()));
        }
        if self.issuer.is_empty() {
            return Err(AuthzooError::EmptyIssuer(self.name.clone()));
        }
        if matches!(self.validation_key.as_deref(), Some("")) {
            return Err(AuthzooError::EmptyValidationKey(self.name.clone()));
        }
        if self.algorithms.is_empty() {
            return Err(AuthzooError::EmptyAlgorithms(self.name.clone()));
        }
        for (claim, requirement) in &self.claims {
            if claim.is_empty() {
                return Err(AuthzooError::EmptyClaimName {
                    role: self.name.clone(),
                });
            }
            requirement.validate(&self.name, claim)?;
        }
        Ok(())
    }

    pub(crate) fn allows_algorithm(&self, algorithm: Algorithm) -> bool {
        self.algorithms
            .iter()
            .any(|allowed| allowed.to_algorithm() == algorithm)
    }
}

impl ClaimRequirement {
    pub fn equals(value: impl Into<String>) -> Self {
        Self::Equals(value.into())
    }

    pub fn any_of(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::AnyOf(values.into_iter().map(Into::into).collect())
    }

    pub fn validate(&self, role: &str, claim: &str) -> Result<(), AuthzooError> {
        let is_empty = match self {
            Self::Equals(value) => value.is_empty(),
            Self::AnyOf(values) => values.is_empty() || values.iter().any(String::is_empty),
            Self::Detailed(DetailedClaimRequirement { any_of }) => {
                any_of.is_empty() || any_of.iter().any(String::is_empty)
            }
        };
        if is_empty {
            return Err(AuthzooError::EmptyClaimRequirement {
                role: role.to_string(),
                claim: claim.to_string(),
            });
        }
        Ok(())
    }

    pub fn matches(&self, value: Option<&str>) -> bool {
        match self {
            Self::Equals(required) => value == Some(required.as_str()),
            Self::AnyOf(required) => required.iter().any(|required| value == Some(required)),
            Self::Detailed(required) => required
                .any_of
                .iter()
                .any(|required| value == Some(required.as_str())),
        }
    }
}

impl std::fmt::Display for ClaimRequirement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Equals(value) => write!(formatter, "equals '{value}'"),
            Self::AnyOf(values) => write!(formatter, "one of {:?}", values),
            Self::Detailed(DetailedClaimRequirement { any_of }) => {
                write!(formatter, "one of {any_of:?}")
            }
        }
    }
}

impl JwtAlgorithm {
    pub(crate) fn to_algorithm(self) -> Algorithm {
        match self {
            Self::Hs256 => Algorithm::HS256,
            Self::Hs384 => Algorithm::HS384,
            Self::Hs512 => Algorithm::HS512,
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::EdDsa => Algorithm::EdDSA,
        }
    }
}

fn default_algorithms() -> Vec<JwtAlgorithm> {
    vec![JwtAlgorithm::Rs256]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct TestConfig {
        #[serde(rename = "role")]
        roles: Vec<RoleConfig>,
    }

    #[test]
    fn parses_role_config_from_toml() {
        let config: TestConfig = toml::from_str(
            r#"
[[role]]
name = "buildkite-release"
issuer = "https://agent.buildkite.com"
audience = "reposnake"
validation-key = "shared-secret"
algorithms = ["HS256"]

[role.claims]
organization_slug = "my-org"
pipeline_slug = "release"
sub = { any-of = ["builder", "release-bot"] }
"#,
        )
        .unwrap();

        let role = &config.roles[0];
        assert_eq!(role.name, "buildkite-release");
        assert_eq!(role.algorithms, vec![JwtAlgorithm::Hs256]);
        assert_eq!(
            role.claims["sub"],
            ClaimRequirement::Detailed(DetailedClaimRequirement {
                any_of: vec!["builder".to_string(), "release-bot".to_string()]
            })
        );
    }

    #[test]
    fn rejects_empty_claim_requirement_values() {
        let error = buildkite_role_with_claims(BTreeMap::from([(
            "sub".to_string(),
            ClaimRequirement::AnyOf(Vec::new()),
        )]))
        .validate()
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "role 'buildkite-release' claim 'sub' must define at least one acceptable value"
        );
    }

    fn buildkite_role_with_claims(claims: BTreeMap<String, ClaimRequirement>) -> RoleConfig {
        RoleConfig {
            name: "buildkite-release".to_string(),
            issuer: "https://agent.buildkite.com".to_string(),
            audience: "reposnake".to_string(),
            validation_key: Some("shared-secret".to_string()),
            algorithms: vec![JwtAlgorithm::Hs256],
            claims,
        }
    }
}
