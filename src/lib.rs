// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use anyhow::Context;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use tracing::{debug, info};

const KUBERNETES_SERVICE_HOST: &str = "https://kubernetes.default.svc";
const KUBERNETES_SERVICE_HOST_ALIASES: &[&str] = &[
    KUBERNETES_SERVICE_HOST,
    "https://kubernetes.default.svc.cluster.local",
];
const KUBERNETES_CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const KUBERNETES_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

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

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatedClaims {
    sub: String,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct TokenValidator {
    roles: BTreeMap<String, RoleConfig>,
}

#[derive(Debug, Error)]
pub enum AuthzooError {
    #[error("role names must not be empty")]
    EmptyRoleName,
    #[error("role '{0}' audience must not be empty")]
    EmptyAudience(String),
    #[error("role '{0}' issuer must not be empty")]
    EmptyIssuer(String),
    #[error("role '{0}' validation-key must not be empty")]
    EmptyValidationKey(String),
    #[error("role '{0}' must allow at least one algorithm")]
    EmptyAlgorithms(String),
    #[error("role '{role}' claim names must not be empty")]
    EmptyClaimName { role: String },
    #[error("role '{role}' claim '{claim}' must define at least one acceptable value")]
    EmptyClaimRequirement { role: String, claim: String },
    #[error("duplicate role '{0}'")]
    DuplicateRole(String),
    #[error("unknown role '{0}'")]
    UnknownRole(String),
    #[error("token algorithm '{algorithm:?}' is not allowed for role '{role}'")]
    AlgorithmNotAllowed { role: String, algorithm: Algorithm },
    #[error("failed to validate token for role '{role}': {source}")]
    TokenValidation {
        role: String,
        #[source]
        source: jsonwebtoken::errors::Error,
    },
    #[error("claim '{claim}' must satisfy {requirement}")]
    MissingClaim {
        claim: String,
        requirement: ClaimRequirement,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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

    fn allows_algorithm(&self, algorithm: Algorithm) -> bool {
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

impl ValidatedClaims {
    pub fn subject(&self) -> &str {
        &self.sub
    }

    pub fn claims(&self) -> &BTreeMap<String, Value> {
        &self.claims
    }

    pub fn claim_value(&self, claim_name: &str) -> Option<&str> {
        if claim_name == "sub" {
            return Some(&self.sub);
        }
        self.claims.get(claim_name).and_then(Value::as_str)
    }

    pub fn first_missing_required_claim<'a>(
        &self,
        required_claims: &'a BTreeMap<String, ClaimRequirement>,
    ) -> Option<(&'a str, &'a ClaimRequirement)> {
        required_claims
            .iter()
            .find(|(claim_name, requirement)| !requirement.matches(self.claim_value(claim_name)))
            .map(|(claim_name, requirement)| (claim_name.as_str(), requirement))
    }

    pub fn require_claims(
        &self,
        required_claims: &BTreeMap<String, ClaimRequirement>,
    ) -> Result<(), AuthzooError> {
        if let Some((claim, requirement)) = self.first_missing_required_claim(required_claims) {
            return Err(AuthzooError::MissingClaim {
                claim: claim.to_string(),
                requirement: requirement.clone(),
            });
        }
        Ok(())
    }
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
        subject = %decoded.claims.sub,
        "role assumption succeeded"
    );

    Ok(decoded.claims)
}

fn resolving_decoding_key(
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

fn discovery_decoding_key(
    role: &RoleConfig,
    token: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, AuthzooError> {
    let openid_configuration_url = format!(
        "{}/.well-known/openid-configuration",
        role.issuer.trim_end_matches('/')
    );
    debug!(
        role = %role.name,
        issuer = %role.issuer,
        openid_configuration_url = %openid_configuration_url,
        "fetching OpenID configuration for validation key discovery"
    );
    let client = discovery_client(role)?;

    let openid_configuration: OpenIdConfiguration = client
        .get(&openid_configuration_url)
        .send()
        .with_context(|| {
            format!("failed to fetch OpenID configuration from '{openid_configuration_url}'")
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "OpenID configuration request to '{openid_configuration_url}' returned an error status"
            )
        })?
        .json()
        .with_context(|| {
            format!("failed to parse OpenID configuration from '{openid_configuration_url}'")
        })?;

    let jwks: JwkSet = client
        .get(&openid_configuration.jwks_uri)
        .send()
        .with_context(|| {
            format!(
                "failed to fetch JWKS from '{}'",
                openid_configuration.jwks_uri
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "JWKS request to '{}' returned an error status",
                openid_configuration.jwks_uri
            )
        })?
        .json()
        .with_context(|| {
            format!(
                "failed to parse JWKS from '{}'",
                openid_configuration.jwks_uri
            )
        })?;
    debug!(
        role = %role.name,
        jwks_key_count = jwks.keys.len(),
        "fetched JWKS for validation key discovery"
    );

    let header = decode_header(token).context("failed to decode token header for key discovery")?;
    let jwk = select_jwk_for_token(&jwks, &header.kid, algorithm)?;

    DecodingKey::from_jwk(jwk)
        .with_context(|| {
            let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
            format!("failed to construct decoding key from discovered JWK '{key_id}'")
        })
        .map_err(AuthzooError::from)
}

fn discovery_client(role: &RoleConfig) -> Result<Client, AuthzooError> {
    let mut builder = Client::builder();

    if is_kubernetes_service_issuer(&role.issuer) {
        debug!("configuring Kubernetes-specific HTTP client settings for validation key discovery");
        builder = configure_in_cluster_client(builder)?;
    }

    Ok(builder
        .build()
        .context("failed to build HTTP client for validation key discovery")?)
}

fn is_kubernetes_service_issuer(issuer: &str) -> bool {
    let issuer = issuer.trim_end_matches('/');
    KUBERNETES_SERVICE_HOST_ALIASES.contains(&issuer)
}

fn configure_in_cluster_client(mut builder: ClientBuilder) -> anyhow::Result<ClientBuilder> {
    if let Ok(ca_cert_pem) = std::fs::read(KUBERNETES_CA_CERT_PATH) {
        let certificate = reqwest::Certificate::from_pem(&ca_cert_pem).with_context(|| {
            format!(
                "failed to parse Kubernetes CA certificate bundle at '{KUBERNETES_CA_CERT_PATH}'"
            )
        })?;
        builder = builder.add_root_certificate(certificate);
    }

    if let Ok(service_account_token) = std::fs::read_to_string(KUBERNETES_TOKEN_PATH) {
        let token = service_account_token.trim();
        if !token.is_empty() {
            let mut headers = HeaderMap::new();
            let header_value = HeaderValue::from_str(&format!("Bearer {token}")).with_context(|| {
                format!(
                    "failed to build Authorization header from Kubernetes token at '{KUBERNETES_TOKEN_PATH}'"
                )
            })?;
            headers.insert(AUTHORIZATION, header_value);
            builder = builder.default_headers(headers);
        }
    }

    Ok(builder)
}

#[derive(Debug, Deserialize)]
struct OpenIdConfiguration {
    jwks_uri: String,
}

fn select_jwk_for_token<'a>(
    jwks: &'a JwkSet,
    kid: &Option<String>,
    algorithm: Algorithm,
) -> anyhow::Result<&'a Jwk> {
    if let Some(kid) = kid {
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| anyhow::anyhow!("no JWK found for token kid '{kid}'"))?;
        ensure_jwk_compatible(jwk, algorithm)?;
        return Ok(jwk);
    }

    let mut matching_keys = jwks
        .keys
        .iter()
        .filter(|jwk| jwk_matches_algorithm(jwk, algorithm));
    let jwk = matching_keys
        .next()
        .ok_or_else(|| anyhow::anyhow!("no compatible JWK found for algorithm '{algorithm:?}'"))?;
    if matching_keys.next().is_some() {
        anyhow::bail!(
            "multiple compatible JWKs found for algorithm '{algorithm:?}' but the token header did not include a kid"
        );
    }
    Ok(jwk)
}

fn ensure_jwk_compatible(jwk: &Jwk, algorithm: Algorithm) -> anyhow::Result<()> {
    if !jwk_matches_algorithm(jwk, algorithm) {
        let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
        anyhow::bail!("discovered JWK '{key_id}' is not compatible with algorithm '{algorithm:?}'");
    }
    Ok(())
}

fn jwk_matches_algorithm(jwk: &Jwk, algorithm: Algorithm) -> bool {
    if let Some(public_key_use) = &jwk.common.public_key_use
        && *public_key_use != PublicKeyUse::Signature
    {
        return false;
    }

    if !key_algorithm_matches(jwk, algorithm) {
        return false;
    }

    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => matches!(jwk.algorithm, AlgorithmParameters::RSA(_)),
        Algorithm::ES256 | Algorithm::ES384 => {
            matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_))
        }
        Algorithm::EdDSA => matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(_)),
    }
}

fn key_algorithm_matches(jwk: &Jwk, algorithm: Algorithm) -> bool {
    match jwk.common.key_algorithm {
        Some(key_algorithm) => key_algorithm == key_algorithm_for_algorithm(algorithm),
        None => true,
    }
}

fn key_algorithm_for_algorithm(algorithm: Algorithm) -> KeyAlgorithm {
    match algorithm {
        Algorithm::HS256 => KeyAlgorithm::HS256,
        Algorithm::HS384 => KeyAlgorithm::HS384,
        Algorithm::HS512 => KeyAlgorithm::HS512,
        Algorithm::RS256 => KeyAlgorithm::RS256,
        Algorithm::RS384 => KeyAlgorithm::RS384,
        Algorithm::RS512 => KeyAlgorithm::RS512,
        Algorithm::PS256 => KeyAlgorithm::PS256,
        Algorithm::PS384 => KeyAlgorithm::PS384,
        Algorithm::PS512 => KeyAlgorithm::PS512,
        Algorithm::ES256 => KeyAlgorithm::ES256,
        Algorithm::ES384 => KeyAlgorithm::ES384,
        Algorithm::EdDSA => KeyAlgorithm::EdDSA,
    }
}

impl JwtAlgorithm {
    fn to_algorithm(self) -> Algorithm {
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
    use jsonwebtoken::{EncodingKey, Header, encode};
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
    fn rejects_empty_claim_requirement_values() {
        let error = TokenValidator::new(vec![RoleConfig {
            claims: BTreeMap::from([("sub".to_string(), ClaimRequirement::AnyOf(Vec::new()))]),
            ..buildkite_role()
        }])
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "role 'buildkite-release' claim 'sub' must define at least one acceptable value"
        );
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
