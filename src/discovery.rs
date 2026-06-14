// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::{AuthzooError, RoleConfig};
use anyhow::Context;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, decode_header};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::debug;

const KUBERNETES_SERVICE_HOST: &str = "https://kubernetes.default.svc";
const KUBERNETES_SERVICE_HOST_ALIASES: &[&str] = &[
    KUBERNETES_SERVICE_HOST,
    "https://kubernetes.default.svc.cluster.local",
];
const KUBERNETES_CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const KUBERNETES_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const JWKS_KEY_CACHE_CAPACITY: usize = 100;
const JWKS_KEY_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

static JWKS_KEY_CACHE: OnceLock<Mutex<JwksKeyCache>> = OnceLock::new();

pub(crate) fn discovery_decoding_key(
    role: &RoleConfig,
    token: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, AuthzooError> {
    let header = decode_header(token).context("failed to decode token header for key discovery")?;
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

    let cache_key = JwksKeyCacheKey::new(&openid_configuration.jwks_uri, &header.kid, algorithm);
    if let Some(jwk) = cached_jwks_key(&cache_key, algorithm) {
        debug!(
            role = %role.name,
            jwks_uri = %openid_configuration.jwks_uri,
            "using cached JWKS validation key"
        );
        return DecodingKey::from_jwk(&jwk)
            .with_context(|| {
                let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
                format!("failed to construct decoding key from cached JWK '{key_id}'")
            })
            .map_err(AuthzooError::from);
    }

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

    let jwk = select_jwk_for_token(&jwks, &header.kid, algorithm)?.clone();
    cache_jwks_key(cache_key, jwk.clone());

    DecodingKey::from_jwk(&jwk)
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

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct JwksKeyCacheKey {
    jwks_uri: String,
    selector: String,
}

impl JwksKeyCacheKey {
    fn new(jwks_uri: &str, kid: &Option<String>, algorithm: Algorithm) -> Self {
        let selector = kid
            .as_ref()
            .map(|kid| format!("kid:{kid}"))
            .unwrap_or_else(|| format!("algorithm:{algorithm:?}"));
        Self {
            jwks_uri: jwks_uri.to_string(),
            selector,
        }
    }
}

#[derive(Debug)]
struct CachedJwksKey {
    jwk: Jwk,
    expires_at: Instant,
}

#[derive(Debug)]
struct JwksKeyCache {
    entries: HashMap<JwksKeyCacheKey, CachedJwksKey>,
    recency: VecDeque<JwksKeyCacheKey>,
    capacity: usize,
    ttl: Duration,
}

impl JwksKeyCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            recency: VecDeque::new(),
            capacity,
            ttl,
        }
    }

    fn get(&mut self, key: &JwksKeyCacheKey, now: Instant) -> Option<Jwk> {
        let (jwk, is_expired) = {
            let entry = self.entries.get(key)?;
            (entry.jwk.clone(), entry.expires_at <= now)
        };

        if is_expired {
            self.entries.remove(key);
            self.remove_from_recency(key);
            return None;
        }

        self.mark_used(key);
        Some(jwk)
    }

    fn insert(&mut self, key: JwksKeyCacheKey, jwk: Jwk, now: Instant) {
        if self.capacity == 0 {
            return;
        }

        self.entries.insert(
            key.clone(),
            CachedJwksKey {
                jwk,
                expires_at: now + self.ttl,
            },
        );
        self.mark_used(&key);
        self.evict_expired(now);
        self.evict_lru();
    }

    fn mark_used(&mut self, key: &JwksKeyCacheKey) {
        self.remove_from_recency(key);
        self.recency.push_back(key.clone());
    }

    fn evict_expired(&mut self, now: Instant) {
        let expired_keys = self
            .entries
            .iter()
            .filter_map(|(key, entry)| (entry.expires_at <= now).then_some(key.clone()))
            .collect::<Vec<_>>();

        for key in expired_keys {
            self.entries.remove(&key);
            self.remove_from_recency(&key);
        }
    }

    fn evict_lru(&mut self) {
        while self.entries.len() > self.capacity {
            if let Some(key) = self.recency.pop_front() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    fn remove_from_recency(&mut self, key: &JwksKeyCacheKey) {
        self.recency.retain(|candidate| candidate != key);
    }
}

fn cached_jwks_key(cache_key: &JwksKeyCacheKey, algorithm: Algorithm) -> Option<Jwk> {
    let cache = JWKS_KEY_CACHE.get_or_init(|| {
        Mutex::new(JwksKeyCache::new(
            JWKS_KEY_CACHE_CAPACITY,
            JWKS_KEY_CACHE_TTL,
        ))
    });
    let Ok(mut cache) = cache.lock() else {
        return None;
    };

    let jwk = cache.get(cache_key, Instant::now())?;
    ensure_jwk_compatible(&jwk, algorithm).ok()?;
    Some(jwk)
}

fn cache_jwks_key(cache_key: JwksKeyCacheKey, jwk: Jwk) {
    let cache = JWKS_KEY_CACHE.get_or_init(|| {
        Mutex::new(JwksKeyCache::new(
            JWKS_KEY_CACHE_CAPACITY,
            JWKS_KEY_CACHE_TTL,
        ))
    });
    let Ok(mut cache) = cache.lock() else {
        return;
    };

    cache.insert(cache_key, jwk, Instant::now());
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jwks_key_cache_returns_cached_key_before_ttl_expires() {
        let mut cache = JwksKeyCache::new(100, Duration::from_secs(60));
        let now = Instant::now();
        let key = test_cache_key("https://issuer.example/jwks", "one");

        cache.insert(key.clone(), test_jwk("one"), now);

        assert_eq!(
            cache
                .get(&key, now + Duration::from_secs(59))
                .unwrap()
                .common
                .key_id
                .as_deref(),
            Some("one")
        );
    }

    #[test]
    fn jwks_key_cache_expires_keys_after_ttl() {
        let mut cache = JwksKeyCache::new(100, Duration::from_secs(60));
        let now = Instant::now();
        let key = test_cache_key("https://issuer.example/jwks", "one");

        cache.insert(key.clone(), test_jwk("one"), now);

        assert!(cache.get(&key, now + Duration::from_secs(60)).is_none());
        assert!(cache.entries.is_empty());
        assert!(cache.recency.is_empty());
    }

    #[test]
    fn jwks_key_cache_evicts_least_recently_used_key() {
        let mut cache = JwksKeyCache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let first = test_cache_key("https://issuer.example/jwks", "one");
        let second = test_cache_key("https://issuer.example/jwks", "two");
        let third = test_cache_key("https://issuer.example/jwks", "three");

        cache.insert(first.clone(), test_jwk("one"), now);
        cache.insert(second.clone(), test_jwk("two"), now);
        assert!(cache.get(&first, now + Duration::from_secs(1)).is_some());
        cache.insert(
            third.clone(),
            test_jwk("three"),
            now + Duration::from_secs(2),
        );

        assert!(cache.get(&first, now + Duration::from_secs(3)).is_some());
        assert!(cache.get(&second, now + Duration::from_secs(3)).is_none());
        assert!(cache.get(&third, now + Duration::from_secs(3)).is_some());
    }

    fn test_cache_key(jwks_uri: &str, kid: &str) -> JwksKeyCacheKey {
        JwksKeyCacheKey::new(jwks_uri, &Some(kid.to_string()), Algorithm::HS256)
    }

    fn test_jwk(kid: &str) -> Jwk {
        serde_json::from_value(json!({
            "kty": "oct",
            "k": "c2hhcmVkLXNlY3JldA",
            "kid": kid,
            "alg": "HS256",
            "use": "sig"
        }))
        .unwrap()
    }
}
