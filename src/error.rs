// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::ClaimRequirement;
use jsonwebtoken::Algorithm;
use thiserror::Error;

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
