// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The authzoo contributors

use crate::{AuthzooError, ClaimRequirement};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatedClaims {
    sub: String,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
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
