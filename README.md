# authzoo

`authzoo` is a Rust library for authorizing JWT-bearing callers through
configurable roles.

The central idea is similar to AWS IAM roles: a caller presents a JWT, and if
that token satisfies the trust criteria for a role, the caller is considered to
have assumed that role. Your application can then attach those roles to whatever
it protects: upload permissions, internal API routes, deployment actions, token
exchange mappings, or anything else with an authorization decision.

`authzoo` handles the reusable JWT parts:

- parsing role configuration from TOML-friendly Serde types
- validating issuer, audience, signature, and expiry
- resolving validation keys from a static key or OIDC/JWKS discovery
- matching token claims against role requirements
- optionally returning validated claims to the application

Your application still owns its own permission model. `authzoo` answers the
question: "Can this token assume this role?"

## Role Config

A role describes which JWTs are trusted to assume it.

```toml
[[role]]
name = "release-pipeline"
issuer = "https://ci.example.com"
audience = "artifact-service"
algorithms = ["RS256"]

[role.claims]
organization = "example-org"
pipeline = "release"
sub = { any-of = ["builder", "release-bot"] }
```

This role can be assumed by a token that:

- is issued by `https://ci.example.com`
- has audience `artifact-service`
- is signed with `RS256`
- has `organization = "example-org"`
- has `pipeline = "release"`
- has `sub` equal to either `builder` or `release-bot`

Claim requirements may be written as exact string matches:

```toml
[role.claims]
environment = "production"
```

Or as one-of matches:

```toml
[role.claims]
sub = { any-of = ["service-a", "service-b"] }
```

## Validation Keys

If `validation-key` is omitted, `authzoo` discovers signing keys using OpenID
Connect discovery:

1. Fetch `<issuer>/.well-known/openid-configuration`.
2. Read the `jwks_uri` field.
3. Fetch the JWKS document.
4. Select a compatible key for the JWT header.

```toml
[[role]]
name = "cluster-workload"
issuer = "https://kubernetes.default.svc"
audience = "internal-api"
algorithms = ["RS256"]

[role.claims]
sub = "system:serviceaccount:default:worker"
```

For Kubernetes service issuers, `authzoo` also uses the in-cluster service
account CA and bearer token when they are available.

For local testing or shared-secret issuers, configure a static validation key:

```toml
[[role]]
name = "local-ci"
issuer = "https://issuer.example"
audience = "artifact-service"
validation-key = "shared-secret"
algorithms = ["HS256"]
```

## Application Use

Applications usually decide which role is required before calling `authzoo`.
That role might come from a route, an action config, a resource policy, or any
other application-specific authorization decision.

```toml
[[protected-action]]
name = "publish-release"
role = "release-pipeline"
```

At runtime, build a token validator from configuration and ask whether the
caller's JWT can assume the required role.

```rust
let validator = authzoo::TokenValidator::try_from(config.authzoo)?;

validator.validate(&action.role, bearer_token)?;

tracing::info!(
    role = %action.role,
    "request authorized"
);
```

If validation returns `Ok(())`, the application knows that the token can assume
the specified role. If validation fails, `authzoo` returns an error explaining
the failed token validation or claim requirement.

If the application needs the token subject or custom claims after validation, it
can call `validate_claims`.

```rust
let claims = validator.validate_claims(&action.role, bearer_token)?;
tracing::info!(
    role = %action.role,
    subject = claims.subject(),
    "request authorized"
);
```

## Public Types

The main types are:

- `Config`: a TOML-friendly wrapper containing `roles`
- `RoleConfig`: issuer, audience, algorithms, validation key, and required claims
- `ClaimRequirement`: exact string or one-of string matching
- `TokenValidator`: validates tokens against a named role
- `ValidatedClaims`: access to `sub` and flattened custom claims

## Boundaries

`authzoo` intentionally does not decide what a role means inside your
application. It only validates that a caller can assume a role. Your application
decides what `release-pipeline`, `cluster-workload`, or `admin` is allowed to
do.

## License

MIT
