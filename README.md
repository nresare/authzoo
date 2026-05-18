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

Your application still owns its own permission model. `authzoo` answers the
question: "Which roles can this token assume?"

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

Each protected resource declares the roles that are allowed to access it.

```toml
[[protected-action]]
name = "publish-release"
allowed-roles = ["release-pipeline", "release-admin"]
```

At runtime, build a token validator from configuration, ask which roles the
caller's JWT can assume, and intersect that list with the resource's allowed
roles.

```rust
let validator = authzoo::TokenValidator::try_from(config.authzoo)?;

let assumed = validator.validate(bearer_token);
let Some(role) = action
    .allowed_roles
    .iter()
    .find(|allowed| assumed.iter().any(|r| r == *allowed))
else {
    return Err(Forbidden);
};

tracing::info!(role = %role, "request authorized");
```

`validate` returns every configured role whose issuer, audience, signature,
and claim requirements are satisfied by the token. If no role matches, the
returned list is empty.

## Public Types

The main types are:

- `Config`: a TOML-friendly wrapper containing `roles`
- `RoleConfig`: issuer, audience, algorithms, validation key, and required claims
- `ClaimRequirement`: exact string or one-of string matching
- `TokenValidator`: returns the roles a token can assume

## Boundaries

`authzoo` intentionally does not decide what a role means inside your
application. It only validates that a caller can assume a role. Your application
decides what `release-pipeline`, `cluster-workload`, or `admin` is allowed to
do.

## License

MIT
