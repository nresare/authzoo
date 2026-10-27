# authzoo

Rust crates for authentication and authorisation services such as [idelephant](https://github.com/nresare/idelephant), 
[idcat](https://github.com/portswigger/idcat) and
[reposnake](https://github.com/nresare/reposnake). Each crate is independent and versioned separately; they share
this repository because they serve the same family of applications.

| Crate | Purpose |
|---|---|
| [`authzoo`](authzoo) | Authorize JWT-bearing callers through configurable roles. |
| [`authzoo-oauth`](authzoo-oauth) | OAuth 2.0 and OpenID Connect building blocks for identity providers and MCP brokers. |
| [`authzoo-server`](authzoo-server) | Axum server utilities: TLS, request logging, graceful shutdown, and optional tracing. |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
```

Building the workspace unifies dependency features across crates, which can
hide a feature one crate needs but does not enable. Also test each crate on its
own, for example `cargo test -p authzoo-server`.

## License

All crates in this repository are licensed under the MIT license. See the
`LICENSE` file in each crate's directory for details.
