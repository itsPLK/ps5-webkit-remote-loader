# Wobkot integration

The upstream [ufm42/wobkot](https://github.com/ufm42/wobkot) repository is pinned
at `vendor/wobkot` as a Git submodule. Files inside that directory are upstream
code and must remain unmodified.

Remote-loader-specific boot, transport, payload API, and packaging integration
lives outside the submodule in `src/wobkot_bootstrap.js`,
`src/wobkot_adapter.js`, and the surrounding project files.

To update Wobkot, fetch and check out the desired upstream commit inside the
submodule, run `make test`, and commit the new submodule pointer in this
repository. Consumers embedding remote-loader, including ps5-webkit-autoloader,
must initialize submodules recursively.
