# Native desktop processing startup

The Tauri launcher can opt into a Rust processing executable with
`STIRLING_NATIVE_BACKEND_PATH`; Java remains the packaged/default sidecar.

The native path now provides:

- an unconditional `Stirling-PDF running on port: <port>` handshake even without `RUST_LOG`;
- an ephemeral loopback port, bounded 90-second launcher wait, stderr/stdout handshake parsing,
  early-exit reporting, stale-process protection, and stale-port cleanup;
- desktop/base/config/log/work environment parity and legacy-workspace migration;
- PID-plus-start-time parent monitoring through `TAURI_PARENT_PID`, with orphan shutdown normally
  observed within one 250 ms poll interval;
- fresh-install configuration initialization in Tauri mode: the packaged Java
  `settings.yml.template` is atomically persisted only when `configs/settings.yml` is absent, and
  an empty `custom_settings.yml` is created only when absent.

Existing settings bytes are never rewritten by the fresh-install initializer. Java's short-file
backup behavior, template-key migrations, and upgrade-time merge remain a separate upgrade gate.
Production sidecar/PDFium packaging, cross-platform signed-bundle upgrade proof, and switching the
default away from Java also remain.
