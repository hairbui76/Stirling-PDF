//! Wiring tests for the executable's background maintenance startup path:
//! which periodic loops actually spawn for each runtime flavour, and that the
//! periodic license re-verification (Java `LicenseKeyChecker` parity) is
//! spawned exactly when license state exists.

use std::fs;

use stirling_processing::{ProcessingRuntime, TimestampSettings, runtime_config::RuntimeConfig};
use tempfile::tempdir;

#[tokio::test]
async fn open_runtime_spawns_core_loops_without_license_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let runtime_config = RuntimeConfig::from_files(
        directory.path().join("settings.yml"),
        directory.path().join("custom.yml"),
    );
    let runtime = ProcessingRuntime::with_runtime_config(
        1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    );

    // The open runtime carries no license state: nothing must be spawned.
    assert!(!runtime.spawn_license_refresh());
    // Job-result cleanup and the mobile-scanner session sweep always run.
    assert_eq!(runtime.spawn_background_maintenance(), 2);
    Ok(())
}

#[tokio::test]
async fn reviewed_security_runtime_spawns_license_refresh_and_audit_retention()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n",
    )?;
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let runtime = ProcessingRuntime::with_reviewed_security(
        1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    )?;

    // Secured startup builds license state, so the seven-day refresh loop
    // must actually spawn — this is the regression guard for the previously
    // dead `spawn_license_refresh` wiring.
    assert!(runtime.spawn_license_refresh());
    // Job results + mobile scanner + audit retention (enabled by default);
    // storage and policies stay off by default so their loops must not spawn.
    assert_eq!(runtime.spawn_background_maintenance(), 3);
    Ok(())
}

#[tokio::test]
async fn storage_and_policy_features_add_their_maintenance_loops()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        concat!(
            "security:\n",
            "  initialLogin:\n",
            "    username: admin@example.test\n",
            "    password: test-only-password\n",
            "storage:\n",
            "  enabled: true\n",
            "policies:\n",
            "  enabled: true\n",
        ),
    )?;
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let runtime = ProcessingRuntime::with_reviewed_security(
        1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    )?;

    assert!(runtime.spawn_license_refresh());
    // Core pair + audit retention + storage cleanup + policy run registry.
    assert_eq!(runtime.spawn_background_maintenance(), 5);
    Ok(())
}
