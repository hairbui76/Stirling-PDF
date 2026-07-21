use std::{env, ffi::OsString, fmt, path::PathBuf};

use stirling_ai_engine::{
    document_migration::{MigrationReport, migrate_sqlite_vec, paths_refer_to_same_file},
    documents::{DocumentRepository, SqliteDocumentStore},
    embedding::EmbeddingClient,
    pgvector_documents::PgVectorDocumentStore,
};

const DEFAULT_MODEL: &str = "voyageai:voyage-4";
const DEFAULT_CHUNK_SIZE: usize = 512;
const DEFAULT_CHUNK_OVERLAP: usize = 64;
const DEFAULT_POOL_MIN_SIZE: usize = 1;
const DEFAULT_POOL_MAX_SIZE: usize = 10;

const USAGE: &str = "\
Migrate a stopped Python sqlite-vec document store into a Rust document store.

Usage:
  migrate-sqlite-vec --source PATH --target-sqlite PATH [OPTIONS]
  migrate-sqlite-vec --source PATH --target-pgvector DSN [OPTIONS]

Required:
  --source PATH              Python sqlite-vec database to read
  --target-sqlite PATH       New Rust SQLite database to create or update
  --target-pgvector DSN      PostgreSQL/pgvector destination

Options:
  --model MODEL              Embedding model (voyageai:, openai:, or ollama:)
  --chunk-size NUMBER        Destination chunk size
  --chunk-overlap NUMBER     Destination chunk overlap
  --pool-min-size NUMBER     Minimum pgvector connections
  --pool-max-size NUMBER     Maximum pgvector connections
  -h, --help                 Print this help

Defaults come from STIRLING_RAG_EMBEDDING_MODEL, STIRLING_RAG_CHUNK_SIZE,
STIRLING_RAG_CHUNK_OVERLAP, STIRLING_DOCUMENTS_PGVECTOR_POOL_MIN_SIZE, and
STIRLING_DOCUMENTS_PGVECTOR_POOL_MAX_SIZE, then fall back to engine defaults.
";

#[derive(Debug)]
struct MigrationCliError(String);

impl MigrationCliError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MigrationCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MigrationCliError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MigrationTarget {
    Sqlite(PathBuf),
    PgVector(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MigrationOptions {
    source: PathBuf,
    target: MigrationTarget,
    model: String,
    chunk_size: usize,
    chunk_overlap: usize,
    pool_min_size: usize,
    pool_max_size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MigrationDefaults {
    model: String,
    chunk_size: usize,
    chunk_overlap: usize,
    pool_min_size: usize,
    pool_max_size: usize,
}

impl MigrationDefaults {
    fn from_environment() -> Result<Self, MigrationCliError> {
        Ok(Self {
            model: environment_string("STIRLING_RAG_EMBEDDING_MODEL", DEFAULT_MODEL)?,
            chunk_size: environment_usize("STIRLING_RAG_CHUNK_SIZE", DEFAULT_CHUNK_SIZE)?,
            chunk_overlap: environment_usize("STIRLING_RAG_CHUNK_OVERLAP", DEFAULT_CHUNK_OVERLAP)?,
            pool_min_size: environment_usize(
                "STIRLING_DOCUMENTS_PGVECTOR_POOL_MIN_SIZE",
                DEFAULT_POOL_MIN_SIZE,
            )?,
            pool_max_size: environment_usize(
                "STIRLING_DOCUMENTS_PGVECTOR_POOL_MAX_SIZE",
                DEFAULT_POOL_MAX_SIZE,
            )?,
        })
    }
}

enum MigrationCommand {
    Help,
    Run(MigrationOptions),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let defaults = MigrationDefaults::from_environment()?;
    match parse_arguments(env::args_os().skip(1), defaults)? {
        MigrationCommand::Help => print!("{USAGE}"),
        MigrationCommand::Run(options) => {
            let report = run_migration(options).await?;
            println!(
                "Migrated {} document(s) and indexed {} chunk(s).",
                report.documents_migrated, report.chunks_indexed
            );
        }
    }
    Ok(())
}

async fn run_migration(options: MigrationOptions) -> Result<MigrationReport, MigrationCliError> {
    if !options.source.is_file() {
        return Err(MigrationCliError::new(format!(
            "sqlite-vec source does not exist or is not a file: {}",
            options.source.display()
        )));
    }
    if let MigrationTarget::Sqlite(target) = &options.target
        && paths_refer_to_same_file(&options.source, target).map_err(|error| {
            MigrationCliError::new(format!(
                "could not compare source and target paths: {error}"
            ))
        })?
    {
        return Err(MigrationCliError::new(
            "source and SQLite destination must be different files",
        ));
    }

    let embedder = EmbeddingClient::from_environment(&options.model)
        .map_err(|error| MigrationCliError::new(format!("embedding configuration: {error}")))?;
    let destination: Box<dyn DocumentRepository> = match options.target {
        MigrationTarget::Sqlite(path) => Box::new(
            SqliteDocumentStore::open(path, options.chunk_size, options.chunk_overlap)
                .map_err(|error| MigrationCliError::new(format!("SQLite destination: {error}")))?,
        ),
        MigrationTarget::PgVector(dsn) => Box::new(
            PgVectorDocumentStore::new(
                &dsn,
                options.pool_min_size,
                options.pool_max_size,
                options.chunk_size,
                options.chunk_overlap,
            )
            .map_err(|error| MigrationCliError::new(format!("pgvector destination: {error}")))?,
        ),
    };
    migrate_sqlite_vec(&options.source, destination.as_ref(), &embedder)
        .await
        .map_err(|error| MigrationCliError::new(format!("migration failed: {error}")))
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = OsString>,
    defaults: MigrationDefaults,
) -> Result<MigrationCommand, MigrationCliError> {
    let mut arguments = arguments.into_iter();
    let mut source = None;
    let mut target_sqlite = None;
    let mut target_pgvector = None;
    let mut model = None;
    let mut chunk_size = None;
    let mut chunk_overlap = None;
    let mut pool_min_size = None;
    let mut pool_max_size = None;

    while let Some(argument) = arguments.next() {
        let flag = argument
            .to_str()
            .ok_or_else(|| MigrationCliError::new("option names must contain valid Unicode"))?;
        match flag {
            "-h" | "--help" => return Ok(MigrationCommand::Help),
            "--source" => set_once(
                &mut source,
                PathBuf::from(next_value(&mut arguments, flag)?),
                flag,
            )?,
            "--target-sqlite" => set_once(
                &mut target_sqlite,
                PathBuf::from(next_value(&mut arguments, flag)?),
                flag,
            )?,
            "--target-pgvector" => {
                let value = unicode_value(next_value(&mut arguments, flag)?, flag)?;
                set_once(&mut target_pgvector, value, flag)?;
            }
            "--model" => {
                let value = unicode_value(next_value(&mut arguments, flag)?, flag)?;
                set_once(&mut model, value, flag)?;
            }
            "--chunk-size" => {
                let value = numeric_value(next_value(&mut arguments, flag)?, flag)?;
                set_once(&mut chunk_size, value, flag)?;
            }
            "--chunk-overlap" => {
                let value = numeric_value(next_value(&mut arguments, flag)?, flag)?;
                set_once(&mut chunk_overlap, value, flag)?;
            }
            "--pool-min-size" => {
                let value = numeric_value(next_value(&mut arguments, flag)?, flag)?;
                set_once(&mut pool_min_size, value, flag)?;
            }
            "--pool-max-size" => {
                let value = numeric_value(next_value(&mut arguments, flag)?, flag)?;
                set_once(&mut pool_max_size, value, flag)?;
            }
            unknown => {
                return Err(MigrationCliError::new(format!(
                    "unknown option {unknown:?}; run with --help for usage"
                )));
            }
        }
    }

    let source = source.ok_or_else(|| MigrationCliError::new("--source is required"))?;
    let target = match (target_sqlite, target_pgvector) {
        (Some(path), None) => MigrationTarget::Sqlite(path),
        (None, Some(dsn)) => MigrationTarget::PgVector(dsn),
        (None, None) => {
            return Err(MigrationCliError::new(
                "exactly one of --target-sqlite or --target-pgvector is required",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(MigrationCliError::new(
                "--target-sqlite and --target-pgvector are mutually exclusive",
            ));
        }
    };
    Ok(MigrationCommand::Run(MigrationOptions {
        source,
        target,
        model: model.unwrap_or(defaults.model),
        chunk_size: chunk_size.unwrap_or(defaults.chunk_size),
        chunk_overlap: chunk_overlap.unwrap_or(defaults.chunk_overlap),
        pool_min_size: pool_min_size.unwrap_or(defaults.pool_min_size),
        pool_max_size: pool_max_size.unwrap_or(defaults.pool_max_size),
    }))
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<OsString, MigrationCliError> {
    arguments
        .next()
        .ok_or_else(|| MigrationCliError::new(format!("{flag} requires a value")))
}

fn unicode_value(value: OsString, flag: &str) -> Result<String, MigrationCliError> {
    value.into_string().map_err(|_| {
        MigrationCliError::new(format!("the value for {flag} must contain valid Unicode"))
    })
}

fn numeric_value(value: OsString, flag: &str) -> Result<usize, MigrationCliError> {
    let value = unicode_value(value, flag)?;
    value.parse::<usize>().map_err(|error| {
        MigrationCliError::new(format!("{flag} must be a non-negative integer: {error}"))
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), MigrationCliError> {
    if slot.is_some() {
        return Err(MigrationCliError::new(format!(
            "{flag} may only be specified once"
        )));
    }
    *slot = Some(value);
    Ok(())
}

fn environment_string(name: &str, default: &str) -> Result<String, MigrationCliError> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(MigrationCliError::new(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

fn environment_usize(name: &str, default: usize) -> Result<usize, MigrationCliError> {
    match env::var(name) {
        Ok(value) => value.parse::<usize>().map_err(|error| {
            MigrationCliError::new(format!("{name} must be a non-negative integer: {error}"))
        }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(MigrationCliError::new(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    use super::{
        DEFAULT_CHUNK_OVERLAP, DEFAULT_CHUNK_SIZE, DEFAULT_MODEL, DEFAULT_POOL_MAX_SIZE,
        DEFAULT_POOL_MIN_SIZE, MigrationCommand, MigrationDefaults, MigrationTarget,
        parse_arguments,
    };

    fn defaults() -> MigrationDefaults {
        MigrationDefaults {
            model: DEFAULT_MODEL.to_owned(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
            pool_min_size: DEFAULT_POOL_MIN_SIZE,
            pool_max_size: DEFAULT_POOL_MAX_SIZE,
        }
    }

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_sqlite_target_with_environment_defaults() {
        let command = parse_arguments(
            arguments(&["--source", "legacy.db", "--target-sqlite", "rust.db"]),
            defaults(),
        )
        .unwrap_or_else(|error| panic!("parse SQLite arguments: {error}"));
        let MigrationCommand::Run(options) = command else {
            panic!("expected migration command");
        };
        assert_eq!(options.source, PathBuf::from("legacy.db"));
        assert_eq!(
            options.target,
            MigrationTarget::Sqlite(PathBuf::from("rust.db"))
        );
        assert_eq!(options.model, DEFAULT_MODEL);
        assert_eq!(options.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(options.chunk_overlap, DEFAULT_CHUNK_OVERLAP);
    }

    #[test]
    fn parses_pgvector_target_and_explicit_overrides() {
        let command = parse_arguments(
            arguments(&[
                "--source",
                "legacy.db",
                "--target-pgvector",
                "postgres://db/documents",
                "--model",
                "ollama:nomic-embed-text",
                "--chunk-size",
                "1000",
                "--chunk-overlap",
                "100",
                "--pool-min-size",
                "2",
                "--pool-max-size",
                "20",
            ]),
            defaults(),
        )
        .unwrap_or_else(|error| panic!("parse pgvector arguments: {error}"));
        let MigrationCommand::Run(options) = command else {
            panic!("expected migration command");
        };
        assert_eq!(
            options.target,
            MigrationTarget::PgVector("postgres://db/documents".to_owned())
        );
        assert_eq!(options.model, "ollama:nomic-embed-text");
        assert_eq!(options.chunk_size, 1000);
        assert_eq!(options.chunk_overlap, 100);
        assert_eq!(options.pool_min_size, 2);
        assert_eq!(options.pool_max_size, 20);
    }

    #[test]
    fn help_does_not_require_migration_arguments() {
        assert!(matches!(
            parse_arguments(arguments(&["--help"]), defaults())
                .unwrap_or_else(|error| panic!("parse help: {error}")),
            MigrationCommand::Help
        ));
    }

    #[test]
    fn rejects_missing_conflicting_duplicate_and_unknown_options() {
        let cases = [
            (vec!["--target-sqlite", "rust.db"], "--source is required"),
            (
                vec!["--source", "legacy.db"],
                "exactly one of --target-sqlite or --target-pgvector is required",
            ),
            (
                vec![
                    "--source",
                    "legacy.db",
                    "--target-sqlite",
                    "rust.db",
                    "--target-pgvector",
                    "postgres://db/documents",
                ],
                "mutually exclusive",
            ),
            (
                vec![
                    "--source",
                    "legacy.db",
                    "--source",
                    "second.db",
                    "--target-sqlite",
                    "rust.db",
                ],
                "--source may only be specified once",
            ),
            (vec!["--unknown"], "unknown option"),
        ];
        for (values, expected) in cases {
            let error = match parse_arguments(arguments(&values), defaults()) {
                Ok(_) => panic!("invalid arguments unexpectedly parsed: {values:?}"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }
}
