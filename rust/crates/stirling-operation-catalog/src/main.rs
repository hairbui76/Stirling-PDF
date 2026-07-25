use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use stirling_operation_catalog::generate_catalog_json;

#[derive(Debug)]
struct Arguments {
    spec: PathBuf,
    output: PathBuf,
    check: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments(env::args().skip(1))?;
    let openapi = fs::read_to_string(&arguments.spec).map_err(|error| {
        format!(
            "cannot read OpenAPI spec {}: {error}",
            arguments.spec.display()
        )
    })?;
    let generated = generate_catalog_json(&openapi)?;

    if arguments.check {
        let committed = fs::read_to_string(&arguments.output).map_err(|error| {
            format!(
                "cannot read generated catalog {}: {error}",
                arguments.output.display()
            )
        })?;
        if committed != generated {
            return Err(format!(
                "{} is stale; run `task engine:tool-models`",
                arguments.output.display()
            )
            .into());
        }
        println!(
            "Operation catalog is current: {}",
            arguments.output.display()
        );
        return Ok(());
    }

    fs::write(&arguments.output, generated).map_err(|error| {
        format!(
            "cannot write operation catalog {}: {error}",
            arguments.output.display()
        )
    })?;
    println!("Wrote operation catalog to {}", arguments.output.display());
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Arguments, String> {
    let mut spec = None;
    let mut output = None;
    let mut check = false;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--spec" => spec = Some(next_value(&mut arguments, "--spec")?),
            "--output" => output = Some(next_value(&mut arguments, "--output")?),
            "--check" => check = true,
            _ => return Err(format!("unknown argument: {argument}\n{USAGE}")),
        }
    }
    Ok(Arguments {
        spec: spec.ok_or_else(|| format!("missing --spec\n{USAGE}"))?,
        output: output.ok_or_else(|| format!("missing --output\n{USAGE}"))?,
        check,
    })
}

fn next_value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf, String> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value for {flag}\n{USAGE}"))
}

const USAGE: &str = "usage: stirling-operation-catalog --spec <SwaggerDoc.json> --output <operation_catalog.json> [--check]";

#[cfg(test)]
mod tests {
    use super::parse_arguments;

    #[test]
    fn parses_required_paths_and_check_mode() -> Result<(), Box<dyn std::error::Error>> {
        let arguments = parse_arguments([
            "--spec".to_owned(),
            "spec.json".to_owned(),
            "--output".to_owned(),
            "catalog.json".to_owned(),
            "--check".to_owned(),
        ])?;
        assert_eq!(arguments.spec.to_string_lossy(), "spec.json");
        assert_eq!(arguments.output.to_string_lossy(), "catalog.json");
        assert!(arguments.check);
        Ok(())
    }

    #[test]
    fn rejects_unknown_arguments() {
        let error = parse_arguments(["--unknown".to_owned()]);
        assert!(error.is_err());
    }
}
