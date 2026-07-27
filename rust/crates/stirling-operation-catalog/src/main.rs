use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use stirling_operation_catalog::{generate_catalog_json, generate_mcp_supplement_json};

#[derive(Debug)]
struct Arguments {
    spec: PathBuf,
    output: PathBuf,
    mcp_supplement: Option<PathBuf>,
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
    write_or_check(
        &arguments,
        &arguments.output,
        generate_catalog_json(&openapi)?,
    )?;
    if let Some(supplement_path) = &arguments.mcp_supplement {
        write_or_check(
            &arguments,
            supplement_path,
            generate_mcp_supplement_json(&openapi)?,
        )?;
    }
    Ok(())
}

fn write_or_check(
    arguments: &Arguments,
    output: &PathBuf,
    generated: String,
) -> Result<(), Box<dyn Error>> {
    if arguments.check {
        let committed = fs::read_to_string(output).map_err(|error| {
            format!(
                "cannot read generated catalog {}: {error}",
                output.display()
            )
        })?;
        if committed != generated {
            return Err(format!(
                "{} is stale; run `task engine:tool-models`",
                output.display()
            )
            .into());
        }
        println!("Operation catalog is current: {}", output.display());
        return Ok(());
    }
    fs::write(output, generated).map_err(|error| {
        format!(
            "cannot write operation catalog {}: {error}",
            output.display()
        )
    })?;
    println!("Wrote operation catalog to {}", output.display());
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Arguments, String> {
    let mut spec = None;
    let mut output = None;
    let mut mcp_supplement = None;
    let mut check = false;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--spec" => spec = Some(next_value(&mut arguments, "--spec")?),
            "--output" => output = Some(next_value(&mut arguments, "--output")?),
            "--mcp-supplement" => {
                mcp_supplement = Some(next_value(&mut arguments, "--mcp-supplement")?);
            }
            "--check" => check = true,
            _ => return Err(format!("unknown argument: {argument}\n{USAGE}")),
        }
    }
    Ok(Arguments {
        spec: spec.ok_or_else(|| format!("missing --spec\n{USAGE}"))?,
        output: output.ok_or_else(|| format!("missing --output\n{USAGE}"))?,
        mcp_supplement,
        check,
    })
}

fn next_value(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf, String> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value for {flag}\n{USAGE}"))
}

const USAGE: &str = "usage: stirling-operation-catalog --spec <SwaggerDoc.json> --output <operation_catalog.json> [--mcp-supplement <mcp_operation_supplement.json>] [--check]";

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
            "--mcp-supplement".to_owned(),
            "supplement.json".to_owned(),
            "--check".to_owned(),
        ])?;
        assert_eq!(arguments.spec.to_string_lossy(), "spec.json");
        assert_eq!(arguments.output.to_string_lossy(), "catalog.json");
        assert_eq!(
            arguments
                .mcp_supplement
                .as_deref()
                .map(|path| path.to_string_lossy().into_owned()),
            Some("supplement.json".to_owned())
        );
        assert!(arguments.check);
        Ok(())
    }

    #[test]
    fn supplement_output_is_optional() -> Result<(), Box<dyn std::error::Error>> {
        let arguments = parse_arguments([
            "--spec".to_owned(),
            "spec.json".to_owned(),
            "--output".to_owned(),
            "catalog.json".to_owned(),
        ])?;
        assert!(arguments.mcp_supplement.is_none());
        Ok(())
    }

    #[test]
    fn rejects_unknown_arguments() {
        let error = parse_arguments(["--unknown".to_owned()]);
        assert!(error.is_err());
    }
}
