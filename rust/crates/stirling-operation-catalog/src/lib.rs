//! Deterministic AI operation-catalog generation from Stirling PDF `OpenAPI`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;
use serde_json::{Map, Value};

const ALLOWED_PATH_PREFIXES: [&str; 4] = [
    "/api/v1/general/",
    "/api/v1/misc/",
    "/api/v1/security/",
    "/api/v1/convert/",
];

const EXCLUDED_PATHS: [&str; 13] = [
    "/api/v1/security/cert-sign",
    "/api/v1/convert/pdf/text-editor",
    "/api/v1/convert/text-editor/pdf",
    "/api/v1/security/get-info-on-pdf",
    "/api/v1/security/verify-pdf",
    "/api/v1/security/validate-signature",
    "/api/v1/misc/list-attachments",
    "/api/v1/misc/show-javascript",
    "/api/v1/misc/decompress-pdf",
    "/api/v1/general/extract-bookmarks",
    "/api/v1/misc/add-image",
    "/api/v1/misc/add-attachments",
    "/api/v1/general/overlay-pdfs",
];

const BASE_CLASS_FIELDS: [&str; 2] = ["fileInput", "fileId"];
const COMPONENT_REF_PREFIX: &str = "#/components/schemas/";

/// A failure to parse or translate an `OpenAPI` operation catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError(String);

impl CatalogError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for CatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CatalogError {}

#[derive(Debug, Deserialize)]
struct OpenApiDocument {
    #[serde(default)]
    paths: BTreeMap<String, PathItem>,
    #[serde(default)]
    components: Components,
}

#[derive(Debug, Default, Deserialize)]
struct Components {
    #[serde(default)]
    schemas: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
struct PathItem {
    post: Option<Operation>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Operation {
    request_body: Option<RequestBody>,
    #[serde(default)]
    parameters: Vec<Parameter>,
}

#[derive(Debug, Default, Deserialize)]
struct RequestBody {
    #[serde(default)]
    content: BTreeMap<String, MediaType>,
}

#[derive(Debug, Default, Deserialize)]
struct MediaType {
    schema: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct Parameter {
    name: Option<String>,
    #[serde(rename = "in")]
    location: Option<String>,
    description: Option<String>,
    schema: Option<Value>,
}

/// Generate the self-contained operation catalog consumed by the Rust AI engine.
///
/// Endpoint selection and parameter filtering intentionally match the retained
/// legacy generator. The emitted schemas retain the Java API's camel-case wire
/// names, with acronym normalization matching the old Pydantic alias generator.
///
/// # Errors
///
/// Returns an error when the input is not valid JSON, a required component is
/// missing, or the supported local-reference/schema shapes are malformed.
pub fn generate_catalog(openapi_json: &str) -> Result<BTreeMap<String, Value>, CatalogError> {
    let document: OpenApiDocument = serde_json::from_str(openapi_json)
        .map_err(|error| CatalogError::new(format!("invalid OpenAPI JSON: {error}")))?;
    CatalogGenerator::new(document).generate(is_operation_path)
}

/// Generate the MCP supplement: the flat `POST` operations that
/// [`generate_catalog`] deliberately excludes for AI-engine reasons but that
/// Java's `McpToolCatalog` (which has no exclusion list) still indexes into
/// its category-tool enums, e.g. `cert-sign` or `overlay-pdfs`. Schemas are
/// produced with exactly the same normalization as the AI catalog.
///
/// # Errors
///
/// Returns an error when the input is not valid JSON, a required component is
/// missing, or the supported local-reference/schema shapes are malformed.
pub fn generate_mcp_supplement(
    openapi_json: &str,
) -> Result<BTreeMap<String, Value>, CatalogError> {
    let document: OpenApiDocument = serde_json::from_str(openapi_json)
        .map_err(|error| CatalogError::new(format!("invalid OpenAPI JSON: {error}")))?;
    CatalogGenerator::new(document).generate(is_mcp_supplement_path)
}

/// Generate stable, pretty-printed catalog bytes with one trailing newline.
///
/// # Errors
///
/// Returns an error when catalog generation or JSON serialization fails.
pub fn generate_catalog_json(openapi_json: &str) -> Result<String, CatalogError> {
    stable_json(&generate_catalog(openapi_json)?)
}

/// Generate stable, pretty-printed MCP supplement bytes with one trailing
/// newline.
///
/// # Errors
///
/// Returns an error when supplement generation or JSON serialization fails.
pub fn generate_mcp_supplement_json(openapi_json: &str) -> Result<String, CatalogError> {
    stable_json(&generate_mcp_supplement(openapi_json)?)
}

fn stable_json(catalog: &BTreeMap<String, Value>) -> Result<String, CatalogError> {
    let mut output = serde_json::to_string_pretty(catalog).map_err(|error| {
        CatalogError::new(format!("cannot serialize operation catalog: {error}"))
    })?;
    output.push('\n');
    Ok(output)
}

struct CatalogGenerator {
    document: OpenApiDocument,
    used_titles: BTreeSet<String>,
}

impl CatalogGenerator {
    fn new(document: OpenApiDocument) -> Self {
        Self {
            document,
            used_titles: BTreeSet::new(),
        }
    }

    fn generate(
        mut self,
        include_path: fn(&str) -> bool,
    ) -> Result<BTreeMap<String, Value>, CatalogError> {
        let paths = std::mem::take(&mut self.document.paths);
        let mut catalog = BTreeMap::new();
        for (path, path_item) in paths {
            if !include_path(&path) {
                continue;
            }
            let schema = self.operation_schema(&path, &path_item)?;
            catalog.insert(path, schema);
        }
        Ok(catalog)
    }

    fn operation_schema(
        &mut self,
        path: &str,
        path_item: &PathItem,
    ) -> Result<Value, CatalogError> {
        let body_schema = path_item
            .post
            .as_ref()
            .and_then(|operation| operation.request_body.as_ref())
            .and_then(request_schema)
            .map(|schema| self.resolve_schema(schema))
            .transpose()?
            .unwrap_or_else(empty_object_schema);

        let mut properties = self.query_properties(path_item)?;
        if let Some(body_properties) = body_schema.get("properties").and_then(Value::as_object) {
            for (name, schema) in body_properties {
                properties.insert(name.clone(), schema.clone());
            }
        }
        let mut filtered_properties = BTreeMap::new();
        for (name, schema) in properties {
            let resolved = self.resolve_schema(&schema)?;
            if !BASE_CLASS_FIELDS.contains(&name.as_str()) && !is_binary_schema(&resolved) {
                filtered_properties.insert(name, schema);
            }
        }

        let body_required = body_schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();

        let mut referenced_components = BTreeSet::new();
        let mut normalized_properties = BTreeMap::new();
        let mut normalized_required = Vec::new();
        for (name, schema) in filtered_properties {
            let resolved = self.resolve_schema(&schema)?;
            let required =
                body_required.contains(name.as_str()) && resolved.get("default").is_none();
            let alias = canonical_wire_name(&name);
            if normalized_properties.contains_key(&alias) {
                return Err(CatalogError::new(format!(
                    "parameter aliases collide at {path}: {name} becomes {alias}"
                )));
            }
            normalized_properties.insert(
                alias.clone(),
                self.normalize_schema(&schema, !required, &mut referenced_components)?,
            );
            if required {
                normalized_required.push(Value::String(alias));
            }
        }

        let mut object = Map::new();
        object.insert("additionalProperties".to_owned(), Value::Bool(false));
        if let Some(description) = body_schema.get("description").and_then(Value::as_str) {
            object.insert(
                "description".to_owned(),
                Value::String(description.to_owned()),
            );
        }
        object.insert("properties".to_owned(), value_object(normalized_properties));
        if !normalized_required.is_empty() {
            object.insert("required".to_owned(), Value::Array(normalized_required));
        }
        object.insert(
            "title".to_owned(),
            Value::String(self.unique_operation_title(path)),
        );
        object.insert("type".to_owned(), Value::String("object".to_owned()));

        let definitions = self.component_definitions(&mut referenced_components)?;
        if !definitions.is_empty() {
            object.insert("$defs".to_owned(), value_object(definitions));
        }
        Ok(Value::Object(object))
    }

    fn query_properties(
        &self,
        path_item: &PathItem,
    ) -> Result<BTreeMap<String, Value>, CatalogError> {
        let mut properties = BTreeMap::new();
        let Some(post) = path_item.post.as_ref() else {
            return Ok(properties);
        };
        for parameter in &post.parameters {
            if parameter.location.as_deref() != Some("query") {
                continue;
            }
            let (Some(name), Some(schema)) = (&parameter.name, &parameter.schema) else {
                continue;
            };
            let mut schema = self.resolve_schema(schema)?;
            if schema.get("description").is_none()
                && let Some(description) = &parameter.description
                && let Some(object) = schema.as_object_mut()
            {
                object.insert("description".to_owned(), Value::String(description.clone()));
            }
            properties.insert(name.clone(), schema);
        }
        Ok(properties)
    }

    fn resolve_schema(&self, schema: &Value) -> Result<Value, CatalogError> {
        let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
            return Ok(schema.clone());
        };
        let Some(name) = reference.strip_prefix(COMPONENT_REF_PREFIX) else {
            return Err(CatalogError::new(format!(
                "unsupported external schema reference: {reference}"
            )));
        };
        self.document
            .components
            .schemas
            .get(name)
            .cloned()
            .ok_or_else(|| CatalogError::new(format!("missing component schema: {name}")))
    }

    fn normalize_schema(
        &self,
        schema: &Value,
        optional: bool,
        referenced_components: &mut BTreeSet<String>,
    ) -> Result<Value, CatalogError> {
        let mut normalized = self.normalize_schema_inner(schema, referenced_components)?;
        let nullable = schema
            .get("nullable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || schema.get("default").is_some_and(Value::is_null)
            || (optional && schema.get("default").is_none());
        if nullable && !schema_accepts_null(&normalized) {
            let default = normalized
                .as_object_mut()
                .and_then(|object| object.remove("default"));
            let mut wrapper = Map::new();
            wrapper.insert(
                "anyOf".to_owned(),
                Value::Array(vec![normalized, null_schema()]),
            );
            wrapper.insert("default".to_owned(), default.unwrap_or(Value::Null));
            normalized = Value::Object(wrapper);
        }
        Ok(normalized)
    }

    fn normalize_schema_inner(
        &self,
        schema: &Value,
        referenced_components: &mut BTreeSet<String>,
    ) -> Result<Value, CatalogError> {
        let Some(source) = schema.as_object() else {
            return Ok(schema.clone());
        };
        let mut normalized = BTreeMap::new();
        for (key, value) in source {
            match key.as_str() {
                "nullable" => {}
                "$ref" => {
                    normalized.insert(
                        "$ref".to_owned(),
                        normalize_reference(value, referenced_components)?,
                    );
                }
                "properties" => {
                    normalized.insert(
                        "properties".to_owned(),
                        self.normalize_properties(source, value, referenced_components)?,
                    );
                }
                "required" => {
                    if let Some(required) = normalize_required(source, value)? {
                        normalized.insert("required".to_owned(), required);
                    }
                }
                "items" => {
                    let mut items = self.normalize_schema(value, false, referenced_components)?;
                    if let Some(object) = items.as_object_mut() {
                        object.remove("default");
                    }
                    normalized.insert(key.clone(), items);
                }
                "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                    normalized.insert(
                        key.clone(),
                        self.normalize_variants(key, value, referenced_components)?,
                    );
                }
                "format"
                    if matches!(value.as_str(), Some("int32" | "int64" | "float" | "double")) => {}
                "pattern" if source.contains_key("enum") => {}
                "exclusiveMinimum" | "exclusiveMaximum" if value == &Value::Bool(false) => {}
                _ => {
                    normalized.insert(key.clone(), value.clone());
                }
            }
        }

        if source.get("type").and_then(Value::as_str) == Some("object")
            && source.contains_key("properties")
            && !source.contains_key("additionalProperties")
        {
            normalized.insert("additionalProperties".to_owned(), Value::Bool(false));
        }
        if source.get("type").and_then(Value::as_str) == Some("number")
            && source
                .get("enum")
                .and_then(Value::as_array)
                .is_some_and(|values| {
                    !values.is_empty()
                        && values.iter().all(|value| {
                            value
                                .as_number()
                                .is_some_and(|number| number.is_i64() || number.is_u64())
                        })
                })
        {
            normalized.insert("type".to_owned(), Value::String("integer".to_owned()));
        }
        Ok(value_object(normalized))
    }

    fn normalize_properties(
        &self,
        source: &Map<String, Value>,
        value: &Value,
        referenced_components: &mut BTreeSet<String>,
    ) -> Result<Value, CatalogError> {
        let property_map = value
            .as_object()
            .ok_or_else(|| CatalogError::new("schema properties must contain an object"))?;
        let required = source
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        let mut properties = BTreeMap::new();
        for (name, property_schema) in property_map {
            let alias = canonical_wire_name(name);
            if properties.contains_key(&alias) {
                return Err(CatalogError::new(format!(
                    "component parameter aliases collide: {name} becomes {alias}"
                )));
            }
            let is_required =
                required.contains(name.as_str()) && property_schema.get("default").is_none();
            properties.insert(
                alias,
                self.normalize_schema(property_schema, !is_required, referenced_components)?,
            );
        }
        Ok(value_object(properties))
    }

    fn normalize_variants(
        &self,
        keyword: &str,
        value: &Value,
        referenced_components: &mut BTreeSet<String>,
    ) -> Result<Value, CatalogError> {
        let variants = value
            .as_array()
            .ok_or_else(|| CatalogError::new(format!("schema {keyword} must contain an array")))?;
        variants
            .iter()
            .map(|variant| self.normalize_schema(variant, false, referenced_components))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array)
    }

    fn component_definitions(
        &self,
        referenced_components: &mut BTreeSet<String>,
    ) -> Result<BTreeMap<String, Value>, CatalogError> {
        let mut definitions = BTreeMap::new();
        while let Some(name) = referenced_components.pop_first() {
            if definitions.contains_key(&name) {
                continue;
            }
            let schema =
                self.document.components.schemas.get(&name).ok_or_else(|| {
                    CatalogError::new(format!("missing component schema: {name}"))
                })?;
            let mut normalized = self.normalize_schema(schema, false, referenced_components)?;
            if normalized.get("title").is_none()
                && let Some(object) = normalized.as_object_mut()
            {
                object.insert("title".to_owned(), Value::String(name.clone()));
            }
            definitions.insert(name, normalized);
        }
        Ok(definitions)
    }

    fn unique_operation_title(&mut self, path: &str) -> String {
        let base = operation_title(path);
        if self.used_titles.insert(base.clone()) {
            return base;
        }
        for suffix in 2_u32.. {
            let candidate = format!("{base}{suffix}");
            if self.used_titles.insert(candidate.clone()) {
                return candidate;
            }
        }
        unreachable!("an operation title suffix is always available")
    }
}

fn request_schema(request_body: &RequestBody) -> Option<&Value> {
    ["multipart/form-data", "application/json"]
        .into_iter()
        .find_map(|media_type| {
            request_body
                .content
                .get(media_type)
                .and_then(|media| media.schema.as_ref())
        })
}

fn is_operation_path(path: &str) -> bool {
    !path.contains('{')
        && ALLOWED_PATH_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
        && !EXCLUDED_PATHS
            .iter()
            .any(|excluded| path == *excluded || path.starts_with(&format!("{excluded}/")))
}

/// An excluded path Java's MCP catalog still exposes: it must carry a flat
/// tail (no nesting, no path variables), because Java's `extractOpId` derives
/// op ids only from flat tails. The nested convert text-editor exclusions are
/// therefore never part of the supplement.
fn is_mcp_supplement_path(path: &str) -> bool {
    EXCLUDED_PATHS.contains(&path)
        && ALLOWED_PATH_PREFIXES.iter().any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|tail| !tail.is_empty() && !tail.contains('/') && !tail.contains('{'))
        })
}

fn is_binary_schema(schema: &Value) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("string")
        && schema.get("format").and_then(Value::as_str) == Some("binary")
}

fn empty_object_schema() -> Value {
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String("object".to_owned()));
    object.insert("properties".to_owned(), Value::Object(Map::new()));
    Value::Object(object)
}

fn null_schema() -> Value {
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String("null".to_owned()));
    Value::Object(object)
}

fn normalize_reference(
    value: &Value,
    referenced_components: &mut BTreeSet<String>,
) -> Result<Value, CatalogError> {
    let reference = value
        .as_str()
        .ok_or_else(|| CatalogError::new("schema $ref must contain a string"))?;
    let name = reference
        .strip_prefix(COMPONENT_REF_PREFIX)
        .ok_or_else(|| {
            CatalogError::new(format!(
                "unsupported external schema reference: {reference}"
            ))
        })?;
    referenced_components.insert(name.to_owned());
    Ok(Value::String(format!("#/$defs/{name}")))
}

fn normalize_required(
    source: &Map<String, Value>,
    value: &Value,
) -> Result<Option<Value>, CatalogError> {
    let aliases = value
        .as_array()
        .ok_or_else(|| CatalogError::new("schema required must contain an array"))?
        .iter()
        .filter_map(Value::as_str)
        .filter(|name| {
            source
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(*name))
                .is_some_and(|property| property.get("default").is_none())
        })
        .map(canonical_wire_name)
        .map(Value::String)
        .collect::<Vec<_>>();
    Ok((!aliases.is_empty()).then_some(Value::Array(aliases)))
}

fn schema_accepts_null(schema: &Value) -> bool {
    if schema.get("type").and_then(Value::as_str) == Some("null") {
        return true;
    }
    ["anyOf", "oneOf"]
        .into_iter()
        .filter_map(|keyword| schema.get(keyword).and_then(Value::as_array))
        .flatten()
        .any(schema_accepts_null)
}

fn value_object(values: BTreeMap<String, Value>) -> Value {
    Value::Object(values.into_iter().collect())
}

fn canonical_wire_name(name: &str) -> String {
    let chars = name.chars().collect::<Vec<_>>();
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, character) in chars.iter().copied().enumerate() {
        let previous = index
            .checked_sub(1)
            .and_then(|value| chars.get(value))
            .copied();
        let next = chars.get(index + 1).copied();
        let starts_word = character.is_ascii_uppercase()
            && index > 0
            && (previous.is_some_and(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
                || next.is_some_and(|value| value.is_ascii_lowercase()));
        if starts_word && !snake.ends_with('_') {
            snake.push('_');
        }
        snake.push(character.to_ascii_lowercase());
    }

    let mut camel = String::with_capacity(snake.len());
    let mut uppercase_next = false;
    for character in snake.chars() {
        if character == '_' {
            uppercase_next = !camel.is_empty();
        } else if uppercase_next {
            camel.push(character.to_ascii_uppercase());
            uppercase_next = false;
        } else {
            camel.push(character);
        }
    }
    camel
}

fn operation_title(path: &str) -> String {
    let segments = path.trim_end_matches('/').split('/').collect::<Vec<_>>();
    let name = if path.contains("/api/v1/convert/") && segments.len() >= 6 {
        format!(
            "{}-to-{}",
            segments[segments.len() - 2],
            segments[segments.len() - 1]
        )
    } else {
        segments.last().copied().unwrap_or_default().to_owned()
    };
    let mut title = name.split('-').map(capitalize).collect::<String>();
    title.push_str("Params");
    title
}

fn capitalize(value: &str) -> String {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    let mut result = String::with_capacity(value.len());
    result.push(first.to_ascii_uppercase());
    result.extend(characters);
    result
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        canonical_wire_name, generate_catalog, generate_catalog_json, generate_mcp_supplement,
        generate_mcp_supplement_json,
    };

    const FIXTURE: &str = r##"
    {
      "openapi": "3.0.3",
      "paths": {
        "/api/v1/general/rotate-pdf": {
          "post": {
            "parameters": [
              {"in": "query", "name": "maxAttachmentSizeMB", "schema": {"type": "integer"}}
            ],
            "requestBody": {
              "content": {
                "multipart/form-data": {
                  "schema": {"$ref": "#/components/schemas/RotateRequest"}
                }
              }
            }
          }
        },
        "/api/v1/security/cert-sign": {
          "post": {
            "requestBody": {
              "content": {
                "multipart/form-data": {
                  "schema": {
                    "type": "object",
                    "properties": {
                      "fileInput": {"type": "string", "format": "binary"},
                      "certType": {"type": "string", "enum": ["PEM", "PKCS12"]}
                    }
                  }
                }
              }
            }
          }
        },
        "/api/v1/convert/pdf/text-editor": {"post": {}},
        "/api/v1/filter/not-an-agent-tool": {"post": {}}
      },
      "components": {
        "schemas": {
          "RotateRequest": {
            "type": "object",
            "required": ["fileInput", "angle", "convertPDFToImage", "mode"],
            "properties": {
              "fileInput": {"type": "string", "format": "binary"},
              "fileId": {"type": "string"},
              "angle": {"type": "integer", "format": "int32", "enum": [0, 90]},
              "convertPDFToImage": {"type": "boolean"},
              "mode": {"$ref": "#/components/schemas/Mode"},
              "quality": {"type": "number", "default": 0.8}
            }
          },
          "Mode": {"type": "string", "enum": ["fast", "exact"]}
        }
      }
    }
    "##;

    #[test]
    fn discovers_filters_and_normalizes_operations() -> Result<(), Box<dyn std::error::Error>> {
        let catalog = generate_catalog(FIXTURE)?;
        assert_eq!(catalog.len(), 1);
        let schema = catalog
            .get("/api/v1/general/rotate-pdf")
            .ok_or("rotate operation missing")?;
        assert_eq!(
            schema["required"],
            json!(["angle", "convertPdfToImage", "mode"])
        );
        assert_eq!(schema["properties"]["angle"]["format"], Value::Null);
        assert_eq!(schema["properties"]["quality"]["default"], json!(0.8));
        assert_eq!(
            schema["properties"]["maxAttachmentSizeMb"],
            json!({
                "anyOf": [{"type": "integer"}, {"type": "null"}],
                "default": null
            })
        );
        assert_eq!(schema["properties"]["mode"]["$ref"], "#/$defs/Mode");
        assert_eq!(schema["$defs"]["Mode"]["enum"], json!(["fast", "exact"]));
        assert!(schema["properties"].get("fileInput").is_none());
        assert!(schema["properties"].get("fileId").is_none());
        Ok(())
    }

    #[test]
    fn canonicalizes_acronyms_like_the_retained_pydantic_aliases() {
        assert_eq!(
            canonical_wire_name("convertPDFToImage"),
            "convertPdfToImage"
        );
        assert_eq!(
            canonical_wire_name("removeXMPMetadata"),
            "removeXmpMetadata"
        );
        assert_eq!(
            canonical_wire_name("maxAttachmentSizeMB"),
            "maxAttachmentSizeMb"
        );
        assert_eq!(canonical_wire_name("pageNumbers"), "pageNumbers");
    }

    #[test]
    fn mcp_supplement_contains_only_flat_excluded_paths() -> Result<(), Box<dyn std::error::Error>>
    {
        let supplement = generate_mcp_supplement(FIXTURE)?;
        assert_eq!(supplement.len(), 1);
        let schema = supplement
            .get("/api/v1/security/cert-sign")
            .ok_or("cert-sign missing from the MCP supplement")?;
        assert_eq!(schema["type"], "object");
        // Optional without a default, so the enum is wrapped in a nullable
        // anyOf exactly like the AI catalog's normalization does.
        assert_eq!(
            schema["properties"]["certType"]["anyOf"][0]["enum"],
            json!(["PEM", "PKCS12"])
        );
        assert!(schema["properties"].get("fileInput").is_none());
        // The AI catalog keeps excluding every one of these paths.
        assert!(
            generate_catalog(FIXTURE)?
                .keys()
                .all(|path| !supplement.contains_key(path))
        );
        Ok(())
    }

    #[test]
    fn serialization_is_stable_and_newline_terminated() -> Result<(), Box<dyn std::error::Error>> {
        let first = generate_catalog_json(FIXTURE)?;
        let second = generate_catalog_json(FIXTURE)?;
        assert_eq!(first, second);
        assert!(first.ends_with('\n'));
        let first_supplement = generate_mcp_supplement_json(FIXTURE)?;
        assert_eq!(first_supplement, generate_mcp_supplement_json(FIXTURE)?);
        assert!(first_supplement.ends_with('\n'));
        Ok(())
    }
}
