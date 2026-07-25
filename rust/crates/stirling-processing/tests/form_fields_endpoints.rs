use std::io::{Cursor, Read};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, dictionary};
use serde_json::{Value, json};
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn extracts_nested_fields_template_and_coordinates() -> Result<(), Box<dyn std::error::Error>>
{
    let pdf = form_pdf()?;
    let fields = post_json("/api/v1/form/fields", &pdf).await?;
    assert_eq!(
        fields,
        json!({
            "fields": [
                {
                    "name": "person.firstName",
                    "label": "First Name",
                    "type": "text",
                    "value": "Alice",
                    "required": true,
                    "pageIndex": 0,
                    "multiSelect": false,
                    "tooltip": "first-widget",
                    "pageOrder": 0
                },
                {
                    "name": "agree",
                    "label": "Accept terms",
                    "type": "checkbox",
                    "value": "Yes",
                    "options": ["Yes"],
                    "required": false,
                    "pageIndex": 0,
                    "multiSelect": false,
                    "pageOrder": 1
                },
                {
                    "name": "colors",
                    "label": "red",
                    "type": "listbox",
                    "value": "red,blue",
                    "options": ["red", "blue", "Red label", "Blue label"],
                    "required": false,
                    "pageIndex": 0,
                    "multiSelect": true,
                    "pageOrder": 2
                }
            ],
            "template": {
                "agree": true,
                "colors": [],
                "person.firstName": "Alice"
            }
        })
    );

    let coordinates = post_json("/api/v1/form/fields-with-coordinates", &pdf).await?;
    assert_eq!(coordinates.as_array().map(Vec::len), Some(3));
    assert_eq!(coordinates[0]["name"], "person.firstName");
    assert_eq!(coordinates[0]["readOnly"], true);
    assert_eq!(coordinates[0]["multiline"], true);
    assert_eq!(coordinates[0]["widgets"][0]["pageIndex"], 0);
    assert_eq!(coordinates[0]["widgets"][0]["x"], 20.0);
    assert_eq!(coordinates[0]["widgets"][0]["y"], 70.0);
    assert_eq!(coordinates[0]["widgets"][0]["width"], 100.0);
    assert_eq!(coordinates[0]["widgets"][0]["height"], 20.0);
    assert_eq!(coordinates[0]["widgets"][0]["fontSize"], 12.0);
    assert_eq!(coordinates[1]["name"], "colors");
    assert_eq!(
        coordinates[1]["displayOptions"],
        json!(["Red label", "Blue label"])
    );
    assert_eq!(coordinates[2]["name"], "agree");
    assert_eq!(coordinates[2]["widgets"][0]["exportValue"], "Yes");
    Ok(())
}

#[tokio::test]
async fn returns_empty_contract_for_pdf_without_acroform() -> Result<(), Box<dyn std::error::Error>>
{
    let pdf = plain_pdf()?;
    assert_eq!(
        post_json("/api/v1/form/fields", &pdf).await?,
        json!({ "fields": [], "template": {} })
    );
    assert_eq!(
        post_json("/api/v1/form/fields-with-coordinates", &pdf).await?,
        json!([])
    );
    Ok(())
}

#[tokio::test]
async fn exports_quoted_csv_and_applies_optional_values() -> Result<(), Box<dyn std::error::Error>>
{
    let pdf = form_pdf()?;
    let response = require_status(
        post_pdf_with_data(
            "/api/v1/form/extract-csv",
            &pdf,
            Some(r#"{"firstName":"A, \"quoted\"\nline","agree":"false"}"#),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/csv");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"form_extracted.csv\""
    );
    let csv = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert_eq!(
        csv,
        concat!(
            "\"Field Name\",\"Value\"\n",
            "\"person.firstName\",\"A, \"\"quoted\"\"\nline\"\n",
            "\"agree\",\"Off\"\n",
            "\"colors\",\"red,blue\"\n"
        )
    );
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_csv_override_json() -> Result<(), Box<dyn std::error::Error>> {
    let response =
        post_pdf_with_data("/api/v1/form/extract-csv", &form_pdf()?, Some("not-json")).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(body["path"], "/api/v1/form/extract-csv");
    Ok(())
}

#[tokio::test]
async fn exports_valid_xlsx_workbook() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_data(
            "/api/v1/form/extract-xlsx",
            &form_pdf()?,
            Some(r#"{"firstName":"X<&"}"#),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"form_extracted.xlsx\""
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut workbook = ZipArchive::new(Cursor::new(bytes))?;
    assert!(workbook.by_name("[Content_Types].xml").is_ok());
    let mut sheet = String::new();
    workbook
        .by_name("xl/worksheets/sheet1.xml")?
        .read_to_string(&mut sheet)?;
    assert!(sheet.contains("Field Name"));
    assert!(sheet.contains("person.firstName"));
    assert!(sheet.contains("X&lt;&amp;"));
    assert!(sheet.contains("red,blue"));
    let mut workbook_xml = String::new();
    workbook
        .by_name("xl/workbook.xml")?
        .read_to_string(&mut workbook_xml)?;
    assert!(workbook_xml.contains("Form Fields"));
    Ok(())
}

#[tokio::test]
async fn requires_java_multipart_field_name() -> Result<(), Box<dyn std::error::Error>> {
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/form/fields")
                .header(header::CONTENT_TYPE, "multipart/form-data; boundary=empty")
                .body(Body::from("--empty--\r\n"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(body["path"], "/api/v1/form/fields");
    assert_eq!(body["message"], "file is required");
    Ok(())
}

#[tokio::test]
async fn deletes_nested_and_root_fields_with_java_payload_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_part(
            "/api/v1/form/delete-fields",
            &form_pdf()?,
            Some((
                "names",
                r#"{"fields":[{"name":"person.firstName"},"agree"]}"#,
            )),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"form_updated.pdf\""
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    let page_id = document.get_pages()[&1];
    assert_eq!(
        document
            .get_dictionary(page_id)?
            .get(b"Annots")?
            .as_array()?
            .len(),
        1
    );

    let fields = post_json("/api/v1/form/fields", &bytes).await?;
    assert_eq!(fields["fields"].as_array().map(Vec::len), Some(1));
    assert_eq!(fields["fields"][0]["name"], "colors");
    assert_eq!(fields["template"], json!({ "colors": [] }));
    Ok(())
}

#[tokio::test]
async fn accepts_legacy_delete_name_shapes_and_removes_acroform()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_part(
            "/api/v1/form/delete-fields",
            &form_pdf()?,
            Some((
                "names",
                r#"[{"targetName":"person"},{"field":{"fieldName":"agree"}},"colors","colors"]"#,
            )),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    let page_id = document.get_pages()[&1];
    assert!(document.get_dictionary(page_id)?.get(b"Annots").is_err());
    assert!(document.catalog()?.get(b"AcroForm").is_err());
    assert_eq!(
        post_json("/api/v1/form/fields", &bytes).await?,
        json!({ "fields": [], "template": {} })
    );
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_or_empty_delete_names() -> Result<(), Box<dyn std::error::Error>> {
    for payload in [None, Some("not-json"), Some(r#"{"fields":[]}"#)] {
        let response = post_pdf_with_part(
            "/api/v1/form/delete-fields",
            &form_pdf()?,
            payload.map(|payload| ("names", payload)),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(body["path"], "/api/v1/form/delete-fields");
    }
    Ok(())
}

#[tokio::test]
async fn fills_text_checkbox_and_multi_choice_values() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_part(
            "/api/v1/form/fill",
            &form_pdf()?,
            Some((
                "data",
                r#"{"person.firstName":"Béatrice","agree":true,"colors":"RED, blue"}"#,
            )),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"form_filled.pdf\""
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let fields = post_json("/api/v1/form/fields", &bytes).await?;
    assert_eq!(fields["fields"][0]["value"], "Béatrice");
    assert_eq!(fields["fields"][1]["value"], "Yes");
    assert_eq!(fields["fields"][2]["value"], "red,blue");
    assert_eq!(
        fields["template"],
        json!({
            "agree": true,
            "colors": [],
            "person.firstName": "Béatrice"
        })
    );
    Ok(())
}

#[tokio::test]
async fn fills_from_field_definition_payload_and_rejects_strict_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_part(
            "/api/v1/form/fill",
            &form_pdf()?,
            Some((
                "data",
                r#"{"fields":[{"name":"person.firstName","value":42},{"targetName":"colors","value":["Red","Blue"]}]}"#,
            )),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let fields = post_json("/api/v1/form/fields", &bytes).await?;
    assert_eq!(fields["fields"][0]["value"], "42");
    assert_eq!(fields["fields"][2]["value"], "red,blue");

    for (pdf, data) in [
        (plain_pdf()?, None),
        (
            form_pdf_without_choice_options()?,
            Some(r#"{"colors":"red"}"#),
        ),
    ] {
        let response =
            post_pdf_with_part("/api/v1/form/fill", &pdf, data.map(|data| ("data", data))).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(body["path"], "/api/v1/form/fill");
    }
    Ok(())
}

#[tokio::test]
async fn validates_fill_json_and_optionally_flattens_with_pdfium()
-> Result<(), Box<dyn std::error::Error>> {
    for (name, value) in [("data", "not-json"), ("flatten", "sometimes")] {
        let response =
            post_pdf_with_part("/api/v1/form/fill", &form_pdf()?, Some((name, value))).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let response = post_pdf_with_parts(
        "/api/v1/form/fill",
        &form_pdf()?,
        &[
            ("data", r#"{"person.firstName":"Flattened"}"#),
            ("flatten", "true"),
        ],
    )
    .await?;
    if std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some() {
        let response = require_status(response, StatusCode::OK).await?;
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let document = Document::load_mem(&bytes)?;
        let page_id = document.get_pages()[&1];
        let widget_count = document
            .get_dictionary(page_id)?
            .get(b"Annots")
            .ok()
            .and_then(|annots| document.dereference(annots).ok())
            .and_then(|(_, annots)| annots.as_array().ok())
            .map_or(0, |annots| {
                annots
                    .iter()
                    .filter(|annotation| {
                        document
                            .dereference(annotation)
                            .ok()
                            .and_then(|(_, annotation)| annotation.as_dict().ok())
                            .and_then(|annotation| annotation.get(b"Subtype").ok())
                            .is_some_and(|subtype| {
                                subtype.as_name().is_ok_and(|name| name == b"Widget")
                            })
                    })
                    .count()
            });
        assert_eq!(widget_count, 0);
        assert!(document.objects.values().any(|object| {
            object.as_stream().is_ok_and(|stream| {
                stream
                    .decompressed_content()
                    .unwrap_or_else(|_| stream.content.clone())
                    .windows(b"Flattened".len())
                    .any(|window| window == b"Flattened")
            })
        }));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

#[tokio::test]
async fn modifies_field_properties_options_and_collision_safe_names()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_part(
            "/api/v1/form/modify-fields",
            &form_pdf()?,
            Some((
                "updates",
                r#"[
                    {"targetName":"person.firstName","name":"colors","label":"Renamed","required":false,"defaultValue":"Updated","tooltip":"Tip"},
                    {"targetName":"colors","options":["X",null," ","Y"],"multiSelect":false,"defaultValue":"Y","tooltip":"Choose"}
                ]"#,
            )),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"form_updated.pdf\""
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let fields = post_json("/api/v1/form/fields", &bytes).await?;
    assert_eq!(fields["fields"][0]["name"], "person.colors_1");
    assert_eq!(fields["fields"][0]["label"], "Renamed");
    assert_eq!(fields["fields"][0]["required"], false);
    assert_eq!(fields["fields"][0]["value"], "Updated");
    assert_eq!(fields["fields"][2]["name"], "colors");
    assert_eq!(fields["fields"][2]["options"], json!(["X", "Y"]));
    assert_eq!(fields["fields"][2]["multiSelect"], false);
    assert_eq!(fields["fields"][2]["value"], "Y");
    Ok(())
}

#[tokio::test]
async fn changes_field_type_with_default_value_and_appearance()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf_with_part(
            "/api/v1/form/modify-fields",
            &form_pdf()?,
            Some((
                "updates",
                r#"[{"targetName":"agree","name":"picker","label":"Pick one","type":"COMBOBOX","required":true,"options":["One","Two"],"defaultValue":"two","tooltip":"Choose one"}]"#,
            )),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let fields = post_json("/api/v1/form/fields", &bytes).await?;
    assert_eq!(fields["fields"][1]["name"], "picker");
    assert_eq!(fields["fields"][1]["label"], "Pick one");
    assert_eq!(fields["fields"][1]["type"], "combobox");
    assert_eq!(fields["fields"][1]["required"], true);
    assert_eq!(fields["fields"][1]["options"], json!(["One", "Two"]));
    assert_eq!(fields["fields"][1]["value"], "Two");
    Ok(())
}

#[tokio::test]
async fn validates_modify_payload_and_keeps_no_form_or_unsupported_types()
-> Result<(), Box<dyn std::error::Error>> {
    for payload in [None, Some("not-json"), Some("[]")] {
        let response = post_pdf_with_part(
            "/api/v1/form/modify-fields",
            &form_pdf()?,
            payload.map(|payload| ("updates", payload)),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let no_form = require_status(
        post_pdf_with_part(
            "/api/v1/form/modify-fields",
            &plain_pdf()?,
            Some(("updates", r#"[{"targetName":"missing","name":"new"}]"#)),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let no_form = to_bytes(no_form.into_body(), usize::MAX).await?;
    assert_eq!(
        post_json("/api/v1/form/fields", &no_form).await?,
        json!({ "fields": [], "template": {} })
    );

    let unsupported = require_status(
        post_pdf_with_part(
            "/api/v1/form/modify-fields",
            &form_pdf()?,
            Some(("updates", r#"[{"targetName":"agree","type":"bogus"}]"#)),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let unsupported = to_bytes(unsupported.into_body(), usize::MAX).await?;
    let fields = post_json("/api/v1/form/fields", &unsupported).await?;
    assert_eq!(fields["fields"][1]["type"], "checkbox");
    assert_eq!(fields["fields"][1]["name"], "agree");
    Ok(())
}

async fn post_json(path: &str, pdf: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let response = require_status(post_pdf(path, pdf).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX).await?,
    )?)
}

async fn post_pdf(path: &str, pdf: &[u8]) -> Result<Response, Box<dyn std::error::Error>> {
    post_pdf_with_part(path, pdf, None).await
}

async fn post_pdf_with_data(
    path: &str,
    pdf: &[u8],
    data: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    post_pdf_with_part(path, pdf, data.map(|data| ("data", data))).await
}

async fn post_pdf_with_part(
    path: &str,
    pdf: &[u8],
    extra: Option<(&str, &str)>,
) -> Result<Response, Box<dyn std::error::Error>> {
    if let Some(extra) = extra {
        post_pdf_with_parts(path, pdf, &[extra]).await
    } else {
        post_pdf_with_parts(path, pdf, &[]).await
    }
}

async fn post_pdf_with_parts(
    path: &str,
    pdf: &[u8],
    extras: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-form-fields-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"form.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    for (name, value) in extras {
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}.json\"\r\nContent-Type: application/json\r\n\r\n{value}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

#[allow(clippy::similar_names, clippy::too_many_lines)]
fn form_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let page_id = document.new_object_id();
    let group_id = document.new_object_id();
    let text_field_id = document.new_object_id();
    let text_widget_id = document.new_object_id();
    let checkbox_field_id = document.new_object_id();
    let checkbox_widget_id = document.new_object_id();
    let list_field_id = document.new_object_id();
    let list_widget_id = document.new_object_id();

    document.objects.insert(
        text_widget_id,
        Object::Dictionary(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "Parent" => text_field_id,
            "P" => page_id,
            "Rect" => vec![30.into(), 700.into(), 130.into(), 720.into()],
            "NM" => Object::string_literal("first-widget"),
        }),
    );
    document.objects.insert(
        text_field_id,
        Object::Dictionary(dictionary! {
            "Parent" => group_id,
            "FT" => "Tx",
            "T" => Object::string_literal("firstName"),
            "TU" => Object::string_literal("First Name:"),
            "V" => Object::string_literal("Alice"),
            "Ff" => (1_i64 | (1_i64 << 1) | (1_i64 << 12)),
            "DA" => Object::string_literal("/Helv 12 Tf 0 g"),
            "Kids" => vec![Object::Reference(text_widget_id)],
        }),
    );
    document.objects.insert(
        group_id,
        Object::Dictionary(dictionary! {
            "T" => Object::string_literal("person"),
            "Kids" => vec![Object::Reference(text_field_id)],
        }),
    );

    document.objects.insert(
        checkbox_widget_id,
        Object::Dictionary(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "Parent" => checkbox_field_id,
            "P" => page_id,
            "Rect" => vec![30.into(), 650.into(), 50.into(), 670.into()],
            "AP" => dictionary! {
                "N" => dictionary! { "Off" => Object::Null, "Yes" => Object::Null }
            },
        }),
    );
    document.objects.insert(
        checkbox_field_id,
        Object::Dictionary(dictionary! {
            "FT" => "Btn",
            "T" => Object::string_literal("agree"),
            "TU" => Object::string_literal("Accept terms"),
            "V" => "Yes",
            "Kids" => vec![Object::Reference(checkbox_widget_id)],
        }),
    );

    document.objects.insert(
        list_widget_id,
        Object::Dictionary(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "Parent" => list_field_id,
            "P" => page_id,
            "Rect" => vec![200.into(), 650.into(), 300.into(), 690.into()],
        }),
    );
    document.objects.insert(
        list_field_id,
        Object::Dictionary(dictionary! {
            "FT" => "Ch",
            "T" => Object::string_literal("colors"),
            "Ff" => (1_i64 << 21),
            "V" => vec![Object::string_literal("red"), Object::string_literal("blue")],
            "Opt" => vec![
                Object::Array(vec![Object::string_literal("red"), Object::string_literal("Red label")]),
                Object::Array(vec![Object::string_literal("blue"), Object::string_literal("Blue label")]),
            ],
            "Kids" => vec![Object::Reference(list_widget_id)],
        }),
    );

    document.objects.insert(
        page_id,
        Object::Dictionary(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "CropBox" => vec![10.into(), 20.into(), 610.into(), 790.into()],
            "Annots" => vec![
                Object::Reference(text_widget_id),
                Object::Reference(checkbox_widget_id),
                Object::Reference(list_widget_id),
            ],
        }),
    );
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![
            Object::Reference(group_id),
            Object::Reference(checkbox_field_id),
            Object::Reference(list_field_id),
        ],
        "DA" => Object::string_literal("/Helv 9 Tf 0 g"),
    });
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
        "AcroForm" => acroform_id,
    });
    document.trailer.set("Root", catalog_id);
    save(document)
}

#[allow(clippy::similar_names)]
fn plain_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    save(document)
}

fn form_pdf_without_choice_options() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = form_pdf()?;
    let mut document = Document::load_mem(&bytes)?;
    for object in document.objects.values_mut() {
        if let Ok(dictionary) = object.as_dict_mut()
            && dictionary
                .get(b"T")
                .ok()
                .and_then(|value| lopdf::decode_text_string(value).ok())
                .as_deref()
                == Some("colors")
        {
            dictionary.remove(b"Opt");
        }
    }
    save(document)
}

fn save(mut document: Document) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
