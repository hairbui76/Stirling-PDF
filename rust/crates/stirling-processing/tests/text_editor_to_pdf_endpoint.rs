use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use lopdf::{Document, content::Content};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn rebuilds_a_pdf_from_editor_json() -> Result<(), Box<dyn std::error::Error>> {
    let content = b"BT /F1 12 Tf 10 50 Td (Rebuilt) Tj ET";
    let json = serde_json::json!({
        "metadata": { "title": "Rebuilt Doc" },
        "pages": [{
            "pageNumber": 1,
            "width": 200.0,
            "height": 160.0,
            "rotation": 90,
            "contentStreams": [{
                "dictionary": {
                    "Length": { "type": "INTEGER", "value": content.len() }
                },
                "rawData": STANDARD.encode(content)
            }]
        }]
    });
    let response = post_json(serde_json::to_vec(&json)?.as_slice()).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("editor.pdf")
    );
    let rebuilt = Document::load_mem(&response_bytes(response).await?)?;
    let pages = rebuilt.get_pages();
    assert_eq!(pages.len(), 1);
    let page_id = *pages.values().next().ok_or("no page")?;
    let page = rebuilt.get_dictionary(page_id)?;
    assert_eq!(page.get(b"Rotate")?.as_i64()?, 90);
    let contents = page.get(b"Contents")?.as_array()?;
    let (_, stream) = rebuilt.dereference(&contents[0])?;
    assert_eq!(stream.as_stream()?.content, content);
    Ok(())
}

#[tokio::test]
async fn regenerates_a_mixed_edit_page_over_the_preserved_stream()
-> Result<(), Box<dyn std::error::Error>> {
    // The page carries both a preserved `contentStreams` entry (an unrelated
    // vector fill plus a represented text draw) and an edited `textElements`
    // projection of it. The endpoint must strip the represented text draw from
    // the preserved stream, append the newly authored text, and leave the
    // unrelated vector fill untouched — rather than writing the preserved
    // stream back verbatim and silently dropping the edit.
    let original_content =
        b"0 1 0 rg 10 10 20 20 re f BT /F1 12 Tf 10 50 Td (Original endpoint text) Tj ET";
    let json = serde_json::json!({
        "fonts": [{
            "id": "body",
            "pageNumber": 1,
            "standard14Name": "Helvetica"
        }],
        "pages": [{
            "pageNumber": 1,
            "width": 200.0,
            "height": 160.0,
            "contentStreams": [{
                "dictionary": {
                    "Length": { "type": "INTEGER", "value": original_content.len() }
                },
                "rawData": STANDARD.encode(original_content)
            }],
            "textElements": [{
                "text": "Edited endpoint text",
                "fontId": "body",
                "fontSize": 12.0,
                "x": 10.0,
                "y": 50.0
            }]
        }]
    });
    let response = post_json(serde_json::to_vec(&json)?.as_slice()).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    let rebuilt = Document::load_mem(&response_bytes(response).await?)?;
    let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
    let content = Content::decode(&rebuilt.get_page_content(page_id))?;

    // The represented text draw from the preserved stream is gone.
    assert!(!content.operations.iter().any(|operation| {
        operation.operator == "Tj"
            && operation
                .operands
                .first()
                .and_then(|object| object.as_str().ok())
                == Some(b"Original endpoint text")
    }));
    // The newly authored text is present.
    let text = content
        .operations
        .iter()
        .find(|operation| operation.operator == "Tj")
        .and_then(|operation| operation.operands.first())
        .and_then(|object| object.as_str().ok())
        .ok_or("missing text")?;
    assert_eq!(text, b"Edited endpoint text");
    // The unrelated retained vector fill survives unchanged.
    assert!(
        content
            .operations
            .iter()
            .any(|operation| operation.operator == "rg")
    );
    assert!(
        content
            .operations
            .iter()
            .any(|operation| operation.operator == "re")
    );
    assert!(
        content
            .operations
            .iter()
            .any(|operation| operation.operator == "f" && operation.operands.is_empty())
    );
    Ok(())
}

#[tokio::test]
async fn draws_an_editor_authored_standard14_page() -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::json!({
        "fonts": [{
            "id": "body",
            "pageNumber": 1,
            "standard14Name": "Helvetica"
        }],
        "pages": [{
            "pageNumber": 1,
            "width": 200.0,
            "height": 160.0,
            "textElements": [{
                "text": "Endpoint text",
                "fontId": "body",
                "fontSize": 14.0,
                "x": 11.0,
                "y": 22.0,
                "fillColor": {
                    "colorSpace": "DeviceGray",
                    "components": [0.25]
                }
            }]
        }]
    });
    let response = post_json(serde_json::to_vec(&json)?.as_slice()).await?;
    let response = require_status(response, StatusCode::OK).await?;
    let rebuilt = Document::load_mem(&response_bytes(response).await?)?;
    let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
    let content = Content::decode(&rebuilt.get_page_content(page_id))?;
    assert!(content.operations.iter().any(|operation| {
        operation.operator == "Tf"
            && operation
                .operands
                .first()
                .and_then(|object| object.as_name().ok())
                == Some(b"RustFont0")
    }));
    let text = content
        .operations
        .iter()
        .find(|operation| operation.operator == "Tj")
        .and_then(|operation| operation.operands.first())
        .and_then(|object| object.as_str().ok())
        .ok_or("missing text")?;
    assert_eq!(text, b"Endpoint text");
    Ok(())
}

#[tokio::test]
async fn rebuilds_editor_form_fields_as_page_widgets() -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::json!({
        "pages": [{ "pageNumber": 1, "width": 200.0, "height": 160.0 }],
        "formFields": [{
            "name": "givenName",
            "fieldType": "Tx",
            "value": "Ada",
            "pageNumber": 1,
            "rect": [10.0, 20.0, 80.0, 40.0]
        }]
    });
    let response = post_json(serde_json::to_vec(&json)?.as_slice()).await?;
    let rebuilt = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let catalog = rebuilt.catalog()?;
    let acroform = rebuilt.get_dictionary(catalog.get(b"AcroForm")?.as_reference()?)?;
    let fields = acroform.get(b"Fields")?.as_array()?;
    assert_eq!(fields.len(), 1);
    let field_id = fields[0].as_reference()?;
    let field = rebuilt.get_dictionary(field_id)?;
    assert_eq!(field.get(b"T")?.as_str()?, b"givenName");
    assert_eq!(field.get(b"V")?.as_str()?, b"Ada");
    let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
    assert_eq!(
        rebuilt
            .get_dictionary(page_id)?
            .get(b"Annots")?
            .as_array()?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn rebuilds_annotation_appearance_streams_as_indirect_objects()
-> Result<(), Box<dyn std::error::Error>> {
    // A non-widget annotation whose raw COS projection nests its `/AP /N`
    // appearance stream inside the dictionary. The rebuild must hoist that
    // stream to an indirect object — a stream is only legal as one — so the
    // output parses (lopdf + PDFium) and keeps the appearance.
    let appearance = b"0 1 0 rg 0 0 50 50 re f";
    let json = serde_json::json!({
        "pages": [{
            "pageNumber": 1,
            "width": 100.0,
            "height": 100.0,
            "annotations": [{
                "subtype": "Square",
                "rect": [10.0, 10.0, 60.0, 60.0],
                "rawData": {
                    "type": "DICTIONARY",
                    "entries": {
                        "Subtype": { "type": "NAME", "value": "Square" },
                        "Rect": { "type": "ARRAY", "items": [
                            { "type": "INTEGER", "value": 10 },
                            { "type": "INTEGER", "value": 10 },
                            { "type": "INTEGER", "value": 60 },
                            { "type": "INTEGER", "value": 60 }
                        ] },
                        "F": { "type": "INTEGER", "value": 4 },
                        "AP": { "type": "DICTIONARY", "entries": {
                            "N": { "type": "STREAM", "stream": {
                                "dictionary": {
                                    "Type": { "type": "NAME", "value": "XObject" },
                                    "Subtype": { "type": "NAME", "value": "Form" },
                                    "BBox": { "type": "ARRAY", "items": [
                                        { "type": "INTEGER", "value": 0 },
                                        { "type": "INTEGER", "value": 0 },
                                        { "type": "INTEGER", "value": 50 },
                                        { "type": "INTEGER", "value": 50 }
                                    ] }
                                },
                                "rawData": STANDARD.encode(appearance)
                            } }
                        } }
                    }
                }
            }]
        }]
    });
    let response = post_json(serde_json::to_vec(&json)?.as_slice()).await?;
    let bytes = response_bytes(require_status(response, StatusCode::OK).await?).await?;

    let rebuilt = Document::load_mem(&bytes)?;
    let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
    let annotations = rebuilt
        .get_dictionary(page_id)?
        .get(b"Annots")?
        .as_array()?
        .clone();
    assert_eq!(annotations.len(), 1);
    let annotation = rebuilt.get_dictionary(annotations[0].as_reference()?)?;
    assert_eq!(annotation.get(b"Subtype")?.as_name()?, b"Square");
    let normal = annotation.get(b"AP")?.as_dict()?.get(b"N")?;
    let normal_id = normal
        .as_reference()
        .map_err(|_| "the /AP /N appearance stream must be an indirect object")?;
    assert_eq!(
        rebuilt.get_object(normal_id)?.as_stream()?.content,
        appearance
    );

    let Some(pdfium) = pdfium()? else {
        return Ok(());
    };
    let document = pdfium.load_pdf_from_byte_slice(&bytes, None)?;
    assert_eq!(document.pages().len(), 1);
    let page = document.pages().get(0)?;
    let rendered = page
        .render_with_config(
            &pdfium_render::prelude::PdfRenderConfig::new()
                .set_target_width(200)
                .render_annotations(true),
        )?
        .as_image()?
        .to_rgba8();
    assert!(
        rendered
            .pixels()
            .any(|pixel| pixel[1] > 200 && pixel[0] < 100 && pixel[2] < 100),
        "the restored appearance stream should render its green square"
    );
    Ok(())
}

/// Binds the natively requested `PDFium` library, or `None` when the test run
/// does not request one. A configured-but-unloadable library is an error so
/// the render assertion cannot be skipped silently.
fn pdfium() -> Result<Option<pdfium_render::prelude::Pdfium>, Box<dyn std::error::Error>> {
    use pdfium_render::prelude::Pdfium;

    let Some(configured) = std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH") else {
        return Ok(None);
    };
    let configured = std::path::PathBuf::from(configured);
    let library = if configured.is_dir() {
        Pdfium::pdfium_platform_library_name_at_path(&configured)
    } else {
        configured
    };
    Ok(Some(Pdfium::new(Pdfium::bind_to_library(library)?)))
}

#[tokio::test]
async fn rejects_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_json(b"not json at all").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn requires_a_file() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-editor-empty";
    let body = format!("--{boundary}--\r\n").into_bytes();
    let response = app(4 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/text-editor/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = response_bytes(response).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

async fn post_json(json: &[u8]) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-editor-json-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"editor.json\"\r\nContent-Type: application/json\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(json);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(4 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/text-editor/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}
