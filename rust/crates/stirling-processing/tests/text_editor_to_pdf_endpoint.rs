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
