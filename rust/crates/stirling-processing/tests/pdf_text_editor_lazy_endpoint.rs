use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use lopdf::{Document, Object, Stream, content::Content, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn lazy_text_editor_job_serves_pages_partial_export_and_cache_clear()
-> Result<(), Box<dyn std::error::Error>> {
    let app = app(4 * 1024 * 1024);
    let metadata = app
        .clone()
        .oneshot(metadata_request(&source_pdf()?)?)
        .await?;
    let metadata = require_status(metadata, StatusCode::OK).await?;
    let job_id = metadata
        .headers()
        .get("x-job-id")
        .ok_or("metadata response has no X-Job-Id")?
        .to_str()?
        .to_owned();

    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/page/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    let page = require_status(page, StatusCode::OK).await?;
    let page: Value = serde_json::from_slice(&response_bytes(page).await?)?;
    assert_eq!(page["pageNumber"], 1);
    assert!(page["contentStreams"][0]["rawData"].is_null());

    let fonts = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/fonts/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    let fonts = require_status(fonts, StatusCode::OK).await?;
    let fonts: Value = serde_json::from_slice(&response_bytes(fonts).await?)?;
    assert_eq!(fonts[0]["id"], "F1");
    assert_eq!(fonts[0]["pageNumber"], 1);
    assert_eq!(fonts[0]["uid"], "1:F1");
    assert_eq!(fonts[0]["baseName"], "Helvetica");
    assert_eq!(fonts[0]["subtype"], "Type1");
    assert_eq!(fonts[0]["embedded"], false);

    let replacement = b"BT /F1 12 Tf 10 50 Td (Updated cached source) Tj ET";
    let updates = serde_json::json!({
        "pages": [{
            "pageNumber": 1,
            "contentStreams": [{
                "dictionary": {
                    "Length": { "type": "INTEGER", "value": replacement.len() }
                },
                "rawData": STANDARD.encode(replacement)
            }]
        }]
    });
    let partial = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/convert/pdf/text-editor/partial/{job_id}?filename=updated.pdf"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&updates)?))?,
        )
        .await?;
    let partial = require_status(partial, StatusCode::OK).await?;
    assert_eq!(partial.headers()[header::CONTENT_TYPE], "application/pdf");
    let rebuilt = Document::load_mem(&response_bytes(partial).await?)?;
    assert_eq!(rebuilt.get_pages().len(), 1);
    assert_eq!(rebuilt.extract_text(&[1])?.trim(), "Updated cached source");

    let cleared_text = post_partial(
        &app,
        &job_id,
        serde_json::json!({
            "pages": [{
                "pageNumber": 1,
                "textElements": []
            }]
        }),
    )
    .await?;
    let cleared_text = Document::load_mem(&cleared_text)?;
    assert!(cleared_text.extract_text(&[1])?.trim().is_empty());
    let page_id = *cleared_text
        .get_pages()
        .get(&1)
        .ok_or("cleared page missing")?;
    assert!(cleared_text.get_page_content(page_id).is_empty());

    let cleared = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/convert/pdf/text-editor/clear-cache/{job_id}"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(cleared.status(), StatusCode::OK);
    let expired = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/page/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn lazy_text_editor_rejects_unknown_jobs() -> Result<(), Box<dyn std::error::Error>> {
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .uri("/api/v1/convert/pdf/text-editor/page/unknown/1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn lazy_text_editor_regenerates_elements_over_vectors_and_refreshes_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let app = app(8 * 1024 * 1024);
    let metadata = app
        .clone()
        .oneshot(metadata_request(&editable_source_pdf()?)?)
        .await?;
    let metadata = require_status(metadata, StatusCode::OK).await?;
    let job_id = metadata
        .headers()
        .get("x-job-id")
        .ok_or("metadata response has no X-Job-Id")?
        .to_str()?
        .to_owned();

    let first_update = serde_json::json!({
        "metadata": { "title": "Partial metadata" },
        "xmpMetadata": STANDARD.encode(b"<x:xmpmeta>partial</x:xmpmeta>"),
        "pages": [{
            "pageNumber": 1,
            "resources": {
                "type": "DICTIONARY",
                "entries": {
                    "MarkerStream": {
                        "type": "STREAM",
                        "stream": { "dictionary": {} }
                    }
                }
            },
            "textElements": [{
                "text": "First element update",
                "fontId": "Helvetica",
                "fontSize": 12.0,
                "x": 15.0,
                "y": 55.0,
                "zOrder": 1
            }],
            "imageElements": [{
                "id": "replacement-image",
                "x": 80.0,
                "y": 20.0,
                "width": 6.0,
                "height": 6.0,
                "zOrder": 0,
                "imageData": replacement_png()?,
                "imageFormat": "png"
            }],
            "annotations": [{
                "subtype": "Text",
                "contents": "preserved annotation",
                "rect": [10.0, 90.0, 20.0, 100.0]
            }]
        }]
    });
    let first = post_partial(&app, &job_id, first_update).await?;
    let first = Document::load_mem(&first)?;
    assert_eq!(first.extract_text(&[1])?.trim(), "First element update");
    assert_eq!(first.extract_text(&[2])?.trim(), "Untouched second page");
    assert_preserved_graph_and_regenerated_page(&first, Some("preserved annotation"), false)?;
    assert_marker_stream(&first)?;

    let second_update = serde_json::json!({
        "pages": [{
            "pageNumber": 1,
            "textElements": [{
                "text": "Second element update",
                "fontId": "Helvetica",
                "fontSize": 12.0,
                "x": 15.0,
                "y": 55.0,
                "zOrder": 1
            }],
            "resources": {
                "type": "DICTIONARY",
                "entries": {
                    "Marker": { "type": "NAME", "value": "PartialResource" }
                }
            },
            "annotations": [{
                "subtype": "Text",
                "contents": "replacement annotation",
                "rect": [30.0, 90.0, 40.0, 100.0],
                "rawData": { "type": "DICTIONARY", "entries": {} }
            }]
        }]
    });
    let second = post_partial(&app, &job_id, second_update).await?;
    let second = Document::load_mem(&second)?;
    assert_eq!(second.extract_text(&[1])?.trim(), "Second element update");
    assert_eq!(second.extract_text(&[2])?.trim(), "Untouched second page");
    assert_preserved_graph_and_regenerated_page(&second, Some("replacement annotation"), true)?;

    let third_update = serde_json::json!({
        "pages": [{
            "pageNumber": 1,
            "textElements": [],
            "annotations": []
        }]
    });
    let third = post_partial(&app, &job_id, third_update).await?;
    let third = Document::load_mem(&third)?;
    assert!(third.extract_text(&[1])?.trim().is_empty());
    assert_eq!(third.extract_text(&[2])?.trim(), "Untouched second page");
    assert_preserved_graph_and_regenerated_page(&third, None, true)?;

    let cached_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/page/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    let cached_page = require_status(cached_page, StatusCode::OK).await?;
    let cached_page: Value = serde_json::from_slice(&response_bytes(cached_page).await?)?;
    assert_eq!(cached_page["textElements"], serde_json::json!([]));

    let cleared = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/convert/pdf/text-editor/clear-cache/{job_id}"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(cleared.status(), StatusCode::OK);
    Ok(())
}

async fn post_partial(
    app: &axum::Router,
    job_id: &str,
    update: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/convert/pdf/text-editor/partial/{job_id}?filename=updated.pdf"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&update)?))?,
        )
        .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    response_bytes(response).await
}

fn assert_preserved_graph_and_regenerated_page(
    document: &Document,
    expected_annotation: Option<&str>,
    expect_marker: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let page_id = *document.get_pages().get(&1).ok_or("first page missing")?;
    let page = document.get_dictionary(page_id)?;
    let annotations = page.get(b"Annots")?.as_array()?;
    if let Some(expected_annotation) = expected_annotation {
        assert_eq!(annotations.len(), 1);
        let (_, annotation) = document.dereference(&annotations[0])?;
        assert_eq!(
            annotation.as_dict()?.get(b"Contents")?.as_str()?,
            expected_annotation.as_bytes()
        );
    } else {
        assert!(annotations.is_empty());
    }
    let content = Content::decode(&document.get_page_content(page_id))?;
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
            .any(|operation| operation.operator == "f")
    );
    assert!(!content.operations.iter().any(|operation| {
        operation.operator == "Do"
            && operation
                .operands
                .first()
                .and_then(|operand| operand.as_name().ok())
                == Some(b"ImOld")
    }));
    assert!(content.operations.iter().any(|operation| {
        operation.operator == "Do"
            && operation
                .operands
                .first()
                .and_then(|operand| operand.as_name().ok())
                .is_some_and(|name| name.starts_with(b"RustImg"))
    }));

    if expect_marker {
        let resources = page.get(b"Resources")?.as_dict()?;
        assert_eq!(resources.get(b"Marker")?.as_name()?, b"PartialResource");
    }

    let catalog = document.catalog()?;
    let metadata = document.trailer.get(b"Info")?;
    let (_, metadata) = document.dereference(metadata)?;
    assert_eq!(
        metadata.as_dict()?.get(b"Title")?.as_str()?,
        b"Partial metadata"
    );
    let xmp = catalog.get(b"Metadata")?;
    let (_, xmp) = document.dereference(xmp)?;
    assert_eq!(xmp.as_stream()?.content, b"<x:xmpmeta>partial</x:xmpmeta>");
    let acro_form = catalog.get(b"AcroForm")?;
    let (_, acro_form) = document.dereference(acro_form)?;
    let field = acro_form
        .as_dict()?
        .get(b"Fields")?
        .as_array()?
        .first()
        .ok_or("form field missing")?;
    let (_, field) = document.dereference(field)?;
    assert_eq!(field.as_dict()?.get(b"T")?.as_str()?, b"preserved-field");
    Ok(())
}

fn assert_marker_stream(document: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let page_id = *document.get_pages().get(&1).ok_or("first page missing")?;
    let marker = document
        .get_dictionary(page_id)?
        .get(b"Resources")?
        .as_dict()?
        .get(b"MarkerStream")?;
    let (_, marker) = document.dereference(marker)?;
    assert_eq!(marker.as_stream()?.content, b"preserved-resource-stream");
    Ok(())
}

fn replacement_png() -> Result<String, image::ImageError> {
    let mut bytes = Vec::new();
    DynamicImage::ImageRgba8(RgbaImage::from_pixel(1, 1, Rgba([0, 0, 255, 255])))
        .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)?;
    Ok(STANDARD.encode(bytes))
}

fn metadata_request(pdf: &[u8]) -> Result<Request<Body>, axum::http::Error> {
    let boundary = "stirling-text-editor-lazy-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Request::builder()
        .method("POST")
        .uri("/api/v1/convert/pdf/text-editor/metadata")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
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

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

fn source_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Cached editor source) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn editable_source_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let old_image_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Image",
            "Width" => 1, "Height" => 1,
            "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8,
        },
        vec![255, 0, 0],
    ));
    let marker_stream_id = document.add_object(Stream::new(
        dictionary! {},
        b"preserved-resource-stream".to_vec(),
    ));
    let first_content_id = document.add_object(Stream::new(
        dictionary! {},
        b"0 1 0 rg 10 10 20 20 re f BT /F1 12 Tf 15 55 Td (Original editable text) Tj ET q 6 0 0 6 80 20 cm /ImOld Do Q".to_vec(),
    ));
    let annotation_id = document.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Text",
        "Rect" => vec![10.into(), 90.into(), 20.into(), 100.into()],
        "Contents" => Object::string_literal("preserved annotation"),
    });
    let first_page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Resources" => dictionary! {
            "Font" => dictionary! { "F1" => font_id },
            "XObject" => dictionary! { "ImOld" => old_image_id },
            "MarkerStream" => marker_stream_id,
        },
        "Contents" => first_content_id,
        "Annots" => vec![Object::Reference(annotation_id)],
    });
    let second_content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 15 55 Td (Untouched second page) Tj ET".to_vec(),
    ));
    let second_page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => second_content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(first_page_id), Object::Reference(second_page_id)],
            "Count" => 2,
        }),
    );
    let field_id = document.add_object(dictionary! {
        "FT" => "Tx",
        "T" => Object::string_literal("preserved-field"),
        "V" => Object::string_literal("preserved value"),
    });
    let acro_form_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(field_id)],
    });
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => page_tree_id, "AcroForm" => acro_form_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
