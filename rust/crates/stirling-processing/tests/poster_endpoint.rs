use std::io::{Cursor, Read};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, content::Content, dictionary};
use stirling_processing::{app, runtime_metrics::application_version};
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn creates_default_top_to_bottom_grid_in_single_pdf_zip()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_poster(&labeled_pdf(&[0, 0])?, "report.pdf", &[]).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"report_poster.zip\""
    );
    let (entry_name, pdf) = first_zip_entry(&response_bytes(response).await?)?;
    assert_eq!(entry_name, "report_poster.pdf");

    let document = Document::load_mem(&pdf)?;
    let pages = document.get_pages().into_values().collect::<Vec<_>>();
    assert_eq!(pages.len(), 8);
    assert_numbers_close(&page_size(&document, pages[0])?, &[595.275_63, 841.889_8]);
    assert_eq!(form_label(&document, pages[0])?, "P1");
    assert_eq!(form_label(&document, pages[4])?, "P2");
    assert_numbers_close(
        &translation_matrix(&document, pages[0], 2)?,
        &[1.0, 0.0, 0.0, 1.0, 0.0, -130.0],
    );
    assert_numbers_close(
        &translation_matrix(&document, pages[3], 2)?,
        &[1.0, 0.0, 0.0, 1.0, -90.0, 0.0],
    );
    let catalog = document.catalog()?;
    assert!(catalog.get(b"AcroForm").is_err());
    assert!(catalog.get(b"Outlines").is_err());
    assert_rebuilt_metadata(&document)?;
    Ok(())
}

#[tokio::test]
async fn applies_right_to_left_order_and_every_supported_target_size()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = labeled_pdf(&[0])?;
    for (size, expected) in [
        ("A4", [595.275_63, 841.889_8]),
        ("Letter", [612.0, 792.0]),
        ("A3", [841.889_8, 1_190.551_1]),
        ("A5", [419.527_56, 595.275_63]),
        ("Legal", [612.0, 1008.0]),
        ("Tabloid", [792.0, 1224.0]),
    ] {
        let response = require_status(
            post_poster(
                &pdf,
                "sheet.pdf",
                &[
                    ("pageSize", size),
                    ("xFactor", "2"),
                    ("yFactor", "1"),
                    ("rightToLeft", "true"),
                ],
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        let (_, output) = first_zip_entry(&response_bytes(response).await?)?;
        let document = Document::load_mem(&output)?;
        let pages = document.get_pages().into_values().collect::<Vec<_>>();
        assert_eq!(pages.len(), 2);
        assert_numbers_close(&page_size(&document, pages[0])?, &expected);
        assert_numbers_close(
            &translation_matrix(&document, pages[0], 2)?,
            &[1.0, 0.0, 0.0, 1.0, -90.0, 0.0],
        );
        assert_numbers_close(
            &translation_matrix(&document, pages[1], 2)?,
            &[1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        );
    }
    Ok(())
}

#[tokio::test]
async fn normalizes_crop_box_and_rotation_like_pdfbox_layer_utility()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_poster(
            &labeled_pdf(&[90])?,
            "rotated.pdf",
            &[("pageSize", "A5"), ("xFactor", "2"), ("yFactor", "1")],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let (_, output) = first_zip_entry(&response_bytes(response).await?)?;
    let document = Document::load_mem(&output)?;
    let first_page = *document.get_pages().values().next().ok_or("missing page")?;
    let form = page_form(&document, first_page)?;
    assert_numbers_close(
        &object_numbers(form.dict.get(b"BBox")?)?,
        &[10.0, 20.0, 190.0, 280.0],
    );
    assert_numbers_close(
        &object_numbers(form.dict.get(b"Matrix")?)?,
        &[0.0, -1.444_444_4, 0.692_307_7, 0.0, -13.846_154, 274.444_46],
    );
    assert_numbers_close(
        &translation_matrix(&document, first_page, 2)?,
        &[1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    );
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_sizes_grids_values_and_missing_files()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = labeled_pdf(&[0])?;
    for fields in [
        vec![("pageSize", "a4")],
        vec![("xFactor", "0")],
        vec![("yFactor", "11")],
        vec![("xFactor", "many")],
        vec![("rightToLeft", "perhaps")],
    ] {
        let response = post_poster(&pdf, "bad.pdf", &fields).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_slice(&response_bytes(response).await?)?;
        assert_eq!(error["path"], "/api/v1/general/split-for-poster-print");
    }

    let boundary = "missing-poster-file";
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/split-for-poster-print")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(format!("--{boundary}--\r\n")))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn first_zip_entry(bytes: &[u8]) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 1);
    let mut entry = archive.by_index(0)?;
    let name = entry.name().to_owned();
    let mut output = Vec::new();
    entry.read_to_end(&mut output)?;
    Ok((name, output))
}

fn page_form(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<&Stream, Box<dyn std::error::Error>> {
    let resources = document
        .get_dictionary(page_id)?
        .get(b"Resources")?
        .as_dict()?;
    let form = resources.get(b"XObject")?.as_dict()?.get(b"PosterPage")?;
    let (_, form) = document.dereference(form)?;
    Ok(form.as_stream()?)
}

fn form_label(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<String, Box<dyn std::error::Error>> {
    let content = Content::decode(&page_form(document, page_id)?.content)?;
    content
        .operations
        .into_iter()
        .find(|operation| operation.operator == "Tj")
        .and_then(|operation| operation.operands.into_iter().next())
        .and_then(|operand| operand.as_str().ok().map(<[u8]>::to_vec))
        .map(|value| String::from_utf8_lossy(&value).into_owned())
        .ok_or_else(|| "missing form label".into())
}

fn translation_matrix(
    document: &Document,
    page_id: lopdf::ObjectId,
    index: usize,
) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
    let operations = Content::decode(&document.get_page_content(page_id))?.operations;
    let operation = operations
        .iter()
        .filter(|operation| operation.operator == "cm")
        .nth(index)
        .ok_or("missing matrix")?;
    Ok(operation
        .operands
        .iter()
        .map(Object::as_float)
        .collect::<Result<Vec<_>, _>>()?)
}

fn page_size(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<[f32; 2], Box<dyn std::error::Error>> {
    let values = object_numbers(document.get_dictionary(page_id)?.get(b"MediaBox")?)?;
    Ok([values[2] - values[0], values[3] - values[1]])
}

fn object_numbers(object: &Object) -> Result<Vec<f32>, lopdf::Error> {
    object.as_array()?.iter().map(Object::as_float).collect()
}

fn assert_numbers_close(actual: &[f32], expected: &[f32]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert!(
            (*actual - *expected).abs() < 0.001,
            "{actual} != {expected}"
        );
    }
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

async fn post_poster(
    pdf: &[u8],
    filename: &str,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-poster-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/split-for-poster-print")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn labeled_pdf(rotations: &[i32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut pages = Vec::new();
    for (index, rotation) in rotations.iter().copied().enumerate() {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            format!("BT (P{}) Tj ET", index + 1).into_bytes(),
        ));
        let mut page = dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "CropBox" => vec![10.into(), 20.into(), 190.into(), 280.into()],
            "Contents" => content_id,
        };
        if rotation != 0 {
            page.set("Rotate", rotation);
        }
        pages.push(document.add_object(page));
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(rotations.len())?,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
            "Resources" => dictionary! {},
        }),
    );
    let outlines_id = document.add_object(dictionary! { "Type" => "Outlines" });
    let acroform_id = document.add_object(dictionary! { "Fields" => Vec::<Object>::new() });
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
        "Outlines" => outlines_id,
        "AcroForm" => acroform_id,
    });
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Source title"),
        "Creator" => Object::string_literal("Source creator"),
        "Producer" => Object::string_literal("Source producer"),
        "CreationDate" => Object::string_literal("D:20240102030405+00'00'"),
        "ModDate" => Object::string_literal("D:20240203040506+00'00'"),
        "Custom" => Object::string_literal("discard me"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn assert_rebuilt_metadata(document: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let (_, info) = document.dereference(document.trailer.get(b"Info")?)?;
    let info = info.as_dict()?;
    let label = format!("Stirling-PDF v{}", application_version());
    assert_eq!(info.get(b"Title")?.as_str()?, b"Source title");
    assert_eq!(info.get(b"Creator")?.as_str()?, label.as_bytes());
    assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
    assert_eq!(
        info.get(b"CreationDate")?.as_str()?,
        b"D:20240102030405+00'00'"
    );
    assert_eq!(info.get(b"ModDate")?.as_str()?, b"D:20240203040506+00'00'");
    assert!(info.get(b"Custom").is_err());
    Ok(())
}
