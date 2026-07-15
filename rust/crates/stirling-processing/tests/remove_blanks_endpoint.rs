use std::{collections::BTreeMap, io::Read};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn separates_text_and_empty_pages_without_pdfium() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_remove_blanks(&mixed_text_and_blank_pdf()?, "10", "99.9").await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_processed.zip")
    );
    let entries = zip_entries(&response_bytes(response).await?)?;
    assert_eq!(
        entries.keys().cloned().collect::<Vec<_>>(),
        vec![
            "source_blankPages.pdf".to_owned(),
            "source_nonBlankPages.pdf".to_owned(),
        ]
    );
    let non_blank = Document::load_mem(&entries["source_nonBlankPages.pdf"])?;
    let blank = Document::load_mem(&entries["source_blankPages.pdf"])?;
    assert_eq!(non_blank.get_pages().len(), 1);
    assert_eq!(blank.get_pages().len(), 1);
    assert!(non_blank.extract_text(&[1])?.contains("Has content"));
    Ok(())
}

#[tokio::test]
async fn emits_the_all_blank_name_when_every_page_is_empty()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_remove_blanks(&empty_pdf(2)?, "10", "99.9").await?;
    let response = require_status(response, StatusCode::OK).await?;
    let entries = zip_entries(&response_bytes(response).await?)?;
    assert_eq!(entries.len(), 1);
    let all_blank = Document::load_mem(&entries["source_allBlankPages.pdf"])?;
    assert_eq!(all_blank.get_pages().len(), 2);
    Ok(())
}

#[tokio::test]
async fn classifies_black_and_white_image_pages_with_native_rendering()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_remove_blanks(&black_and_white_image_pdf()?, "10", "99.9").await?;
    if !native_pdfium_requested() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    let entries = zip_entries(&response_bytes(response).await?)?;
    assert!(entries.contains_key("source_nonBlankPages.pdf"));
    assert!(entries.contains_key("source_blankPages.pdf"));
    assert_eq!(
        Document::load_mem(&entries["source_nonBlankPages.pdf"])?
            .get_pages()
            .len(),
        1
    );
    assert_eq!(
        Document::load_mem(&entries["source_blankPages.pdf"])?
            .get_pages()
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn rejects_a_non_integer_threshold() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_remove_blanks(&empty_pdf(1)?, "bad", "99.9").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn native_pdfium_requested() -> bool {
    std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some()
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

async fn post_remove_blanks(
    pdf: &[u8],
    threshold: &str,
    white_percent: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-remove-blanks-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    for (name, value) in [("threshold", threshold), ("whitePercent", white_percent)] {
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/remove-blanks")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn zip_entries(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut archive = ZipArchive::new(std::io::Cursor::new(bytes))?;
    let mut entries = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        entries.insert(entry.name().to_owned(), bytes);
    }
    Ok(entries)
}

fn mixed_text_and_blank_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let text_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Has content) Tj ET".to_vec(),
    ));
    let empty_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
    let text_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 80.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => text_id,
    });
    let blank_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 80.into()],
        "Resources" => dictionary! {},
        "Contents" => empty_id,
    });
    finish_pdf(
        &mut document,
        page_tree_id,
        vec![text_page_id, blank_page_id],
    )
}

fn empty_pdf(page_count: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut pages = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 80.into()],
            "Resources" => dictionary! {},
            "Contents" => content_id,
        }));
    }
    finish_pdf(&mut document, page_tree_id, pages)
}

fn black_and_white_image_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut pages = Vec::new();
    for color in [[0_u8, 0, 0], [255_u8, 255, 255]] {
        let image_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8,
            },
            color.to_vec(),
        ));
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            b"q 20 0 0 20 0 0 cm /Im0 Do Q".to_vec(),
        ));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 20.into(), 20.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => image_id } },
            "Contents" => content_id,
        }));
    }
    finish_pdf(&mut document, page_tree_id, pages)
}

fn finish_pdf(
    document: &mut Document,
    page_tree_id: lopdf::ObjectId,
    pages: Vec<lopdf::ObjectId>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let count = i64::try_from(pages.len())?;
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => count,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
