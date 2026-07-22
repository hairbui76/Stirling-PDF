use std::io::{Cursor, Read};

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
async fn splits_root_bookmarks_into_named_contiguous_chapters()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_chapters(&bookmarked_pdf()?, 0, false, false).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("bookmarked.zip")
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.by_index(0)?.name(), "0 RootOne.pdf");
    assert_eq!(archive.by_index(1)?.name(), "1 Root Two.pdf");
    assert_eq!(
        page_widths(&zip_entry(&mut archive, 0)?)?,
        vec![101, 102, 103]
    );
    assert_eq!(page_widths(&zip_entry(&mut archive, 1)?)?, vec![104]);
    Ok(())
}

#[tokio::test]
async fn honors_bookmark_depth_and_metadata_flag() -> Result<(), Box<dyn std::error::Error>> {
    for (include_metadata, expects_metadata) in [(false, false), (true, true)] {
        let response = require_status(
            post_chapters(&bookmarked_pdf()?, 1, include_metadata, false).await?,
            StatusCode::OK,
        )
        .await?;
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let mut archive = ZipArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.len(), 3);
        assert_eq!(archive.by_index(0)?.name(), "0 RootOne.pdf");
        assert_eq!(archive.by_index(1)?.name(), "1 Child.pdf");
        assert_eq!(archive.by_index(2)?.name(), "2 Root Two.pdf");
        assert_eq!(page_widths(&zip_entry(&mut archive, 0)?)?, vec![101]);
        assert_eq!(page_widths(&zip_entry(&mut archive, 1)?)?, vec![102, 103]);
        let first = Document::load_mem(&zip_entry(&mut archive, 0)?)?;
        assert_eq!(first.trailer.get(b"Info").is_ok(), expects_metadata);
        assert!(first.catalog()?.get(b"Outlines").is_err());
    }
    Ok(())
}

#[tokio::test]
async fn rejects_documents_without_internal_bookmarks() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_chapters(&plain_pdf()?, 0, false, false).await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("No PDF bookmarks/outline found"));
    assert!(body.contains("/api/v1/general/split-pdf-by-chapters"));
    Ok(())
}

fn zip_entry<R: std::io::Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut entry = archive.by_index(index)?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn page_widths(bytes: &[u8]) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let document = Document::load_mem(bytes)?;
    document
        .get_pages()
        .into_values()
        .map(|page_id| {
            Ok(document
                .get_dictionary(page_id)?
                .get(b"MediaBox")?
                .as_array()?[2]
                .as_i64()?)
        })
        .collect()
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

async fn post_chapters(
    pdf: &[u8],
    level: i32,
    include_metadata: bool,
    allow_duplicates: bool,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-split-chapters-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "bookmarked.pdf", pdf);
    add_text_part(&mut body, boundary, "bookmarkLevel", &level.to_string());
    add_text_part(
        &mut body,
        boundary,
        "includeMetadata",
        &include_metadata.to_string(),
    );
    add_text_part(
        &mut body,
        boundary,
        "allowDuplicates",
        &allow_duplicates.to_string(),
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/split-pdf-by-chapters")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn add_file_part(body: &mut Vec<u8>, boundary: &str, filename: &str, content: &[u8]) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
}

fn add_text_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

fn bookmarked_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = base_document(&[101, 102, 103, 104])?;
    let pages: Vec<_> = document.get_pages().into_values().collect();
    let outlines_id = document.new_object_id();
    let root_one_id = document.new_object_id();
    let child_id = document.new_object_id();
    let root_two_id = document.new_object_id();
    document.objects.insert(
        root_one_id,
        Object::Dictionary(dictionary! {
            "Title" => Object::string_literal("Root/One"),
            "Parent" => outlines_id,
            "Dest" => vec![Object::Reference(pages[0]), Object::Name(b"Fit".to_vec())],
            "First" => child_id,
            "Last" => child_id,
            "Count" => 1,
            "Next" => root_two_id,
        }),
    );
    document.objects.insert(
        child_id,
        Object::Dictionary(dictionary! {
            "Title" => Object::string_literal("Child"),
            "Parent" => root_one_id,
            "Dest" => Object::string_literal("child-dest"),
        }),
    );
    document.objects.insert(
        root_two_id,
        Object::Dictionary(dictionary! {
            "Title" => Object::string_literal("Root Two"),
            "Parent" => outlines_id,
            "Dest" => vec![Object::Reference(pages[3]), Object::Name(b"Fit".to_vec())],
            "Prev" => root_one_id,
        }),
    );
    document.objects.insert(
        outlines_id,
        Object::Dictionary(dictionary! {
            "Type" => "Outlines",
            "First" => root_one_id,
            "Last" => root_two_id,
            "Count" => 3,
        }),
    );
    document.catalog_mut()?.set("Outlines", outlines_id);
    document.catalog_mut()?.set(
        "Names",
        dictionary! {
            "Dests" => dictionary! {
                "Names" => vec![
                    Object::string_literal("child-dest"),
                    Object::Array(vec![Object::Reference(pages[1]), Object::Name(b"Fit".to_vec())]),
                ],
            },
        },
    );
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Source metadata"),
    });
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn plain_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = base_document(&[100])?;
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn base_document(widths: &[i64]) -> Result<Document, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut page_ids = Vec::with_capacity(widths.len());
    for width in widths {
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), (*width).into(), 200.into()],
            "Contents" => content_id,
        });
        page_ids.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids,
            "Count" => i64::try_from(widths.len())?,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
    });
    document.trailer.set("Root", catalog_id);
    Ok(document)
}
