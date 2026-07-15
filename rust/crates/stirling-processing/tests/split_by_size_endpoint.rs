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
async fn splits_by_page_count_with_the_existing_zip_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_split(1, "2", "source.pages.pdf", &[101, 102, 103, 104, 105]).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.pages.zip")
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 3);
    assert_eq!(archive.by_index(0)?.name(), "source.pages_1.pdf");
    assert_eq!(page_widths(&zip_entry(&mut archive, 0)?)?, vec![101, 102]);
    assert_eq!(page_widths(&zip_entry(&mut archive, 1)?)?, vec![103, 104]);
    assert_eq!(page_widths(&zip_entry(&mut archive, 2)?)?, vec![105]);
    Ok(())
}

#[tokio::test]
async fn distributes_extra_pages_across_the_first_documents()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_split(2, "3", "uneven.pdf", &[101, 102, 103, 104, 105, 106, 107]).await?,
        StatusCode::OK,
    )
    .await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 3);
    assert_eq!(page_widths(&zip_entry(&mut archive, 0)?)?.len(), 3);
    assert_eq!(page_widths(&zip_entry(&mut archive, 1)?)?.len(), 2);
    assert_eq!(page_widths(&zip_entry(&mut archive, 2)?)?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_split_arguments_on_the_size_route()
-> Result<(), Box<dyn std::error::Error>> {
    for (split_type, split_value) in [(1, "0"), (2, "nope"), (3, "2")] {
        let response = require_status(
            post_split(split_type, split_value, "invalid.pdf", &[100]).await?,
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
        assert!(body.contains("/api/v1/general/split-by-size-or-count"));
    }
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

async fn post_split(
    split_type: i32,
    split_value: &str,
    filename: &str,
    widths: &[i64],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-split-by-size-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        filename,
        &pdf_with_page_widths(widths)?,
    );
    add_text_part(&mut body, boundary, "splitType", &split_type.to_string());
    add_text_part(&mut body, boundary, "splitValue", split_value);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/split-by-size-or-count")
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

fn pdf_with_page_widths(widths: &[i64]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
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
