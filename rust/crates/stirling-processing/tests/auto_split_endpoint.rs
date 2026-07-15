use std::{
    fs,
    io::{Cursor, Read},
    path::PathBuf,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::{
    app,
    pdf_merge::{MergeInput, MergeOptions, merge_pdf_paths_to_file},
};
use tempfile::tempdir;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn returns_one_document_when_no_divider_is_present() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_auto_split(&text_pdf(3)?, "plain.pdf", None).await?;
    if unavailable_without_configuration(&response)? {
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"plain.zip\""
    );
    let entries = zip_documents(&response_bytes(response).await?)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "plain_1.pdf");
    assert_eq!(entries[0].1.get_pages().len(), 3);
    Ok(())
}

#[tokio::test]
async fn native_qr_detection_splits_and_duplex_skips_the_divider_back()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_none() {
        return Ok(());
    }
    let directory = tempdir()?;
    let before = write_pdf(directory.path().join("before.pdf"), &text_pdf(1)?)?;
    let back = write_pdf(directory.path().join("back.pdf"), &text_pdf(1)?)?;
    let after = write_pdf(directory.path().join("after.pdf"), &text_pdf(1)?)?;
    let divider = repository_root().join(
        "app/core/src/main/resources/static/files/Auto Splitter Divider (with instructions).pdf",
    );
    let merged = directory.path().join("packet.pdf");
    merge_pdf_paths_to_file(
        &[
            merge_input("before.pdf", before),
            merge_input("divider.pdf", divider),
            merge_input("back.pdf", back),
            merge_input("after.pdf", after),
        ],
        MergeOptions::default(),
        &merged,
    )?;
    let merged = fs::read(merged)?;

    let normal_response = require_status(
        post_auto_split(&merged, "packet.pdf", Some("false")).await?,
        StatusCode::OK,
    )
    .await?;
    let duplex_response = require_status(
        post_auto_split(&merged, "packet.pdf", Some("true")).await?,
        StatusCode::OK,
    )
    .await?;
    let normal = zip_documents(&response_bytes(normal_response).await?)?;
    let duplex = zip_documents(&response_bytes(duplex_response).await?)?;
    assert_eq!(normal.len(), 2);
    assert_eq!(duplex.len(), 2);
    assert_eq!(normal[0].0, "packet_1.pdf");
    assert_eq!(normal[1].0, "packet_2.pdf");
    let normal_pages = normal
        .iter()
        .map(|(_, document)| document.get_pages().len())
        .sum::<usize>();
    let duplex_pages = duplex
        .iter()
        .map(|(_, document)| document.get_pages().len())
        .sum::<usize>();
    assert_eq!(normal_pages, duplex_pages + 1);
    assert_eq!(
        duplex[1].1.get_pages().len(),
        normal[1].1.get_pages().len() - 1
    );
    Ok(())
}

#[tokio::test]
async fn validates_boolean_and_required_upload() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_auto_split(&text_pdf(1)?, "bad.pdf", Some("perhaps")).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: serde_json::Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(error["path"], "/api/v1/misc/auto-split-pdf");

    let boundary = "missing-auto-split-file";
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/auto-split-pdf")
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

fn unavailable_without_configuration(
    response: &Response,
) -> Result<bool, Box<dyn std::error::Error>> {
    if response.status() != StatusCode::NOT_IMPLEMENTED {
        return Ok(false);
    }
    if std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some() {
        return Err(
            std::io::Error::other("configured PDFium runtime did not execute auto split").into(),
        );
    }
    Ok(true)
}

fn zip_documents(bytes: &[u8]) -> Result<Vec<(String, Document)>, Box<dyn std::error::Error>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    let mut documents = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        let mut pdf = Vec::new();
        entry.read_to_end(&mut pdf)?;
        documents.push((name, Document::load_mem(&pdf)?));
    }
    Ok(documents)
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

async fn post_auto_split(
    pdf: &[u8],
    filename: &str,
    duplex_mode: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-auto-split-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    if let Some(duplex_mode) = duplex_mode {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"duplexMode\"\r\n\r\n{duplex_mode}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/auto-split-pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn text_pdf(page_count: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut pages = Vec::new();
    for page_index in 0..page_count {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            format!("BT (Page {}) Tj ET", page_index + 1).into_bytes(),
        ));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 300.into(), 300.into()],
            "Resources" => dictionary! {},
            "Contents" => content_id,
        }));
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(page_count)?,
        }),
    );
    let catalog_id = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn write_pdf(path: PathBuf, bytes: &[u8]) -> Result<PathBuf, std::io::Error> {
    fs::write(&path, bytes)?;
    Ok(path)
}

fn merge_input(filename: &str, path: PathBuf) -> MergeInput {
    MergeInput {
        filename: filename.to_owned(),
        path,
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}
