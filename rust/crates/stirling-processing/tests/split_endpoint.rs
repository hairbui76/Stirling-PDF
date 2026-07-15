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
async fn splits_after_selected_pages_into_the_existing_zip_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-split-pages-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "source.pages.pdf",
        &pdf_with_page_widths(&[101, 102, 103, 104, 105])?,
    );
    add_text_part(&mut body, boundary, "pageNumbers", "2,4");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_split(body, boundary).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.pages_split.zip")
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 3);
    assert_eq!(archive.by_index(0)?.name(), "source.pages_1.pdf");
    assert_eq!(archive.by_index(1)?.name(), "source.pages_2.pdf");
    assert_eq!(archive.by_index(2)?.name(), "source.pages_3.pdf");
    assert_eq!(page_widths(&zip_entry(&mut archive, 0)?)?, vec![101, 102]);
    assert_eq!(page_widths(&zip_entry(&mut archive, 1)?)?, vec![103, 104]);
    assert_eq!(page_widths(&zip_entry(&mut archive, 2)?)?, vec![105]);
    Ok(())
}

#[tokio::test]
async fn keeps_only_live_form_fields_in_each_split() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-split-form-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "form.pdf", &pdf_with_two_page_form()?);
    add_text_part(&mut body, boundary, "pageNumbers", "all");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_split(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    for (index, expected_name) in [b"first".as_slice(), b"second".as_slice()]
        .into_iter()
        .enumerate()
    {
        let split = Document::load_mem(&zip_entry(&mut archive, index)?)?;
        let acroform_id = split.catalog()?.get(b"AcroForm")?.as_reference()?;
        let fields = split
            .get_dictionary(acroform_id)?
            .get(b"Fields")?
            .as_array()?;
        assert_eq!(fields.len(), 1);
        assert_eq!(
            split
                .get_dictionary(fields[0].as_reference()?)?
                .get(b"T")?
                .as_str()?,
            expected_name
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_unsafe_expressions_with_the_split_path() -> Result<(), Box<dyn std::error::Error>>
{
    let boundary = "stirling-invalid-split-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "invalid.pdf",
        &pdf_with_page_widths(&[100])?,
    );
    add_text_part(&mut body, boundary, "pageNumbers", "n^2");
    finish_multipart(&mut body, boundary);

    let response =
        require_status(post_split(body, boundary).await?, StatusCode::BAD_REQUEST).await?;
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("Invalid expression format"));
    assert!(body.contains("/api/v1/general/split-pages"));
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

async fn post_split(body: Vec<u8>, boundary: &str) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/split-pages")
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

fn finish_multipart(body: &mut Vec<u8>, boundary: &str) {
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
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

fn pdf_with_two_page_form() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::load_mem(&pdf_with_page_widths(&[100, 200])?)?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    let first = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Tx",
        "T" => Object::string_literal("first"),
        "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
        "P" => page_ids[0],
    });
    let second = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Tx",
        "T" => Object::string_literal("second"),
        "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
        "P" => page_ids[1],
    });
    document
        .get_dictionary_mut(page_ids[0])?
        .set("Annots", vec![Object::Reference(first)]);
    document
        .get_dictionary_mut(page_ids[1])?
        .set("Annots", vec![Object::Reference(second)]);
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(first), Object::Reference(second)],
    });
    document.catalog_mut()?.set("AcroForm", acroform_id);
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
