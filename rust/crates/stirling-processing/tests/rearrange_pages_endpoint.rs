use std::collections::HashSet;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn applies_a_custom_page_order_without_a_browser_change()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-rearrange-custom-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "source.order.pdf",
        &pdf_with_page_widths(&[101, 102, 103])?,
    );
    add_text_part(&mut body, boundary, "pageNumbers", "3,1,2");
    add_text_part(&mut body, boundary, "customMode", "custom");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_rearrange(body, boundary).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.order_rearranged.pdf")
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(page_widths(&bytes)?, vec![103, 101, 102]);
    Ok(())
}

#[tokio::test]
async fn creates_distinct_page_nodes_for_duplicate_mode() -> Result<(), Box<dyn std::error::Error>>
{
    let boundary = "stirling-rearrange-duplicate-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "duplicate.pdf",
        &pdf_with_page_widths(&[101, 102])?,
    );
    add_text_part(&mut body, boundary, "pageNumbers", "3");
    add_text_part(&mut body, boundary, "customMode", "DUPLICATE");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_rearrange(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    assert_eq!(page_widths(&bytes)?, vec![101, 101, 101, 102, 102, 102]);
    assert_eq!(page_ids.len(), 6);
    assert_eq!(page_ids.iter().copied().collect::<HashSet<_>>().len(), 6);
    Ok(())
}

#[tokio::test]
async fn preserves_side_stitch_padding_order_and_distinct_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-rearrange-booklet-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "booklet.pdf",
        &pdf_with_page_widths(&[101, 102, 103, 104, 105, 106])?,
    );
    add_text_part(
        &mut body,
        boundary,
        "customMode",
        "SIDE_STITCH_BOOKLET_SORT",
    );
    finish_multipart(&mut body, boundary);

    let response = require_status(post_rearrange(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    assert_eq!(
        page_widths(&bytes)?,
        vec![104, 101, 102, 103, 106, 105, 106, 106]
    );
    assert_eq!(page_ids.iter().copied().collect::<HashSet<_>>().len(), 8);
    Ok(())
}

#[tokio::test]
async fn rejects_unknown_modes_with_the_rearrange_path() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-invalid-rearrange-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "invalid.pdf",
        &pdf_with_page_widths(&[100])?,
    );
    add_text_part(&mut body, boundary, "customMode", "NOT_A_MODE");
    finish_multipart(&mut body, boundary);

    let response = require_status(
        post_rearrange(body, boundary).await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("unsupported custom mode"));
    assert!(body.contains("/api/v1/general/rearrange-pages"));
    Ok(())
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

async fn post_rearrange(
    body: Vec<u8>,
    boundary: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/rearrange-pages")
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
