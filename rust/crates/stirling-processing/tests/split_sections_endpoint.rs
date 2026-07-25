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
async fn merges_every_section_in_java_iteration_order() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_sections(
            &[100, 200],
            &[
                ("horizontalDivisions", "0"),
                ("verticalDivisions", "1"),
                ("merge", "true"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("sections_split.pdf")
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let output = Document::load_mem(&bytes)?;
    assert_eq!(output.get_pages().len(), 4);
    assert_eq!(
        page_sizes(&output)?,
        vec![(100, 100), (100, 100), (200, 100), (200, 100)]
    );
    assert!(output.catalog()?.get(b"AcroForm").is_err());
    Ok(())
}

#[tokio::test]
async fn emits_unsplit_and_custom_split_pages_as_separate_zip_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_sections(
            &[100, 200],
            &[
                ("horizontalDivisions", "1"),
                ("verticalDivisions", "0"),
                ("merge", "false"),
                ("splitMode", "CUSTOM"),
                ("pageNumbers", "2"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 3);
    assert_eq!(archive.by_index(0)?.name(), "sections_split_1_1.pdf");
    assert_eq!(archive.by_index(1)?.name(), "sections_split_2_1.pdf");
    assert_eq!(archive.by_index(2)?.name(), "sections_split_2_2.pdf");
    assert_eq!(single_page_size(&zip_entry(&mut archive, 0)?)?, (100, 200));
    assert_eq!(single_page_size(&zip_entry(&mut archive, 1)?)?, (100, 200));
    assert_eq!(single_page_size(&zip_entry(&mut archive, 2)?)?, (100, 200));
    Ok(())
}

#[tokio::test]
async fn requires_page_numbers_for_custom_mode() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_sections(
            &[100],
            &[
                ("horizontalDivisions", "1"),
                ("verticalDivisions", "1"),
                ("merge", "true"),
                ("splitMode", "CUSTOM"),
            ],
        )
        .await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("pageNumbers is required"));
    assert!(body.contains("/api/v1/general/split-pdf-by-sections"));
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

fn single_page_size(bytes: &[u8]) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let document = Document::load_mem(bytes)?;
    Ok(page_sizes(&document)?[0])
}

fn page_sizes(document: &Document) -> Result<Vec<(i64, i64)>, Box<dyn std::error::Error>> {
    document
        .get_pages()
        .into_values()
        .map(|page_id| {
            let media_box = document
                .get_dictionary(page_id)?
                .get(b"MediaBox")?
                .as_array()?;
            Ok((media_box[2].as_i64()?, media_box[3].as_i64()?))
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

async fn post_sections(
    widths: &[i64],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-split-sections-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "sections.pdf",
        &pdf_with_page_widths(widths)?,
    );
    for (name, value) in fields {
        add_text_part(&mut body, boundary, name, value);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/split-pdf-by-sections")
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
        let content_id =
            document.add_object(Stream::new(dictionary! {}, b"0 0 m 10 10 l S".to_vec()));
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
            "Resources" => dictionary! {},
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
        "AcroForm" => dictionary! { "Fields" => Vec::<Object>::new() },
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
