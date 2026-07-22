use std::io::{Cursor, Read as _};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, ObjectId};
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

struct SvgUpload<'a> {
    filename: &'a str,
    bytes: &'a [u8],
}

#[tokio::test]
async fn converts_one_svg_to_a_vector_pdf_with_intrinsic_dimensions()
-> Result<(), Box<dyn std::error::Error>> {
    let svg = svg(120, 80, "red");
    let response = post_svgs(
        &[SvgUpload {
            filename: "diagram.svg",
            bytes: svg.as_bytes(),
        }],
        None,
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("diagram.pdf")
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let page_id = document.get_pages()[&1];
    assert_eq!(page_size(&document, page_id)?, (120.0, 80.0));
    assert!(!document.get_page_content(page_id).is_empty());
    Ok(())
}

#[tokio::test]
async fn returns_separate_pdfs_in_a_named_zip() -> Result<(), Box<dyn std::error::Error>> {
    let first = svg(100, 50, "red");
    let second = svg(30, 70, "blue");
    let response = post_svgs(
        &[
            SvgUpload {
                filename: "first.svg",
                bytes: first.as_bytes(),
            },
            SvgUpload {
                filename: "second.SVG",
                bytes: second.as_bytes(),
            },
        ],
        Some(false),
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("first_converted_svgs.zip")
    );
    let mut archive = ZipArchive::new(Cursor::new(response_bytes(response).await?))?;
    assert_eq!(archive.len(), 2);
    for (name, size) in [("first.pdf", (100.0, 50.0)), ("second.pdf", (30.0, 70.0))] {
        let mut entry = archive.by_name(name)?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        let document = Document::load_mem(&bytes)?;
        assert_eq!(page_size(&document, document.get_pages()[&1])?, size);
    }
    Ok(())
}

#[tokio::test]
async fn combines_svg_files_as_differently_sized_pdf_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let first = svg(100, 50, "red");
    let second = svg(30, 70, "blue");
    let response = post_svgs(
        &[
            SvgUpload {
                filename: "first.svg",
                bytes: first.as_bytes(),
            },
            SvgUpload {
                filename: "second.svg",
                bytes: second.as_bytes(),
            },
        ],
        Some(true),
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("first_combined.pdf")
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages();
    assert_eq!(pages.len(), 2);
    assert_eq!(page_size(&document, pages[&1])?, (100.0, 50.0));
    assert_eq!(page_size(&document, pages[&2])?, (30.0, 70.0));
    Ok(())
}

#[tokio::test]
async fn defaults_missing_dimensions_to_a4_and_skips_bad_batch_members()
-> Result<(), Box<dyn std::error::Error>> {
    let dimensionless = br#"<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0 L10 10"/></svg>"#;
    let response = post_svgs(
        &[
            SvgUpload {
                filename: "broken.svg",
                bytes: b"not svg",
            },
            SvgUpload {
                filename: "valid.svg",
                bytes: dimensionless,
            },
        ],
        Some(false),
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let (width, height) = page_size(&document, document.get_pages()[&1])?;
    assert!((width - 595.0).abs() < 0.01);
    assert!((height - 842.0).abs() < 0.01);
    Ok(())
}

#[tokio::test]
async fn rejects_missing_non_svg_unsafe_invalid_and_bad_boolean_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_svgs(&[], None).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_svgs(
            &[SvgUpload {
                filename: "image.png",
                bytes: b"not svg",
            }],
            None,
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    let unsafe_svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><image href="file:///secret"/></svg>"#;
    assert_eq!(
        post_svgs(
            &[SvgUpload {
                filename: "unsafe.svg",
                bytes: unsafe_svg,
            }],
            None,
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_svgs(
            &[SvgUpload {
                filename: "broken.svg",
                bytes: b"<svg",
            }],
            None,
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_svgs_with_boolean_text(
            &[SvgUpload {
                filename: "valid.svg",
                bytes: svg(10, 10, "red").as_bytes(),
            }],
            "sometimes",
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn post_svgs(
    files: &[SvgUpload<'_>],
    combine: Option<bool>,
) -> Result<Response, Box<dyn std::error::Error>> {
    match combine {
        Some(value) => {
            post_svgs_with_boolean_text(files, if value { "true" } else { "false" }).await
        }
        None => post_svgs_body(files, None).await,
    }
}

async fn post_svgs_with_boolean_text(
    files: &[SvgUpload<'_>],
    combine: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    post_svgs_body(files, Some(combine)).await
}

async fn post_svgs_body(
    files: &[SvgUpload<'_>],
    combine: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-svg-to-pdf-boundary";
    let mut body = Vec::new();
    for file in files {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{}\"\r\nContent-Type: image/svg+xml\r\n\r\n",
                file.filename
            )
            .as_bytes(),
        );
        body.extend_from_slice(file.bytes);
        body.extend_from_slice(b"\r\n");
    }
    if let Some(combine) = combine {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"combineIntoSinglePdf\"\r\n\r\n{combine}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/svg/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
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

fn page_size(document: &Document, page_id: ObjectId) -> Result<(f32, f32), lopdf::Error> {
    let page = document.get_dictionary(page_id)?;
    let (_, media_box) = document.dereference(page.get(b"MediaBox")?)?;
    let media_box = media_box.as_array()?;
    Ok((
        media_box[2].as_float()? - media_box[0].as_float()?,
        media_box[3].as_float()? - media_box[1].as_float()?,
    ))
}

fn svg(width: u32, height: u32, color: &str) -> String {
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\"><rect width=\"{width}\" height=\"{height}\" fill=\"{color}\"/></svg>"
    )
}
