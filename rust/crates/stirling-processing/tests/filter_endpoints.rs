use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn filters_literal_text() -> Result<(), Box<dyn std::error::Error>> {
    let pdf = filter_pdf()?;

    assert_passes(
        post_filter(
            "/api/v1/filter/filter-contains-text",
            &pdf,
            &[("pageNumbers", "1"), ("text", "needle text")],
        )
        .await?,
        &pdf,
    )
    .await?;
    assert_status(
        post_filter(
            "/api/v1/filter/filter-contains-text",
            &pdf,
            &[("pageNumbers", "1"), ("text", "absent")],
        )
        .await?,
        StatusCode::NO_CONTENT,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn filters_images_counts_sizes_bytes_and_rotation() -> Result<(), Box<dyn std::error::Error>>
{
    let pdf = filter_pdf()?;

    assert_passes(
        post_filter(
            "/api/v1/filter/filter-contains-image",
            &pdf,
            &[("pageNumbers", "2")],
        )
        .await?,
        &pdf,
    )
    .await?;
    assert_status(
        post_filter(
            "/api/v1/filter/filter-contains-image",
            &pdf,
            &[("pageNumbers", "1")],
        )
        .await?,
        StatusCode::NO_CONTENT,
    )
    .await?;

    assert_passes(
        post_filter(
            "/api/v1/filter/filter-page-count",
            &pdf,
            &[("pageCount", "2"), ("comparator", "Equal")],
        )
        .await?,
        &pdf,
    )
    .await?;
    assert_status(
        post_filter(
            "/api/v1/filter/filter-page-count",
            &pdf,
            &[("pageCount", "2"), ("comparator", "Greater")],
        )
        .await?,
        StatusCode::NO_CONTENT,
    )
    .await?;

    assert_passes(
        post_filter(
            "/api/v1/filter/filter-page-size",
            &pdf,
            &[("standardPageSize", "LETTER"), ("comparator", "Equal")],
        )
        .await?,
        &pdf,
    )
    .await?;
    assert_status(
        post_filter(
            "/api/v1/filter/filter-page-size",
            &pdf,
            &[("standardPageSize", "A4"), ("comparator", "Equal")],
        )
        .await?,
        StatusCode::NO_CONTENT,
    )
    .await?;

    let file_size = pdf.len().to_string();
    assert_passes(
        post_filter(
            "/api/v1/filter/filter-file-size",
            &pdf,
            &[("fileSize", file_size.as_str()), ("comparator", "Equal")],
        )
        .await?,
        &pdf,
    )
    .await?;

    assert_passes(
        post_filter(
            "/api/v1/filter/filter-page-rotation",
            &pdf,
            &[("rotation", "90"), ("comparator", "Equal")],
        )
        .await?,
        &pdf,
    )
    .await?;
    assert_status(
        post_filter(
            "/api/v1/filter/filter-page-rotation",
            &pdf,
            &[("rotation", "90"), ("comparator", "Less")],
        )
        .await?,
        StatusCode::NO_CONTENT,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn rejects_an_unknown_comparator_with_the_filter_path()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_filter(
        "/api/v1/filter/filter-page-count",
        &filter_pdf()?,
        &[("pageCount", "2"), ("comparator", "greater")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert!(String::from_utf8_lossy(&body).contains("/api/v1/filter/filter-page-count"));
    Ok(())
}

async fn assert_passes(
    response: Response,
    original: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.pdf")
    );
    assert_eq!(to_bytes(response.into_body(), usize::MAX).await?, original);
    Ok(())
}

async fn assert_status(
    response: Response,
    expected: StatusCode,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(response, expected).await?;
    if expected == StatusCode::NO_CONTENT {
        assert!(to_bytes(response.into_body(), usize::MAX).await?.is_empty());
    }
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

async fn post_filter(
    path: &str,
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-filter-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
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
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn filter_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let text_content_id = document.add_object(Stream::new(
        Dictionary::new(),
        b"BT /F1 12 Tf 10 20 Td (needle text) Tj ET".to_vec(),
    ));
    let page_one_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => text_content_id,
    });
    let image_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => 1,
            "Height" => 1,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        },
        vec![0, 0, 0],
    ));
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "Resources" => dictionary! {
                "XObject" => dictionary! { "Im0" => image_id },
            },
        },
        b"/Im0 Do".to_vec(),
    ));
    let page_two_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
        "Resources" => dictionary! { "XObject" => dictionary! { "Fm0" => form_id } },
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_one_id), Object::Reference(page_two_id)],
            "Count" => 2,
            "Rotate" => 90,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
