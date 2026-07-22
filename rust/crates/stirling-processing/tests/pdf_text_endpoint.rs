use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn extracts_multi_page_utf8_plain_text() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(&text_pdf()?, Some("txt")).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.txt")
    );
    let text = String::from_utf8(response_bytes(response).await?)?;
    assert!(text.contains("First page"));
    assert!(text.contains("Second page"));
    assert!(text.find("First page") < text.find("Second page"));
    Ok(())
}

#[tokio::test]
async fn emits_a_valid_text_only_rtf_document() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(&text_pdf()?, Some("rtf")).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.rtf")
    );
    let rtf = String::from_utf8(response_bytes(response).await?)?;
    assert!(rtf.starts_with("{\\rtf1"));
    assert!(rtf.contains("First page"));
    assert!(rtf.contains("Second page"));
    assert!(rtf.contains("\\par"));
    assert!(rtf.ends_with('}'));
    Ok(())
}

#[tokio::test]
async fn validates_format_upload_and_pdf_data() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_pdf(&text_pdf()?, Some("docx")).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_pdf(&text_pdf()?, None).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_pdf(b"not a pdf", Some("txt")).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let boundary = "stirling-pdf-text-missing";
    let response = app(1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/text")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"outputFormat\"\r\n\r\ntxt\r\n--{boundary}--\r\n"
                )))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

async fn post_pdf(
    pdf: &[u8],
    output_format: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-text-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    if let Some(output_format) = output_format {
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"outputFormat\"\r\n\r\n{output_format}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/text")
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

fn text_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let mut pages = Vec::new();
    for text in ["First page", "Second page"] {
        let content = document.add_object(Stream::new(
            dictionary! {},
            format!("BT /F1 12 Tf 10 50 Td ({text}) Tj ET").into_bytes(),
        ));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content,
        }));
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => 2,
        }),
    );
    let catalog = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
