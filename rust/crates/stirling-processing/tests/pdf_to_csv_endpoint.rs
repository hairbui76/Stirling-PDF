use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn pdf_to_csv_route_requires_an_upload() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_multipart(None).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn pdf_to_csv_route_extracts_a_ruled_table_or_reports_missing_pdfium()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = ruled_table_pdf()?;
    let response = post_multipart(Some(("table.pdf", "application/pdf", &pdf))).await?;
    if response.status() == StatusCode::NOT_IMPLEMENTED {
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/csv");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("table_extracted.csv")
    );
    assert_eq!(
        response_bytes(response).await?,
        b"\"A\",\"B\"\r\n\"C\",\"D\"\r\n"
    );
    Ok(())
}

async fn post_multipart(
    file: Option<(&str, &str, &[u8])>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-csv-boundary";
    let mut body = Vec::new();
    if let Some((filename, content_type, bytes)) = file {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/csv")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
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

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

fn ruled_table_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"1 w 10 10 m 190 10 l S 10 100 m 190 100 l S 10 190 m 190 190 l S 10 10 m 10 190 l S 100 10 m 100 190 l S 190 10 m 190 190 l S BT /F1 12 Tf 30 145 Td (A) Tj ET BT /F1 12 Tf 120 145 Td (B) Tj ET BT /F1 12 Tf 30 55 Td (C) Tj ET BT /F1 12 Tf 120 55 Td (D) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
