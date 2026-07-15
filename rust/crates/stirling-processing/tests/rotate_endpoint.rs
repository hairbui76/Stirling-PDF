use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn rotates_every_page_and_preserves_the_browser_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-rotate-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "quarter.turn.pdf",
        &pdf_with_rotations(&[0, 90])?,
    );
    add_text_part(&mut body, boundary, "angle", "90");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_rotate(body, boundary).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("quarter.turn_rotated.pdf")
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(page_rotations(&bytes)?, vec![90, 180]);
    Ok(())
}

#[tokio::test]
async fn defaults_the_rotation_angle_to_ninety_degrees() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-default-rotate-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "default.pdf",
        &pdf_with_rotations(&[270])?,
    );
    finish_multipart(&mut body, boundary);

    let response = require_status(post_rotate(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let rotations = page_rotations(&bytes)?;
    assert!(rotations == [0] || rotations == [360]);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_angles_with_the_rotate_api_path() -> Result<(), Box<dyn std::error::Error>>
{
    let boundary = "stirling-invalid-rotate-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "invalid.pdf",
        &pdf_with_rotations(&[0])?,
    );
    add_text_part(&mut body, boundary, "angle", "45");
    finish_multipart(&mut body, boundary);

    let response =
        require_status(post_rotate(body, boundary).await?, StatusCode::BAD_REQUEST).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8(bytes.to_vec())?;
    assert!(body.contains("Angle must be a multiple of 90"));
    assert!(body.contains("/api/v1/general/rotate-pdf"));
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

async fn post_rotate(
    body: Vec<u8>,
    boundary: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/rotate-pdf")
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

fn pdf_with_rotations(rotations: &[i64]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut page_ids = Vec::with_capacity(rotations.len());
    for rotation in rotations {
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
            "Rotate" => *rotation,
        });
        page_ids.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids,
            "Count" => i64::try_from(rotations.len())?,
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

fn page_rotations(bytes: &[u8]) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let document = Document::load_mem(bytes)?;
    document
        .get_pages()
        .into_values()
        .map(|page_id| Ok(document.get_dictionary(page_id)?.get(b"Rotate")?.as_i64()?))
        .collect()
}
