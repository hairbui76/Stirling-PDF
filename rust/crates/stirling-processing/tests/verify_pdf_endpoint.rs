use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use serde_json::{Value, json};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn reports_java_compatible_not_pdfa_result_without_external_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let response =
        require_status(post_pdf(Some(&pdf_with_xmp(None)?)).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(
        body,
        json!([{
            "standard": "not-pdfa",
            "standardName": "Not PDF/A (no PDF/A identification metadata)",
            "validationProfile": null,
            "validationProfileName": null,
            "complianceSummary": "Not PDF/A (no PDF/A identification metadata)",
            "declaredPdfa": false,
            "compliant": false,
            "totalFailures": 1,
            "totalWarnings": 0,
            "failures": [{
                "ruleId": null,
                "message": "Document does not declare PDF/A compliance in its XMP metadata.",
                "location": null,
                "specification": "XMP pdfaid",
                "clause": null,
                "testNumber": null
            }],
            "warnings": []
        }])
    );
    Ok(())
}

#[tokio::test]
async fn ignores_incomplete_pdfa_identification_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let xmp = br#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:id="http://www.aiim.org/pdfa/ns/id/" id:part="2"/></rdf:RDF>"#;
    let response = require_status(
        post_pdf(Some(&pdf_with_xmp(Some(xmp))?)).await?,
        StatusCode::OK,
    )
    .await?;
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(body[0]["standard"], "not-pdfa");
    assert_eq!(body.as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn validates_required_file_and_pdf_syntax() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(post_pdf(None).await?.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        post_pdf(Some(b"not a PDF")).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn post_pdf(pdf: Option<&[u8]>) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-verify-pdf-boundary";
    let mut body = Vec::new();
    if let Some(pdf) = pdf {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(pdf);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/verify-pdf")
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
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

fn pdf_with_xmp(xmp: Option<&[u8]>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let leaf_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 180.into(), 120.into()],
        "Resources" => Dictionary::new(),
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(leaf_id)],
            "Count" => 1,
        }),
    );
    let mut catalog = dictionary! { "Type" => "Catalog", "Pages" => page_tree_id };
    if let Some(xmp) = xmp {
        let metadata_id = document.add_object(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            xmp.to_vec(),
        ));
        catalog.set("Metadata", metadata_id);
    }
    let catalog_id = document.add_object(catalog);
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
