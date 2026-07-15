use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{
    Dictionary, Document, EncryptionState, EncryptionVersion, Object, Permissions, Stream,
    dictionary,
};
use serde_json::{Value, json};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn returns_java_compatible_analysis_json() -> Result<(), Box<dyn std::error::Error>> {
    let pdf = analysis_pdf()?;

    let page_count = post_json("/api/v1/analysis/page-count", &pdf).await?;
    assert_eq!(page_count, json!({ "pageCount": 2 }));

    let basic_info = post_json("/api/v1/analysis/basic-info", &pdf).await?;
    assert_eq!(basic_info["pageCount"], 2);
    assert_eq!(basic_info["pdfVersion"], 1.7);
    assert_eq!(basic_info["fileSize"], u64::try_from(pdf.len())?);

    let properties = post_json("/api/v1/analysis/document-properties", &pdf).await?;
    assert_eq!(properties["title"], "Analysis fixture");
    assert_eq!(properties["author"], "Stirling");
    assert_eq!(properties["subject"], Value::Null);
    assert_eq!(properties["creationDate"], "D:20260715123456+07'00'");

    let dimensions = post_json("/api/v1/analysis/page-dimensions", &pdf).await?;
    assert_eq!(
        dimensions,
        json!([
            { "width": 180.0, "height": 260.0 },
            { "width": 400.0, "height": 500.0 }
        ])
    );

    let fields = post_json("/api/v1/analysis/form-fields", &pdf).await?;
    assert_eq!(
        fields,
        json!({
            "fieldCount": 2,
            "hasXFA": true,
            "isSignaturesExist": true
        })
    );

    let annotations = post_json("/api/v1/analysis/annotation-info", &pdf).await?;
    assert_eq!(
        annotations,
        json!({
            "totalCount": 3,
            "typeBreakdown": { "Link": 1, "Widget": 2 }
        })
    );

    let fonts = post_json("/api/v1/analysis/font-info", &pdf).await?;
    assert_eq!(fonts, json!({ "fontCount": 2, "fonts": ["F1", "F2"] }));

    let security = post_json("/api/v1/analysis/security-info", &pdf).await?;
    assert_eq!(security, json!({ "isEncrypted": false }));
    Ok(())
}

#[tokio::test]
async fn reports_empty_password_encryption_and_permissions()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = encrypted_pdf()?;
    let security = post_json("/api/v1/analysis/security-info", &pdf).await?;
    assert_eq!(
        security,
        json!({
            "isEncrypted": true,
            "keyLength": 128,
            "permissions": {
                "preventPrinting": false,
                "preventModify": true,
                "preventExtractContent": true,
                "preventModifyAnnotations": true
            }
        })
    );
    Ok(())
}

async fn post_json(path: &str, pdf: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let response = require_status(post_pdf(path, pdf).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
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

async fn post_pdf(path: &str, pdf: &[u8]) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-analysis-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"analysis.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
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

fn analysis_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let font_one_id = document.add_object(font("Helvetica"));
    let font_two_id = document.add_object(font("Courier"));
    let signature_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Sig",
        "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
    });
    let text_field_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Tx",
        "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
    });
    let link_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Link",
        "Rect" => vec![20.into(), 20.into(), 30.into(), 30.into()],
    });
    let page_one_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
        "CropBox" => vec![10.into(), 20.into(), 190.into(), 280.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_one_id } },
        "Annots" => vec![Object::Reference(link_id), Object::Reference(signature_id)],
    });
    let page_two_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 400.into(), 500.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F2" => font_two_id } },
        "Annots" => vec![Object::Reference(text_field_id)],
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_one_id), Object::Reference(page_two_id)],
            "Count" => 2,
        }),
    );
    let xfa_id = document.add_object(Stream::new(Dictionary::new(), b"<xfa/>".to_vec()));
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(signature_id), Object::Reference(text_field_id)],
        "XFA" => xfa_id,
    });
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
        "AcroForm" => acroform_id,
    });
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Analysis fixture"),
        "Author" => Object::string_literal("Stirling"),
        "CreationDate" => Object::string_literal("D:20260715123456+07'00'"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    save(document)
}

fn encrypted_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = basic_pdf();
    document.trailer.set(
        "ID",
        vec![
            Object::string_literal("stirling-analysis-encrypted-id"),
            Object::string_literal("stirling-analysis-encrypted-id"),
        ],
    );
    let state = EncryptionState::try_from(EncryptionVersion::V2 {
        document: &document,
        owner_password: "owner-password",
        user_password: "",
        key_length: 128,
        permissions: Permissions::PRINTABLE,
    })?;
    document.encrypt(&state)?;
    save(document)
}

fn basic_pdf() -> Document {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
    });
    document.trailer.set("Root", catalog_id);
    document
}

fn font(base_font: &str) -> Dictionary {
    dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => Object::Name(base_font.as_bytes().to_vec()),
    }
}

fn save(mut document: Document) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
