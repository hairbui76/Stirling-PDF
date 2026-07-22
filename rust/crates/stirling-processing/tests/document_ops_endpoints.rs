use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn removes_and_flattens_signature_fields_only() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/security/remove-cert-sign",
            "signed.pdf",
            &pdf_with_signature_and_text_field()?,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("signed_unsigned.pdf")
    );
    let output = response_document(response).await?;
    let acroform_id = output.catalog()?.get(b"AcroForm")?.as_reference()?;
    let fields = output
        .get_dictionary(acroform_id)?
        .get(b"Fields")?
        .as_array()?;
    assert_eq!(fields.len(), 1);
    assert_eq!(
        output
            .get_dictionary(fields[0].as_reference()?)?
            .get(b"FT")?
            .as_name()?,
        b"Tx"
    );
    Ok(())
}

#[tokio::test]
async fn decompresses_filtered_streams_without_recompressing_them()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/misc/decompress-pdf",
            "compressed.pdf",
            &pdf_with_compressed_content()?,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("compressed_decompressed.pdf")
    );
    let output = response_document(response).await?;
    let page_id = output
        .get_pages()
        .into_values()
        .next()
        .ok_or("missing page")?;
    let content_id = output
        .get_dictionary(page_id)?
        .get(b"Contents")?
        .as_reference()?;
    let stream = output.get_object(content_id)?.as_stream()?;
    assert!(!stream.dict.has(b"Filter"));
    assert_eq!(stream.content, b"BT (decompressed) Tj ET");
    Ok(())
}

#[tokio::test]
async fn unlocks_field_flags_locks_and_xfa_access() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/misc/unlock-pdf-forms",
            "locked.pdf",
            &pdf_with_locked_form()?,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("locked_unlocked_forms.pdf")
    );
    let output = response_document(response).await?;
    let acroform_id = output.catalog()?.get(b"AcroForm")?.as_reference()?;
    let acroform = output.get_dictionary(acroform_id)?;
    assert!(acroform.get(b"NeedAppearances")?.as_bool()?);
    let field_id = acroform.get(b"Fields")?.as_array()?[0].as_reference()?;
    let field = output.get_dictionary(field_id)?;
    assert_eq!(field.get(b"Ff")?.as_i64()?, 0);
    assert!(!field.has(b"Lock"));
    let xfa_id = acroform.get(b"XFA")?.as_reference()?;
    let xfa = output
        .get_object(xfa_id)?
        .as_stream()?
        .decompressed_content()?;
    assert!(String::from_utf8(xfa)?.contains("access=\"open\""));
    Ok(())
}

#[tokio::test]
async fn removes_direct_and_nested_images_but_preserves_form_xobjects()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/general/remove-image-pdf",
            "images.pdf",
            &pdf_with_direct_and_nested_images()?,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("images_images_removed.pdf")
    );
    let output = response_document(response).await?;
    let page_id = output
        .get_pages()
        .into_values()
        .next()
        .ok_or("missing page")?;
    let resources = output
        .get_dictionary(page_id)?
        .get(b"Resources")?
        .as_dict()?;
    let xobjects = resources.get(b"XObject")?.as_dict()?;
    assert!(!xobjects.has(b"Im0"));
    let form_id = xobjects.get(b"Fm0")?.as_reference()?;
    let form = output.get_object(form_id)?.as_stream()?;
    let nested = form
        .dict
        .get(b"Resources")?
        .as_dict()?
        .get(b"XObject")?
        .as_dict()?;
    assert!(!nested.has(b"NestedIm"));
    Ok(())
}

#[tokio::test]
async fn repairs_by_parsing_and_rewriting_the_pdf_structure()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/misc/repair",
            "damaged.pdf",
            &save(basic_document().0)?,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("damaged_repaired.pdf")
    );
    let output = response_document(response).await?;
    assert_eq!(output.get_pages().len(), 1);
    Ok(())
}

async fn response_document(response: Response) -> Result<Document, Box<dyn std::error::Error>> {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(Document::load_mem(&bytes)?)
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

async fn post_pdf(
    path: &str,
    filename: &str,
    pdf: &[u8],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-document-op-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
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

fn basic_document() -> (Document, lopdf::ObjectId) {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
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
    (document, page_id)
}

fn save(mut document: Document) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn pdf_with_signature_and_text_field() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (mut document, page_id) = basic_document();
    let signature_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Sig",
        "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
    });
    let text_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Tx",
        "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
    });
    document.get_dictionary_mut(page_id)?.set(
        "Annots",
        vec![Object::Reference(signature_id), Object::Reference(text_id)],
    );
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(signature_id), Object::Reference(text_id)],
        "SigFlags" => 3,
    });
    document.catalog_mut()?.set("AcroForm", acroform_id);
    save(document)
}

fn pdf_with_compressed_content() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (mut document, page_id) = basic_document();
    let mut stream = Stream::new(Dictionary::new(), b"BT (decompressed) Tj ET".to_vec());
    stream.compress()?;
    let content_id = document.add_object(stream);
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", content_id);
    save(document)
}

fn pdf_with_locked_form() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (mut document, _) = basic_document();
    let field_id = document.add_object(dictionary! {
        "FT" => "Tx",
        "T" => Object::string_literal("locked"),
        "Ff" => 1,
        "Lock" => dictionary! { "Action" => "All" },
    });
    let xfa_id = document.add_object(Stream::new(
        dictionary! {},
        br#"<field access = "readOnly">test</field>"#.to_vec(),
    ));
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(field_id)],
        "XFA" => xfa_id,
    });
    document.catalog_mut()?.set("AcroForm", acroform_id);
    save(document)
}

fn pdf_with_direct_and_nested_images() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (mut document, page_id) = basic_document();
    let direct_image_id = document.add_object(Stream::new(
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
    let nested_image_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => 1,
            "Height" => 1,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        },
        vec![255, 255, 255],
    ));
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "Resources" => dictionary! {
                "XObject" => dictionary! { "NestedIm" => nested_image_id },
            },
        },
        b"/NestedIm Do".to_vec(),
    ));
    document.get_dictionary_mut(page_id)?.set(
        "Resources",
        dictionary! {
            "XObject" => dictionary! {
                "Im0" => direct_image_id,
                "Fm0" => form_id,
            },
        },
    );
    save(document)
}
