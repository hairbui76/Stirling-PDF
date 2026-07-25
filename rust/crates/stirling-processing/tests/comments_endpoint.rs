use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn adds_valid_sticky_notes_and_skips_invalid_specs() -> Result<(), Box<dyn std::error::Error>>
{
    let comments = r#"[
        {"pageIndex":0,"x":10,"y":20,"width":30,"height":40,"text":"Nhận xét 😀","author":"  ","subject":"Review"},
        null,
        {"pageIndex":0,"x":1,"y":2,"width":10,"height":10,"text":"   "},
        {"pageIndex":9,"x":1,"y":2,"width":10,"height":10,"text":"bad page"},
        {"pageIndex":0,"x":1,"y":2,"width":0,"height":10,"text":"bad size"}
    ]"#;
    let response = require_status(
        post_comments(&basic_pdf()?, Some(comments)).await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_commented.pdf")
    );
    let output = response_bytes(response).await?;
    let document = Document::load_mem(&output)?;
    let page_id = *document.get_pages().values().next().ok_or("missing page")?;
    let annotations = document
        .get_dictionary(page_id)?
        .get(b"Annots")?
        .as_array()?;
    assert_eq!(annotations.len(), 2, "existing note plus one valid note");
    let added = annotations
        .iter()
        .filter_map(|annotation| document.dereference(annotation).ok())
        .filter_map(|(_, annotation)| annotation.as_dict().ok())
        .find(|annotation| {
            annotation
                .get(b"Contents")
                .ok()
                .and_then(|value| lopdf::decode_text_string(value).ok())
                .as_deref()
                == Some("Nhận xét 😀")
        })
        .ok_or("missing added annotation")?;
    assert_eq!(added.get(b"Subtype")?.as_name()?, b"Text");
    assert_eq!(added.get(b"Name")?.as_name()?, b"Comment");
    assert_eq!(lopdf::decode_text_string(added.get(b"T")?)?, "Stirling AI");
    assert_eq!(lopdf::decode_text_string(added.get(b"Subj")?)?, "Review");
    assert_eq!(
        added
            .get(b"Rect")?
            .as_array()?
            .iter()
            .map(Object::as_float)
            .collect::<Result<Vec<_>, _>>()?,
        vec![10.0, 20.0, 40.0, 60.0]
    );
    assert!((added.get(b"CA")?.as_float()? - 0.9).abs() < f32::EPSILON);
    assert!(lopdf::decode_text_string(added.get(b"CreationDate")?)?.starts_with("D:"));
    Ok(())
}

#[tokio::test]
async fn rejects_missing_blank_and_invalid_comment_json() -> Result<(), Box<dyn std::error::Error>>
{
    for comments in [None, Some("   "), Some("not-json")] {
        let response = post_comments(&basic_pdf()?, comments).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    Ok(())
}

#[tokio::test]
async fn native_pdfium_resolves_anchor_text_to_a_twenty_point_icon()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_none() {
        return Ok(());
    }
    let comments = r#"[{"pageIndex":0,"x":1,"y":2,"width":3,"height":4,"text":"anchored","anchorText":"Anchor Text"}]"#;
    let response = require_status(
        post_comments(&text_pdf()?, Some(comments)).await?,
        StatusCode::OK,
    )
    .await?;
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let page_id = *document.get_pages().values().next().ok_or("missing page")?;
    let annotation = document
        .dereference(
            document
                .get_dictionary(page_id)?
                .get(b"Annots")?
                .as_array()?
                .first()
                .ok_or("missing annotation")?,
        )?
        .1
        .as_dict()?;
    let rect = annotation
        .get(b"Rect")?
        .as_array()?
        .iter()
        .map(Object::as_float)
        .collect::<Result<Vec<_>, _>>()?;
    assert_ne!(rect, vec![1.0, 2.0, 4.0, 6.0]);
    assert!((rect[2] - rect[0] - 20.0).abs() < 0.01);
    assert!((rect[3] - rect[1] - 20.0).abs() < 0.01);
    Ok(())
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

async fn post_comments(
    pdf: &[u8],
    comments: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-comments-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    if let Some(comments) = comments {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"comments\"\r\n\r\n{comments}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/add-comments")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn basic_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let existing_note = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Text",
        "Contents" => Object::string_literal("existing"),
        "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
    });
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
        "Annots" => vec![Object::Reference(existing_note)],
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => root_pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn text_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(lopdf::Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 50 200 Td (Anchor Text) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => root_pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
