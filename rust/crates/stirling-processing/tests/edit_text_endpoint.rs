use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, content::Content, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn edit_text_applies_ordered_literal_replacements() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_edit_text(
        &source_pdf()?,
        r#"[{"find":"Acme","replace":"Rust"},{"find":"Rust","replace":"Stirling"}]"#,
        None,
        None,
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_edited.pdf")
    );

    let output = Document::load_mem(&response_bytes(response).await?)?;
    assert_eq!(
        output.extract_text(&[1])?.trim(),
        "Stirling cat catalog cat"
    );
    assert_eq!(output.extract_text(&[2])?.trim(), "Stirling");
    Ok(())
}

#[tokio::test]
async fn edit_text_respects_page_selection_and_whole_word_search()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_edit_text(
        &source_pdf()?,
        r#"[{"find":"cat","replace":"dog"}]"#,
        Some("1"),
        Some("true"),
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    assert_eq!(output.extract_text(&[1])?.trim(), "Acme dog catalog dog");
    assert_eq!(output.extract_text(&[2])?.trim(), "Acme");
    Ok(())
}

#[tokio::test]
async fn edit_text_replaces_text_inside_a_form_xobject() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_edit_text(
        &form_xobject_pdf()?,
        r#"[{"find":"Nested","replace":"Updated"}]"#,
        None,
        None,
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = *output.get_pages().values().next().ok_or("missing page")?;
    let page = output.get_dictionary(page_id)?;
    let resources = page.get(b"Resources")?.as_dict()?;
    let xobjects = resources.get(b"XObject")?.as_dict()?;
    let form_id = xobjects.get(b"Fm1")?.as_reference()?;
    let form = output.get_object(form_id)?.as_stream()?;
    assert!(
        String::from_utf8_lossy(&form.decompressed_content()?).contains("Updated"),
        "the Form XObject text should be rewritten"
    );
    Ok(())
}

#[tokio::test]
async fn edit_text_clones_shared_form_xobjects_for_a_partial_page_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_edit_text(
        &shared_form_xobject_pdf()?,
        r#"[{"find":"Nested","replace":"Updated"}]"#,
        Some("1"),
        None,
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_ids = output.get_pages().into_values().collect::<Vec<_>>();
    let first_form_id = form_id_for_page(&output, page_ids[0])?;
    let second_form_id = form_id_for_page(&output, page_ids[1])?;
    assert_ne!(first_form_id, second_form_id);
    assert!(
        String::from_utf8_lossy(
            &output
                .get_object(first_form_id)?
                .as_stream()?
                .decompressed_content()?
        )
        .contains("Updated")
    );
    assert!(
        String::from_utf8_lossy(
            &output
                .get_object(second_form_id)?
                .as_stream()?
                .decompressed_content()?
        )
        .contains("Nested text")
    );
    Ok(())
}

#[tokio::test]
async fn edit_text_matches_across_tj_operators_and_tj_array_strings()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_edit_text(
        &fragmented_text_pdf()?,
        r#"[{"find":"Hello World","replace":"Goodbye Earth"}]"#,
        None,
        None,
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    assert_eq!(output.extract_text(&[1])?.trim(), "Goodbye Earth!");
    Ok(())
}

#[tokio::test]
async fn edit_text_matches_across_page_and_form_content_streams()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_edit_text(
        &page_form_boundary_pdf()?,
        r#"[{"find":"Hello World","replace":"Goodbye Earth"}]"#,
        None,
        None,
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = *output.get_pages().values().next().ok_or("missing page")?;
    let page_content = String::from_utf8_lossy(&output.get_page_content(page_id)).into_owned();
    let form_id = form_id_for_page(&output, page_id)?;
    let form_content = String::from_utf8_lossy(
        &output
            .get_object(form_id)?
            .as_stream()?
            .decompressed_content()?,
    )
    .into_owned();
    assert!(page_content.contains("Goodbye Earth"));
    assert!(!form_content.contains("World"));
    assert!(form_content.contains('!'));
    Ok(())
}

#[tokio::test]
async fn edit_text_isolates_repeated_form_invocations_on_one_page()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_edit_text(
        &repeated_form_xobject_pdf()?,
        r#"[{"find":"middle shared omega","replace":"done"}]"#,
        None,
        None,
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = *output.get_pages().values().next().ok_or("missing page")?;
    let page = output.get_dictionary(page_id)?;
    let xobjects = page
        .get(b"Resources")?
        .as_dict()?
        .get(b"XObject")?
        .as_dict()?;
    let content = Content::decode(&output.get_page_content(page_id))?;
    let form_names = content
        .operations
        .iter()
        .filter(|operation| operation.operator == "Do")
        .map(|operation| operation.operands[0].as_name().map(<[u8]>::to_vec))
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(form_names.len(), 2);
    assert_ne!(form_names[0], form_names[1]);
    let first_form_id = xobjects.get(&form_names[0])?.as_reference()?;
    let second_form_id = xobjects.get(&form_names[1])?.as_reference()?;
    assert_ne!(first_form_id, second_form_id);

    let first_form = String::from_utf8_lossy(
        &output
            .get_object(first_form_id)?
            .as_stream()?
            .decompressed_content()?,
    )
    .into_owned();
    let second_form = String::from_utf8_lossy(
        &output
            .get_object(second_form_id)?
            .as_stream()?
            .decompressed_content()?,
    )
    .into_owned();
    let page_content = String::from_utf8_lossy(&output.get_page_content(page_id)).into_owned();
    assert!(first_form.contains("shared"));
    assert!(!second_form.contains("shared"));
    assert!(page_content.contains("done"));
    assert!(!page_content.contains("middle"));
    assert!(!page_content.contains("omega"));
    Ok(())
}

#[tokio::test]
async fn edit_text_rejects_missing_or_invalid_edits() -> Result<(), Box<dyn std::error::Error>> {
    let source = source_pdf()?;
    assert_eq!(
        post_edit_text(&source, "[]", None, None).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_edit_text(&source, r#"[{"find":"","replace":"x"}]"#, None, None)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_edit_text(&source, "not-json", None, None)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn post_edit_text(
    pdf: &[u8],
    edits: &str,
    page_numbers: Option<&str>,
    whole_word_search: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-edit-text-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    append_field(&mut body, boundary, "edits", edits);
    if let Some(page_numbers) = page_numbers {
        append_field(&mut body, boundary, "pageNumbers", page_numbers);
    }
    if let Some(whole_word_search) = whole_word_search {
        append_field(&mut body, boundary, "wholeWordSearch", whole_word_search);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/edit-text")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn append_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
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

async fn response_bytes(response: Response) -> Result<Vec<u8>, axum::Error> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

fn source_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let mut page_ids = Vec::new();
    for text in ["Acme cat catalog cat", "Acme"] {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            format!("BT /F1 12 Tf 10 50 Td ({text}) Tj ET").into_bytes(),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 120.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content_id,
        });
        page_ids.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => page_ids, "Count" => 2,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn fragmented_text_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Hello ) Tj [(Wor) 0 (ld!)] TJ ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 240.into(), 120.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn page_form_boundary_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        },
        b"BT /F1 12 Tf 10 30 Td (World!) Tj ET".to_vec(),
    ));
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 70 Td (Hello ) Tj ET q /Fm1 Do Q".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 240.into(), 120.into()],
        "Resources" => dictionary! {
            "Font" => dictionary! { "F1" => font_id },
            "XObject" => dictionary! { "Fm1" => form_id },
        },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn form_xobject_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        },
        b"BT /F1 12 Tf 10 30 Td (Nested text) Tj ET".to_vec(),
    ));
    let content_id = document.add_object(Stream::new(dictionary! {}, b"q /Fm1 Do Q".to_vec()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 120.into()],
        "Resources" => dictionary! { "XObject" => dictionary! { "Fm1" => form_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn shared_form_xobject_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        },
        b"BT /F1 12 Tf 10 30 Td (Nested text) Tj ET".to_vec(),
    ));
    let mut pages = Vec::new();
    for _ in 0..2 {
        let content_id = document.add_object(Stream::new(dictionary! {}, b"q /Fm1 Do Q".to_vec()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 120.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "Fm1" => form_id } },
            "Contents" => content_id,
        });
        pages.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => pages, "Count" => 2,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn repeated_form_xobject_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        },
        b"BT /F1 12 Tf 10 30 Td (shared) Tj ET".to_vec(),
    ));
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 90 Td (Alpha ) Tj ET /Fm1 Do BT /F1 12 Tf 10 60 Td ( middle ) Tj ET /Fm1 Do BT /F1 12 Tf 10 30 Td ( omega) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 240.into(), 120.into()],
        "Resources" => dictionary! {
            "Font" => dictionary! { "F1" => font_id },
            "XObject" => dictionary! { "Fm1" => form_id },
        },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn form_id_for_page(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<lopdf::ObjectId, lopdf::Error> {
    let page = document.get_dictionary(page_id)?;
    let resources = page.get(b"Resources")?.as_dict()?;
    let xobjects = resources.get(b"XObject")?.as_dict()?;
    xobjects.get(b"Fm1")?.as_reference()
}
