use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Bookmark, Dictionary, Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn merges_multipart_pdf_uploads_without_a_browser_change()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-test-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "alpha.pdf", &pdf_with_pages(1)?);
    add_file_part(&mut body, boundary, "bravo.pdf", &pdf_with_pages(2)?);
    add_text_part(&mut body, boundary, "sortType", "orderProvided");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("alpha_merged_unsigned.pdf")
    );

    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    assert_eq!(document.get_pages().len(), 3);
    Ok(())
}

#[tokio::test]
async fn sorts_by_pdf_title_before_choosing_the_download_name()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-title-sort-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "zulu.pdf",
        &pdf_with_metadata(1, Some("Zulu"), None)?,
    );
    add_file_part(
        &mut body,
        boundary,
        "alpha.pdf",
        &pdf_with_metadata(1, Some("alpha"), None)?,
    );
    add_text_part(&mut body, boundary, "sortType", "byPDFTitle");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("alpha_merged_unsigned.pdf")
    );
    Ok(())
}

#[tokio::test]
async fn sorts_both_legacy_date_modes_newest_first() -> Result<(), Box<dyn std::error::Error>> {
    for sort_type in ["byDateModified", "byDateCreated"] {
        let boundary = format!("stirling-{sort_type}-boundary");
        let mut body = Vec::new();
        add_file_part(
            &mut body,
            &boundary,
            "older.pdf",
            &pdf_with_metadata(1, None, Some("D:20200101000000Z"))?,
        );
        add_file_part(
            &mut body,
            &boundary,
            "newer.pdf",
            &pdf_with_metadata(1, None, Some("D:20260101000000Z"))?,
        );
        add_text_part(&mut body, &boundary, "sortType", sort_type);
        finish_multipart(&mut body, &boundary);

        let response = require_status(post_merge(body, &boundary).await?, StatusCode::OK).await?;
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("newer_merged_unsigned.pdf")
        );
    }
    Ok(())
}

#[tokio::test]
async fn accepts_remove_cert_sign_when_the_merge_has_no_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-unsigned-remove-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "unsigned.pdf", &pdf_with_pages(1)?);
    add_text_part(&mut body, boundary, "removeCertSign", "true");
    finish_multipart(&mut body, boundary);

    require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    Ok(())
}

#[tokio::test]
async fn flattens_only_the_signature_field_when_remove_cert_sign_is_enabled()
-> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-signed-remove-boundary";
    let mut body = Vec::new();
    add_file_part(
        &mut body,
        boundary,
        "signed.pdf",
        &pdf_with_signed_signature_and_text_form()?,
    );
    add_text_part(&mut body, boundary, "removeCertSign", "true");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    let acroform_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
    let fields = document
        .get_dictionary(acroform_id)?
        .get(b"Fields")?
        .as_array()?;
    assert_eq!(fields.len(), 1);
    let text_field_id = fields[0].as_reference()?;
    assert_eq!(
        document
            .get_dictionary(text_field_id)?
            .get(b"FT")?
            .as_name()?,
        b"Tx"
    );
    let page_id = *document
        .get_pages()
        .values()
        .next()
        .ok_or_else(|| std::io::Error::other("merged page is missing"))?;
    assert!(
        document
            .get_dictionary(page_id)?
            .get(b"Annots")?
            .as_array()?
            .is_empty()
    );
    assert!(contains_bytes(
        &document.get_page_content(page_id),
        b"/StirlingSig0 Do"
    ));
    Ok(())
}

#[tokio::test]
async fn preserves_the_seed_acroform() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-seed-form-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "form.pdf", &pdf_with_text_form()?);
    add_file_part(&mut body, boundary, "ordinary.pdf", &pdf_with_pages(1)?);
    finish_multipart(&mut body, boundary);

    let response = require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    let acroform_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
    let fields = document
        .get_dictionary(acroform_id)?
        .get(b"Fields")?
        .as_array()?;

    assert_eq!(fields.len(), 1);
    Ok(())
}

#[tokio::test]
async fn preserves_source_bookmarks_with_page_offsets() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-source-bookmark-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "first.pdf", &pdf_with_pages(1)?);
    add_file_part(
        &mut body,
        boundary,
        "second.pdf",
        &pdf_with_bookmark(2, "Source chapter", 1)?,
    );
    finish_multipart(&mut body, boundary);

    let response = require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    assert_eq!(document.get_pages().len(), 3);
    if bytes
        .windows(b"/Dest [2 /Fit]".len())
        .any(|window| window == b"/Dest [2 /Fit]")
    {
        assert!(
            bytes
                .windows(
                    b"/Title <FEFF0053006F007500720063006500200063006800610070007400650072>".len(),
                )
                .any(|window| {
                    window
                        == b"/Title <FEFF0053006F007500720063006500200063006800610070007400650072>"
                })
        );
    } else {
        let toc = document.get_toc()?;
        assert_eq!(toc.toc.len(), 1);
        assert_eq!(toc.toc[0].title, "Source chapter");
        assert_eq!(toc.toc[0].page, 3);
    }
    Ok(())
}

#[tokio::test]
async fn generates_filename_toc_entries_in_input_order() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-generated-toc-boundary";
    let mut body = Vec::new();
    add_file_part(&mut body, boundary, "alpha.pdf", &pdf_with_pages(1)?);
    add_file_part(&mut body, boundary, "bravo.pdf", &pdf_with_pages(1)?);
    add_text_part(&mut body, boundary, "generateToc", "true");
    finish_multipart(&mut body, boundary);

    let response = require_status(post_merge(body, boundary).await?, StatusCode::OK).await?;
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let document = Document::load_mem(&bytes)?;
    if contains_bytes(&bytes, b"/Dest [0 /Fit]") {
        let alpha = find_bytes(&bytes, b"/Title <FEFF0061006C007000680061>")
            .ok_or_else(|| std::io::Error::other("generated alpha bookmark is missing"))?;
        let bravo = find_bytes(&bytes, b"/Title <FEFF0062007200610076006F>")
            .ok_or_else(|| std::io::Error::other("generated bravo bookmark is missing"))?;
        assert!(alpha < bravo);
        assert!(contains_bytes(&bytes, b"/Dest [1 /Fit]"));
    } else {
        let toc = document.get_toc()?;
        assert_eq!(toc.toc.len(), 2);
        assert_eq!(toc.toc[0].title, "alpha");
        assert_eq!(toc.toc[0].page, 1);
        assert_eq!(toc.toc[1].title, "bravo");
        assert_eq!(toc.toc[1].page, 2);
    }
    Ok(())
}

#[tokio::test]
async fn round_trips_generated_bookmarks_through_another_merge()
-> Result<(), Box<dyn std::error::Error>> {
    let first_boundary = "stirling-bookmark-roundtrip-first";
    let mut first_body = Vec::new();
    add_file_part(
        &mut first_body,
        first_boundary,
        "alpha.pdf",
        &pdf_with_pages(1)?,
    );
    add_file_part(
        &mut first_body,
        first_boundary,
        "bravo.pdf",
        &pdf_with_pages(1)?,
    );
    add_text_part(&mut first_body, first_boundary, "generateToc", "true");
    finish_multipart(&mut first_body, first_boundary);
    let first_response = require_status(
        post_merge(first_body, first_boundary).await?,
        StatusCode::OK,
    )
    .await?;
    let first_output = to_bytes(first_response.into_body(), usize::MAX).await?;

    let second_boundary = "stirling-bookmark-roundtrip-second";
    let mut second_body = Vec::new();
    add_file_part(
        &mut second_body,
        second_boundary,
        "merged.pdf",
        &first_output,
    );
    add_file_part(
        &mut second_body,
        second_boundary,
        "tail.pdf",
        &pdf_with_pages(1)?,
    );
    finish_multipart(&mut second_body, second_boundary);
    let second_response = require_status(
        post_merge(second_body, second_boundary).await?,
        StatusCode::OK,
    )
    .await?;
    let second_output = to_bytes(second_response.into_body(), usize::MAX).await?;

    let document = Document::load_mem(&second_output)?;
    assert_eq!(document.get_pages().len(), 3);
    if contains_bytes(&second_output, b"/Title <FEFF0061006C007000680061>") {
        assert!(contains_bytes(
            &second_output,
            b"/Title <FEFF0062007200610076006F>"
        ));
    } else {
        let toc = document.get_toc()?;
        assert_eq!(toc.toc.len(), 2);
        assert_eq!(toc.toc[0].title, "alpha");
        assert_eq!(toc.toc[1].title, "bravo");
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

async fn post_merge(body: Vec<u8>, boundary: &str) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/merge-pdfs")
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

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes(haystack, needle).is_some()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn pdf_with_pages(page_count: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pdf_with_metadata(page_count, None, None)
}

fn pdf_with_text_form() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::load_mem(&pdf_with_pages(1)?)?;
    let field_id = document.add_object(dictionary! {
        "FT" => "Tx",
        "T" => Object::string_literal("name"),
    });
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(field_id)],
    });
    document.catalog_mut()?.set("AcroForm", acroform_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn pdf_with_signed_signature_and_text_form() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::load_mem(&pdf_with_pages(1)?)?;
    let page_id = *document
        .get_pages()
        .values()
        .next()
        .ok_or_else(|| std::io::Error::other("test page is missing"))?;
    let appearance_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 20.into()],
        },
        b"0 0 100 20 re f".to_vec(),
    ));
    let signature_value_id = document.add_object(dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "adbe.pkcs7.detached",
        "ByteRange" => vec![0.into(), 0.into(), 0.into(), 0.into()],
        "Contents" => Object::string_literal("test-signature"),
    });
    let signature_field_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Sig",
        "T" => Object::string_literal("signature"),
        "Rect" => vec![50.into(), 60.into(), 250.into(), 100.into()],
        "AP" => dictionary! { "N" => appearance_id },
        "P" => page_id,
        "V" => signature_value_id,
    });
    let text_field_id = document.add_object(dictionary! {
        "FT" => "Tx",
        "T" => Object::string_literal("name"),
    });
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![
            Object::Reference(signature_field_id),
            Object::Reference(text_field_id),
        ],
        "SigFlags" => 3,
    });
    document.catalog_mut()?.set("AcroForm", acroform_id);
    document
        .get_dictionary_mut(page_id)?
        .set("Annots", vec![Object::Reference(signature_field_id)]);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn pdf_with_bookmark(
    page_count: usize,
    title: &str,
    page_index: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::load_mem(&pdf_with_pages(page_count)?)?;
    let page_id = document
        .get_pages()
        .values()
        .nth(page_index)
        .copied()
        .ok_or_else(|| std::io::Error::other("bookmark page is outside the test document"))?;
    document.add_bookmark(
        Bookmark::new(title.to_owned(), [0.0, 0.0, 0.0], 0, page_id),
        None,
    );
    if let Some(outline_id) = document.build_outline() {
        document.catalog_mut()?.set("Outlines", outline_id);
    }
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn pdf_with_metadata(
    page_count: usize,
    title: Option<&str>,
    modification_date: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut page_ids = Vec::new();
    for _ in 0..page_count {
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_object_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
        });
        page_ids.push(page_object_id.into());
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids,
            "Count" => u32::try_from(page_count)?,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    if title.is_some() || modification_date.is_some() {
        let mut info = Dictionary::new();
        if let Some(title) = title {
            info.set("Title", Object::string_literal(title));
        }
        if let Some(modification_date) = modification_date {
            info.set("ModDate", Object::string_literal(modification_date));
        }
        let info_id = document.add_object(info);
        document.trailer.set("Info", info_id);
    }
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
