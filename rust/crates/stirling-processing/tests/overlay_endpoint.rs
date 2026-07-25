use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn sequential_overlay_starts_with_the_second_file_and_advances_its_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_overlay(
        "base.pdf",
        &pdf_with_markers(&["BASE"; 5])?,
        &[
            ("a.pdf", pdf_with_markers(&["A0", "A1"])?),
            ("b.pdf", pdf_with_markers(&["B0", "B1", "B2"])?),
        ],
        "SequentialOverlay",
        &[],
        0,
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("base_overlayed.pdf")
    );
    let output = response_document(response).await?;
    assert_eq!(
        overlay_markers(&output)?,
        vec!["B0", "B1", "B2", "A0", "A1"]
    );
    Ok(())
}

#[tokio::test]
async fn interleaved_overlay_round_robins_files_but_uses_only_their_first_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_overlay(
            "base.pdf",
            &pdf_with_markers(&["BASE"; 4])?,
            &[
                ("a.pdf", pdf_with_markers(&["A0", "A1"])?),
                ("b.pdf", pdf_with_markers(&["B0", "B1"])?),
            ],
            "InterleavedOverlay",
            &[],
            0,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let output = response_document(response).await?;
    assert_eq!(overlay_markers(&output)?, vec!["A0", "B0", "A0", "B0"]);
    Ok(())
}

#[tokio::test]
async fn fixed_repeat_overlay_uses_page_count_as_span_and_leaves_unmapped_pages_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_overlay(
            "base.pdf",
            &pdf_with_markers(&["BASE"; 6])?,
            &[
                ("a.pdf", pdf_with_markers(&["A0", "A1"])?),
                ("b.pdf", pdf_with_markers(&["B0", "B1"])?),
            ],
            "FixedRepeatOverlay",
            &[1, 1],
            0,
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let output = response_document(response).await?;
    assert_eq!(
        overlay_markers_optional(&output)?,
        vec![
            Some("A0".to_owned()),
            Some("A0".to_owned()),
            Some("B0".to_owned()),
            Some("B0".to_owned()),
            None,
            None,
        ]
    );
    Ok(())
}

#[tokio::test]
async fn preserves_foreground_and_background_content_order()
-> Result<(), Box<dyn std::error::Error>> {
    for (position, overlay_first) in [(0, false), (1, true)] {
        let response = require_status(
            post_overlay(
                "base.pdf",
                &pdf_with_markers(&["BASE_MARKER"])?,
                &[("overlay.pdf", pdf_with_markers(&["OVERLAY_MARKER"])?)],
                "InterleavedOverlay",
                &[],
                position,
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        let output = response_document(response).await?;
        let page_id = output
            .get_pages()
            .into_values()
            .next()
            .ok_or("missing page")?;
        let content = output.get_page_content(page_id);
        let overlay_index = find_bytes(&content, b"/OL0 Do").ok_or("missing overlay draw")?;
        let base_index = find_bytes(&content, b"BASE_MARKER").ok_or("missing base marker")?;
        assert_eq!(overlay_index < base_index, overlay_first);
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_modes_and_mismatched_fixed_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let base = pdf_with_markers(&["BASE"])?;
    let overlay = pdf_with_markers(&["OVERLAY"])?;
    for (mode, counts) in [("Unknown", Vec::new()), ("FixedRepeatOverlay", Vec::new())] {
        let response = require_status(
            post_overlay(
                "base.pdf",
                &base,
                &[("overlay.pdf", overlay.clone())],
                mode,
                &counts,
                0,
            )
            .await?,
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        assert!(String::from_utf8_lossy(&body).contains("/api/v1/general/overlay-pdfs"));
    }
    Ok(())
}

fn overlay_markers(document: &Document) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    overlay_markers_optional(document)?
        .into_iter()
        .map(|marker| marker.ok_or_else(|| std::io::Error::other("missing overlay").into()))
        .collect()
}

fn overlay_markers_optional(
    document: &Document,
) -> Result<Vec<Option<String>>, Box<dyn std::error::Error>> {
    document
        .get_pages()
        .into_values()
        .enumerate()
        .map(|(index, page_id)| {
            let Some(resources) = inherited_value(document, page_id, b"Resources") else {
                return Ok(None);
            };
            let (_, resources) = document.dereference(&resources)?;
            let Ok(xobjects) = resources.as_dict()?.get(b"XObject") else {
                return Ok(None);
            };
            let (_, xobjects) = document.dereference(xobjects)?;
            let name = format!("OL{index}");
            let Ok(form) = xobjects.as_dict()?.get(name.as_bytes()) else {
                return Ok(None);
            };
            let (_, form) = document.dereference(form)?;
            let content = form.as_stream()?.decompressed_content()?;
            let marker = String::from_utf8(content)?.trim().to_owned();
            Ok(Some(marker))
        })
        .collect()
}

fn inherited_value(document: &Document, mut id: lopdf::ObjectId, key: &[u8]) -> Option<Object> {
    loop {
        let dictionary = document.get_dictionary(id).ok()?;
        if let Ok(value) = dictionary.get(key) {
            return Some(value.clone());
        }
        id = dictionary.get(b"Parent").ok()?.as_reference().ok()?;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn response_document(response: Response) -> Result<Document, Box<dyn std::error::Error>> {
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

async fn post_overlay(
    base_filename: &str,
    base: &[u8],
    overlays: &[(&str, Vec<u8>)],
    mode: &str,
    counts: &[i32],
    position: i32,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-overlay-boundary";
    let mut body = Vec::new();
    append_file(&mut body, boundary, "fileInput", base_filename, base);
    for (filename, bytes) in overlays {
        append_file(&mut body, boundary, "overlayFiles", filename, bytes);
    }
    append_field(&mut body, boundary, "overlayMode", mode);
    for count in counts {
        append_field(&mut body, boundary, "counts", &count.to_string());
    }
    append_field(
        &mut body,
        boundary,
        "overlayPosition",
        &position.to_string(),
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/overlay-pdfs")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn append_file(body: &mut Vec<u8>, boundary: &str, name: &str, filename: &str, bytes: &[u8]) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

fn append_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

fn pdf_with_markers(markers: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let mut pages = Vec::with_capacity(markers.len());
    for marker in markers {
        let content_id =
            document.add_object(Stream::new(dictionary! {}, marker.as_bytes().to_vec()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => root_pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
            "Contents" => content_id,
        });
        pages.push(Object::Reference(page_id));
    }
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages,
            "Count" => i64::try_from(markers.len())?,
            "Resources" => dictionary! {},
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
