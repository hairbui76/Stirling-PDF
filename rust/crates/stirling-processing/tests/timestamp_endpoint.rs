use std::error::Error;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use bcder::{
    Integer, Mode, OctetString, Oid,
    decode::{Constructed, SliceSource},
    encode::Values,
};
use cryptographic_message_syntax::{
    Bytes,
    asn1::{
        rfc3161::{
            OID_CONTENT_TYPE_TST_INFO, PkiStatus, PkiStatusInfo, TimeStampReq, TimeStampResp,
            TstInfo,
        },
        rfc5652::{
            CmsVersion, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
            SignerInfos,
        },
    },
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use stirling_processing::{TimestampSettings, app_with_timestamp_settings};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;
use x509_certificate::asn1time::{GeneralizedTime, GeneralizedTimeAllowedTimezone};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn rejects_unapproved_tsa_urls_before_contacting_them() -> TestResult {
    let response = post(
        app_with_timestamp_settings(2 * 1024 * 1024, TimestampSettings::default()),
        &single_page_pdf()?,
        Some("http://127.0.0.1:8080/metadata"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("not in the allowed list"), "{body}");
    Ok(())
}

#[tokio::test]
async fn sends_an_rfc3161_request_and_returns_an_incrementally_timestamped_pdf() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let tsa_url = format!("http://{}/tsr", listener.local_addr()?);
    let server = tokio::spawn(async move { serve_matching_timestamp_response(listener).await });
    let settings = TimestampSettings {
        default_tsa_url: "http://timestamp.digicert.com".to_owned(),
        custom_tsa_urls: vec![tsa_url.clone()],
    };
    let response = post(
        app_with_timestamp_settings(2 * 1024 * 1024, settings),
        &single_page_pdf()?,
        Some(&tsa_url),
    )
    .await?;
    let server_result = server.await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        return Err(format!(
            "expected timestamp response to succeed, got {status}: {}; TSA mock: {}",
            String::from_utf8_lossy(&body),
            server_result
                .err()
                .map_or_else(|| "ok".to_owned(), |error| error.to_string())
        )
        .into());
    }
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("input_timestamped.pdf")
    );
    let output = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    let document = Document::load_mem(&output)?;
    assert!(document.objects.values().any(|object| {
        object.as_dict().is_ok_and(|dictionary| {
            dictionary
                .get(b"Type")
                .and_then(Object::as_name)
                .is_ok_and(|name| name == b"DocTimeStamp")
        })
    }));

    let request = server_result?;
    assert!(request.starts_with(b"POST /tsr HTTP/1.1\r\n"));
    let request_text = String::from_utf8_lossy(&request);
    assert!(
        request_text
            .to_ascii_lowercase()
            .contains("content-type: application/timestamp-query"),
        "{request_text}"
    );
    assert!(!request_body(&request)?.is_empty());
    Ok(())
}

async fn post(
    app: axum::Router,
    pdf: &[u8],
    tsa_url: Option<&str>,
) -> TestResult<axum::response::Response> {
    let boundary = "stirling-timestamp-boundary";
    let mut body = Vec::new();
    append_file_part(&mut body, boundary, pdf);
    if let Some(tsa_url) = tsa_url {
        append_value_part(&mut body, boundary, "tsaUrl", tsa_url);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/timestamp-pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn append_file_part(body: &mut Vec<u8>, boundary: &str, pdf: &[u8]) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"input.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
}

fn append_value_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

async fn serve_matching_timestamp_response(listener: TcpListener) -> TestResult<Vec<u8>> {
    let (mut socket, _) = listener.accept().await?;
    let request = read_http_request(&mut socket).await?;
    let timestamp_request =
        Constructed::decode(request_body(&request)?, Mode::Der, TimeStampReq::take_from)?;
    let response_body = matching_timestamp_response(&timestamp_request)?;
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            )
            .as_bytes(),
        )
        .await?;
    socket.write_all(&response_body).await?;
    Ok(request)
}

async fn read_http_request(socket: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Err("TSA client closed the request before sending its body".into());
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = header_end + 4;
            let headers = std::str::from_utf8(&request[..header_end])?;
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
                .transpose()?
                .ok_or("timestamp request has no Content-Length")?;
            if request.len() >= body_start + content_length {
                return Ok(request);
            }
        }
    }
}

fn request_body(request: &[u8]) -> TestResult<&[u8]> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("HTTP request header is incomplete")?;
    Ok(&request[header_end + 4..])
}

fn matching_timestamp_response(request: &TimeStampReq) -> TestResult<Vec<u8>> {
    let gen_time = GeneralizedTime::parse(
        SliceSource::new(b"20260716000000Z"),
        false,
        GeneralizedTimeAllowedTimezone::Z,
    )?;
    let timestamp_info = TstInfo {
        version: Integer::from(1),
        policy: Oid(Bytes::copy_from_slice(&[42, 3])),
        message_imprint: request.message_imprint.clone(),
        serial_number: Integer::from(1),
        gen_time,
        accuracy: None,
        ordering: None,
        nonce: request.nonce.clone(),
        tsa: None,
        extensions: None,
    };
    let mut timestamp_info_bytes = Vec::new();
    timestamp_info
        .encode_ref()
        .write_encoded(Mode::Der, &mut timestamp_info_bytes)?;
    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::default(),
        content_info: EncapsulatedContentInfo {
            content_type: Oid(Bytes::copy_from_slice(OID_CONTENT_TYPE_TST_INFO.as_ref())),
            content: Some(OctetString::new(Bytes::from(timestamp_info_bytes))),
        },
        certificates: None,
        crls: None,
        signer_infos: SignerInfos::default(),
    };
    let mut token_bytes = Vec::new();
    signed_data
        .encode_ref()
        .write_encoded(Mode::Der, &mut token_bytes)?;
    let status = PkiStatusInfo {
        status: PkiStatus::Granted,
        status_string: None,
        fail_info: None,
    };
    let mut bytes = Vec::new();
    bcder::encode::sequence((status.encode_ref(), signed_data.encode_ref()))
        .write_encoded(Mode::Der, &mut bytes)?;
    let _: TimeStampResp =
        Constructed::decode(bytes.as_slice(), Mode::Der, TimeStampResp::take_from)?;
    Ok(bytes)
}

fn single_page_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
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
