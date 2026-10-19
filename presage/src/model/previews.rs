use futures::stream::{self, StreamExt};
use libsignal_service::sender::AttachmentSpec;
use mime::Mime;
use regex::Regex;
use reqwest::header::CONTENT_TYPE;
use reqwest::IntoUrl;
use scraper::{Html, Selector};
use std::str::FromStr;
use url::Url;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("The response does not contain a Content-Type header")]
    MissingContentTypeHeadersError,
    //#[error("Err error: {0}")]
    //ConversionError,
    #[error("Err error: {0}")]
    UnsupportedMimeTypeError(String),
    #[error("Downloaded file does not look like an image")]
    NonImageBytesError,
    #[error("ToStr error: {0}")]
    ToStrtError(#[from] reqwest::header::ToStrError),
    #[error("FromStr error: {0}")]
    FromStrError(#[from] mime::FromStrError),
}

#[derive(Clone, PartialEq, Debug)]
pub struct PreviewContent {
    pub url: Option<String>,
    pub title: Option<String>,
    pub image: Option<Vec<u8>>,
    /// The MIME (e.g. `image/jpeg`) of `image`, detected from the response's
    /// `Content-Type` header or, failing that, sniffed from the image bytes themselves:
    pub image_content_type: Option<String>,
    pub description: Option<String>,
    pub date: Option<u64>,
}

pub async fn generate_preview_from_url<T: IntoUrl>(
    url: T,
    client: &reqwest::Client,
) -> Result<PreviewContent, Error> {
    let url = url.into_url()?;
    // a default url value in case the og:url tag is missing
    let default_url_preview = url.clone().host_str().map(|y| y.to_string());

    let mut preview: PreviewContent = {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("user-agent", "WhatsApp/2".parse().unwrap());

        let response = client
            .get(url)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?;

        let headers = &response.headers();

        match headers.get(CONTENT_TYPE) {
            None => return Err(Error::MissingContentTypeHeadersError),
            Some(content_type) => {
                let content_type = content_type.to_str()?;
                let content_type = Mime::from_str(content_type)?;
                match (content_type.type_(), content_type.subtype()) {
                    (mime::TEXT, mime::HTML) => {
                        let html = response.text().await?;
                        generate_preview_from_html(&html, client).await
                    }
                    (mime::IMAGE, _) => {
                        let (image, image_content_type) =
                            match fetch_image_from_response(response).await {
                                Ok((bytes, content_type)) => (Some(bytes), Some(content_type)),
                                Err(_) => (None, None),
                            };
                        PreviewContent {
                            url: None,
                            title: None,
                            image,
                            image_content_type,
                            description: None,
                            date: None,
                        }
                    }
                    _ => {
                        return Err(Error::UnsupportedMimeTypeError(format!(
                            "Got unsupported mime type:{}.",
                            content_type
                        )))
                    }
                }
            }
        }
    };

    if preview.url.is_none() {
        preview.url = default_url_preview;
    }
    Ok(preview)
}

/// The function builds a Preview primarily from the html's OG tags.
/// If some of these are unavailable, it resorts to other tags to fill the preview's fields.
/// The url is taken from the stemmed url of the page.
/// The title is taken from the <title> tag (if available).
/// The description is taken from the  <meta name="description"> tag (if available).
pub async fn generate_preview_from_html(
    html_doc: &str,
    client: &reqwest::Client,
) -> PreviewContent {
    let document = Html::parse_document(html_doc);
    let selector = Selector::parse("meta").unwrap();
    let mut preview = PreviewContent {
        url: None,
        title: None,
        image: None,
        image_content_type: None,
        description: None,
        date: None,
    };

    for element in document.select(&selector) {
        // get description from <meta name="description">
        let name = element
            .value()
            .attr("name")
            .unwrap_or("")
            .trim()
            .to_string();

        if (name == "description") && (preview.description.is_none()) {
            if let Some(c) = element.value().attr("content") {
                preview.description = Some(c.to_string())
            }
        }

        // get fields from <meta property="og:"
        let property = element.value().attr("property").unwrap_or("").to_string();
        if let Some(capture) = property.strip_prefix("og:") {
            let field = capture.trim();
            let content = element.value().attr("content").unwrap_or("").to_string();
            match field {
                "url" => preview.url = Some(content),
                "title" => preview.title = Some(content),
                "image" => {
                    if let Ok((bytes, content_type)) = fetch_image_from_url(content, client).await {
                        preview.image = Some(bytes);
                        preview.image_content_type = Some(content_type);
                    }
                }
                "description" => preview.description = Some(content),
                "date" | "article:published_time" | "article:modified_time" => {
                    preview.date = std::cmp::max(preview.date, timestamp_from_iso(&content))
                }
                _ => (),
            }
        }

        // Check whether the preview is still missing any fields; if not, break.
        // in practice, since date is essentially never set on real pages, this rarely breaks
        // early and we scan the whole `<head>`.
        if [
            preview.url.is_none(),
            preview.title.is_none(),
            preview.image.is_none(),
            preview.description.is_none(),
            preview.date.is_none(),
        ]
        .iter()
        .all(|&is_missing| !is_missing)
        {
            break;
        }
    }

    // in case no og:title was found, get the value from <title>
    if preview.title.is_none() | (preview.title == Some("".to_string())) {
        let selector = Selector::parse("title").unwrap();
        let title = document
            .select(&selector)
            .next()
            .map(|x| x.inner_html().trim().to_owned());
        preview.title = title;
    }
    preview
}

/// The task of extracting urls from a text message is not trivial, since
/// they might be enclosed within parentheses or be immediately followed
/// by punctuation. This here function tries to strike a balance, taking
/// into account that punctuations as well as parentheses might
/// appear within valid urls.
pub fn extract_urls_from_text_block(message: &str) -> Vec<Url> {
    let re = Regex::new(
        r#"(?xi)
        \b
        (
            (?:https?://)?              # Optional scheme
            (?:www\.)?
            [a-z0-9.-]+\.[a-z]{2,}
            [^\s]*                      # Capture everything until whitespace
        )
        "#,
    )
    .unwrap();

    let mut urls = Vec::new();

    for cap in re.captures_iter(message) {
        let mut candidate = cap[1].to_string();

        // Trim wrapping punctuation
        candidate = candidate
            .trim_matches(|c: char| {
                matches!(
                    c,
                    '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\'' | ',' | '.' | '!' | '?' | ':'
                )
            })
            .to_string();

        // Balance parentheses
        loop {
            let opens = candidate.matches('(').count();
            let closes = candidate.matches(')').count();

            if closes > opens && candidate.ends_with(')') {
                // remove closing parenthesis
                candidate.pop();
            } else {
                break;
            }
        }

        // Add scheme
        let url = if candidate.starts_with("http://") || candidate.starts_with("https://") {
            candidate.clone()
        } else {
            format!("https://{}", candidate)
        };

        if let Ok(url) = Url::parse(&url) {
            urls.push(url);
        }
    }
    urls
}

pub async fn generate_previews_from_message(message: &str) -> Vec<PreviewContent> {
    let urls = extract_urls_from_text_block(message);
    let client = reqwest::Client::new();

    stream::iter(urls)
        .map(|url| generate_preview_from_url(url, &client))
        .buffer_unordered(10)
        .filter_map(|res| async move { res.ok() })
        .collect()
        .await
}

/// Builds the `AttachmentSpec` and raw bytes needed to upload `content`'s image as an
/// attachment, e.g. via `Manager::upload_attachment`. Returns `None` if `content` has no image.
pub fn build_preview_image(content: &PreviewContent) -> Option<(AttachmentSpec, Vec<u8>)> {
    let image = content.image.as_ref()?;
    let content_type = content.image_content_type.as_ref()?;

    Some((
        AttachmentSpec {
            content_type: content_type.clone(),
            length: image.len(),
            file_name: None,
            preview: None,
            voice_note: None,
            borderless: None,
            width: None,
            height: None,
            caption: None,
            blur_hash: None,
        },
        image.clone(),
    ))
}

async fn fetch_image_from_url<T: IntoUrl>(
    url: T,
    client: &reqwest::Client,
) -> Result<(Vec<u8>, String), Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("user-agent", "WhatsApp/2".parse().unwrap());

    let response: reqwest::Response = client
        .get(url)
        .headers(headers)
        .send()
        .await?
        .error_for_status()?;

    fetch_image_from_response(response).await
}

/// Fetches the body of `response`, returning its bytes along with the detected image MIME
/// (e.g. `image/jpeg`), preferring the response's own `Content-Type` header and falling
/// back to sniffing the file signature when that header is missing or not an image type.
async fn fetch_image_from_response(
    response: reqwest::Response,
) -> Result<(Vec<u8>, String), Error> {
    let header_content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Mime::from_str(value).ok())
        .filter(|mime| mime.type_() == mime::IMAGE)
        .map(|mime| mime.essence_str().to_string());

    let bytes = response.bytes().await?;

    let Some(content_type) =
        header_content_type.or_else(|| sniff_image_mime_type(&bytes).map(str::to_string))
    else {
        return Err(Error::NonImageBytesError);
    };

    Ok((bytes.into(), content_type))
}

fn timestamp_from_iso(datetime_str: &str) -> Option<u64> {
    let datetime = chrono::DateTime::parse_from_rfc3339(datetime_str).ok()?;
    let timestamp = chrono::DateTime::timestamp(&datetime);
    Some(timestamp as u64)
}

/// Detects the image MIME essence (e.g. `image/jpeg`) from a file's magic bytes.
fn sniff_image_mime_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("image/webp")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_urls_from_text_block() {
        assert_eq!(
            extract_urls_from_text_block("check this out: https://example.com/foo"),
            vec![Url::parse("https://example.com/foo").unwrap()]
        );

        assert_eq!(
            extract_urls_from_text_block("see (https://example.com/foo) for details"),
            vec![Url::parse("https://example.com/foo").unwrap()]
        );

        assert_eq!(
            extract_urls_from_text_block("visit example.com."),
            vec![Url::parse("https://example.com").unwrap()]
        );

        assert_eq!(
            extract_urls_from_text_block("https://a.com and https://b.com/path?x=1"),
            vec![
                Url::parse("https://a.com").unwrap(),
                Url::parse("https://b.com/path?x=1").unwrap()
            ]
        );

        assert!(extract_urls_from_text_block("no links in this message").is_empty());
    }

    #[test]
    fn test_sniff_image_mime_type() {
        assert_eq!(
            sniff_image_mime_type(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some("image/jpeg")
        );
        assert_eq!(
            sniff_image_mime_type(b"\x89PNG\r\n\x1a\n"),
            Some("image/png")
        );
        assert_eq!(sniff_image_mime_type(b"GIF89a"), Some("image/gif"));
        assert_eq!(sniff_image_mime_type(b"BM\0\0\0\0"), Some("image/bmp"));
        assert_eq!(
            sniff_image_mime_type(b"RIFF\0\0\0\0WEBPVP8 "),
            Some("image/webp")
        );
        assert_eq!(sniff_image_mime_type(b"not an image"), None);
    }

    #[tokio::test]
    async fn test_generate_preview_from_html_uses_og_tags() {
        let html = r#"
            <html><head>
                <meta property="og:title" content="Example title">
                <meta property="og:description" content="Example description">
                <title>Fallback title</title>
            </head></html>
        "#;
        let client = reqwest::Client::new();
        let preview = generate_preview_from_html(html, &client).await;

        assert_eq!(preview.title.as_deref(), Some("Example title"));
        assert_eq!(preview.description.as_deref(), Some("Example description"));
        assert!(preview.image.is_none());
    }

    #[tokio::test]
    async fn test_generate_preview_from_html_falls_back_to_title_tag() {
        let html = r#"
            <html><head>
                <meta name="description" content="Meta description">
                <title>  Fallback title  </title>
            </head></html>
        "#;
        let client = reqwest::Client::new();
        let preview = generate_preview_from_html(html, &client).await;

        assert_eq!(preview.title.as_deref(), Some("Fallback title"));
        assert_eq!(preview.description.as_deref(), Some("Meta description"));
    }
}

// Expected behaviour, mostly from what Signal clients accept when receiving a preview:
// https://github.com/signalapp/Signal-Android/blob/main/app/src/main/java/org/thoughtcrime/securesms/messages/DataMessageProcessor.kt
// https://github.com/signalapp/Signal-Android/blob/main/app/src/main/java/org/thoughtcrime/securesms/util/LinkUtil.kt
// and defences from https://github.com/whisperfish/presage/pull/465
#[cfg(test)]
mod signal_compat {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    use super::*;

    // a public-looking https host, resolved to localhost by `client()`
    const HOST: &str = "preview.whisperfish.org";

    struct Tls {
        cert: CertificateDer<'static>,
        config: Arc<rustls::ServerConfig>,
    }

    static TLS: LazyLock<Tls> = LazyLock::new(|| {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![HOST.to_owned(), "127.0.0.1".to_owned()])
                .unwrap();
        let cert = cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
        Tls {
            cert,
            config: Arc::new(config),
        }
    });

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_der(&TLS.cert).unwrap()])
            .resolve(HOST, "127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap()
    }

    struct Route {
        path: &'static str,
        status: &'static str,
        content_type: &'static str,
        headers: String,
        body: Vec<u8>,
        hang: bool,
    }

    impl Route {
        fn new(path: &'static str, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
            Self {
                path,
                status: "200 OK",
                content_type,
                headers: String::new(),
                body: body.into(),
                hang: false,
            }
        }

        fn redirect(path: &'static str, location: String) -> Self {
            Self {
                status: "302 Found",
                headers: format!("Location: {location}\r\n"),
                ..Self::new(path, "text/html", "")
            }
        }
    }

    struct Request {
        headers: Vec<(String, String)>,
    }

    impl Request {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    type Requests = Arc<Mutex<Vec<Request>>>;

    /// Serves `routes` over https, returns the base url and the requests seen.
    fn serve(routes: Vec<Route>) -> (String, Requests) {
        serve_on("https", routes)
    }

    fn serve_http(routes: Vec<Route>) -> (String, Requests) {
        serve_on("http", routes)
    }

    fn serve_on(scheme: &'static str, routes: Vec<Route>) -> (String, Requests) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!(
            "{scheme}://{HOST}:{}",
            listener.local_addr().unwrap().port()
        );
        let routes = Arc::new(routes);
        let requests = Requests::default();
        let seen = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let routes = routes.clone();
                let seen = seen.clone();
                std::thread::spawn(move || {
                    if scheme == "https" {
                        let conn = rustls::ServerConnection::new(TLS.config.clone()).unwrap();
                        handle(rustls::StreamOwned::new(conn, stream), &routes, &seen);
                    } else {
                        handle::<TcpStream>(stream, &routes, &seen);
                    }
                });
            }
        });
        (base, requests)
    }

    fn handle<S: Read + Write>(stream: S, routes: &[Route], seen: &Requests) {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let path = request_line.split(' ').nth(1).unwrap_or("/").to_owned();
        let mut headers = Vec::new();
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
            line.clear();
        }
        seen.lock().unwrap().push(Request { headers });

        let stream = reader.get_mut();
        let Some(route) = routes.iter().find(|r| r.path == path) else {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        if route.hang {
            std::thread::sleep(Duration::from_secs(3600));
        }
        let header = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
            route.status,
            route.content_type,
            route.body.len(),
            route.headers,
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&route.body);
        let _ = stream.flush();
    }

    fn extracted(body: &str) -> Vec<String> {
        extract_urls_from_text_block(body)
            .into_iter()
            .map(|url| url.to_string())
            .collect()
    }

    // link detection

    #[test]
    fn only_https_links_are_previewed() {
        assert!(extracted("http://signal.org and signal.org").is_empty());
    }

    #[test]
    fn reserved_domains_are_not_previewed() {
        assert!(extracted("https://foo.onion https://www.example.com https://a.test").is_empty());
    }

    #[test]
    fn ip_addresses_are_not_previewed() {
        assert!(extracted("https://192.168.1.1/admin").is_empty());
    }

    #[test]
    fn file_names_are_not_links() {
        assert!(extracted("see main.rs, e.g. node.js").is_empty());
    }

    #[test]
    fn email_addresses_are_not_links() {
        assert!(extracted("mail me at me@signal.org").is_empty());
    }

    #[test]
    fn parentheses_in_links_are_kept() {
        assert_eq!(
            extracted("see (https://en.wikipedia.org/wiki/Rust_(programming_language))"),
            vec!["https://en.wikipedia.org/wiki/Rust_(programming_language)"]
        );
    }

    #[test]
    fn link_is_kept_as_written_in_the_body() {
        // receivers drop the preview if its url is not in the message body
        assert_eq!(
            extracted("https://signal.org/ü"),
            vec!["https://signal.org/ü"]
        );
    }

    // html parsing

    #[tokio::test]
    async fn title_entities_are_decoded() {
        let html = "<html><head><title>Signal &amp; you</title></head></html>";
        let preview = generate_preview_from_html(html, &client()).await;
        assert_eq!(preview.title.as_deref(), Some("Signal & you"));
    }

    #[tokio::test]
    async fn date_is_article_published_time_in_millis() {
        let html = r#"<html><head>
            <meta property="og:title" content="t">
            <meta property="article:published_time" content="2024-01-01T00:00:00Z">
        </head></html>"#;
        let preview = generate_preview_from_html(html, &client()).await;
        assert_eq!(preview.date, Some(1_704_067_200_000));
    }

    // fetching

    #[tokio::test]
    async fn preview_url_is_the_link_not_og_url() {
        let (base, _) = serve(vec![Route::new(
            "/page",
            "text/html",
            r#"<meta property="og:url" content="https://signal.org/other"><title>t</title>"#,
        )]);
        let url = format!("{base}/page");
        let preview = generate_preview_from_url(url.as_str(), &client())
            .await
            .unwrap();
        assert_eq!(preview.url.as_deref(), Some(url.as_str()));
    }

    #[tokio::test]
    async fn preview_url_is_the_link_not_the_host() {
        let (base, _) = serve(vec![Route::new("/page", "text/html", "<title>t</title>")]);
        let url = format!("{base}/page");
        let preview = generate_preview_from_url(url.as_str(), &client())
            .await
            .unwrap();
        assert_eq!(preview.url.as_deref(), Some(url.as_str()));
    }

    #[tokio::test]
    async fn untitled_page_has_no_preview() {
        // receivers drop previews without a title
        let (base, _) = serve(vec![Route::new("/page", "text/html", "<p>no title</p>")]);
        let result = generate_preview_from_url(format!("{base}/page"), &client()).await;
        assert!(result.is_err() || result.unwrap().title.is_some());
    }

    #[tokio::test]
    async fn image_link_is_titled_by_file_name() {
        let (base, _) = serve(vec![Route::new(
            "/logo.png",
            "image/png",
            b"\x89PNG\r\n\x1a\n".to_vec(),
        )]);
        let preview = generate_preview_from_url(format!("{base}/logo.png"), &client())
            .await
            .unwrap();
        assert_eq!(preview.title.as_deref(), Some("logo.png"));
        assert!(preview.image.is_some());
    }

    #[tokio::test]
    async fn relative_og_image_is_fetched() {
        let (base, _) = serve(vec![
            Route::new(
                "/page",
                "text/html",
                r#"<meta property="og:image" content="/img.png"><title>t</title>"#,
            ),
            Route::new("/img.png", "image/png", b"\x89PNG\r\n\x1a\n".to_vec()),
        ]);
        let preview = generate_preview_from_url(format!("{base}/page"), &client())
            .await
            .unwrap();
        assert!(preview.image.is_some());
    }

    #[tokio::test]
    async fn oversized_image_is_dropped() {
        // Signal-Android caps preview images at 2 MB
        let mut big = b"\x89PNG\r\n\x1a\n".to_vec();
        big.resize(3 * 1024 * 1024, 0);
        let image_base = serve(vec![Route::new("/big.png", "image/png", big)]).0;
        let (base, _) = serve(vec![Route::new(
            "/page",
            "text/html",
            format!(r#"<meta property="og:image" content="{image_base}/big.png"><title>t</title>"#),
        )]);
        let preview = generate_preview_from_url(format!("{base}/page"), &client())
            .await
            .unwrap();
        assert!(preview.image.is_none());
    }

    #[tokio::test]
    async fn requests_use_whatsapp_user_agent() {
        let (base, requests) = serve(vec![Route::new("/page", "text/html", "<title>t</title>")]);
        let _ = generate_preview_from_url(format!("{base}/page"), &client()).await;
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0].header("user-agent"), Some("WhatsApp/2"));
    }

    #[tokio::test]
    async fn hanging_server_times_out() {
        let (base, _) = serve(vec![Route {
            hang: true,
            ..Route::new("/page", "text/html", "")
        }]);
        let client = client();
        let fetch = generate_preview_from_url(format!("{base}/page"), &client);
        assert!(
            tokio::time::timeout(Duration::from_secs(30), fetch)
                .await
                .is_ok(),
            "fetching a preview must not hang the send"
        );
    }

    // defences

    #[test]
    fn reserved_domains_are_case_insensitive() {
        assert!(extracted("https://Example.COM/x https://foo.I2P https://bar.Onion").is_empty());
    }

    #[test]
    fn private_ip_literals_are_not_previewed() {
        for url in [
            "https://10.0.0.1/",
            "https://172.16.0.1/",
            "https://192.168.1.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[fc00::1]/",
            "https://[fe80::1]/",
            "https://[::ffff:127.0.0.1]/",
        ] {
            assert!(extracted(url).is_empty(), "{url}");
        }
    }

    #[tokio::test]
    async fn redirect_to_internal_host_is_not_followed() {
        let (internal, requests) = serve(vec![Route::new(
            "/admin",
            "text/html",
            "<title>internal</title>",
        )]);
        let internal = internal.replace(HOST, "127.0.0.1");
        let (base, _) = serve(vec![Route::redirect("/page", format!("{internal}/admin"))]);
        let _ = generate_preview_from_url(format!("{base}/page"), &client()).await;
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn og_image_must_be_https() {
        let (image_base, requests) = serve_http(vec![Route::new(
            "/img.png",
            "image/png",
            b"\x89PNG\r\n\x1a\n".to_vec(),
        )]);
        let (base, _) = serve(vec![Route::new(
            "/page",
            "text/html",
            format!(r#"<meta property="og:image" content="{image_base}/img.png"><title>t</title>"#),
        )]);
        let preview = generate_preview_from_url(format!("{base}/page"), &client())
            .await
            .unwrap();
        assert!(preview.image.is_none());
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cookies_are_not_sent_back() {
        let (base, requests) = serve(vec![Route {
            headers: "Set-Cookie: session=secret\r\n".to_owned(),
            ..Route::new("/page", "text/html", "<title>t</title>")
        }]);
        let client = client();
        let _ = generate_preview_from_url(format!("{base}/page"), &client).await;
        let _ = generate_preview_from_url(format!("{base}/page"), &client).await;
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.header("cookie").is_none()));
    }
}
