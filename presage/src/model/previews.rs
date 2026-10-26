use libsignal_service::sender::AttachmentSpec;
use mime::Mime;
use regex::Regex;
use reqwest::header::CONTENT_TYPE;
use reqwest::IntoUrl;
use scraper::{Html, Selector};
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use url::{Host, Url};

// same limits as Signal-Android
const MAX_HTML_SIZE: usize = 2 * 1024 * 1024;
const MAX_IMAGE_SIZE: usize = 2 * 1024 * 1024;

// Signal clients don't preview links to these
const RESERVED_DOMAINS: &[&str] = &[
    "example",
    "example.com",
    "example.net",
    "example.org",
    "i2p",
    "invalid",
    "localhost",
    "onion",
    "test",
];

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("The response does not contain a Content-Type header")]
    MissingContentTypeHeadersError,
    #[error("Unsupported mime type: {0}")]
    UnsupportedMimeTypeError(String),
    #[error("Downloaded file does not look like an image")]
    NonImageBytesError,
    #[error("ToStr error: {0}")]
    ToStrError(#[from] reqwest::header::ToStrError),
    #[error("FromStr error: {0}")]
    FromStrError(#[from] mime::FromStrError),
    #[error("The page has no title")]
    MissingTitleError,
    #[error("The page is larger than {MAX_HTML_SIZE} bytes")]
    HtmlTooLargeError,
    #[error("The image is larger than {MAX_IMAGE_SIZE} bytes")]
    ImageTooLargeError,
    #[error("Redirect to a url that can't be previewed")]
    RedirectError,
    #[error("The url can't be previewed")]
    NotPreviewableError,
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

/// Client for fetching previews: https only, no internal hosts, and a timeout.
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent("WhatsApp/2")
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if is_previewable(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
}

/// Whether Signal clients accept a preview for `url`: https, and a public domain name.
fn is_previewable(url: &Url) -> bool {
    let Some(Host::Domain(domain)) = url.host() else {
        return false;
    };
    // "localhost." is localhost
    let domain = domain.trim_end_matches('.');
    url.scheme() == "https"
        && !RESERVED_DOMAINS
            .iter()
            .any(|reserved| domain == *reserved || domain.ends_with(&format!(".{reserved}")))
}

pub async fn generate_preview_from_url<T: IntoUrl + AsRef<str>>(
    url: T,
    client: &reqwest::Client,
) -> Result<PreviewContent, Error> {
    // receivers drop the preview if its url is not exactly as in the message body
    let link = url.as_ref().to_owned();
    let url = url.into_url()?;
    if !is_previewable(&url) {
        return Err(Error::NotPreviewableError);
    }

    let mut preview: PreviewContent = {
        let mut response = client.get(url.clone()).send().await?.error_for_status()?;
        // the client stopped at a redirect to an invalid url
        if response.status().is_redirection() {
            return Err(Error::RedirectError);
        }

        let headers = &response.headers();

        match headers.get(CONTENT_TYPE) {
            None => return Err(Error::MissingContentTypeHeadersError),
            Some(content_type) => {
                let content_type = content_type.to_str()?;
                let content_type = Mime::from_str(content_type)?;
                match (content_type.type_(), content_type.subtype()) {
                    (mime::TEXT, mime::HTML) => {
                        let mut html = Vec::new();
                        while let Some(chunk) = response.chunk().await? {
                            if html.len() + chunk.len() > MAX_HTML_SIZE {
                                return Err(Error::HtmlTooLargeError);
                            }
                            html.extend_from_slice(&chunk);
                        }
                        let html = String::from_utf8_lossy(&html);
                        fetch_preview_from_html(&html, &url, client).await
                    }
                    (mime::IMAGE, _) => {
                        // like Signal-Android, use the file name as title
                        let title = response
                            .url()
                            .path_segments()
                            .and_then(|mut segments| segments.next_back())
                            .filter(|name| !name.is_empty())
                            .map(|name| {
                                percent_encoding::percent_decode_str(name)
                                    .decode_utf8_lossy()
                                    .into_owned()
                            });
                        let (image, image_content_type) =
                            match fetch_image_from_response(response).await {
                                Ok((bytes, content_type)) => (Some(bytes), Some(content_type)),
                                Err(_) => (None, None),
                            };
                        PreviewContent {
                            url: None,
                            title,
                            image,
                            image_content_type,
                            description: None,
                            date: None,
                        }
                    }
                    _ => return Err(Error::UnsupportedMimeTypeError(content_type.to_string())),
                }
            }
        }
    };

    if preview.title.as_deref().is_none_or(str::is_empty) {
        return Err(Error::MissingTitleError);
    }
    preview.url = Some(link);
    Ok(preview)
}

/// The function builds a Preview primarily from the html's OG tags.
/// If some of these are unavailable, it resorts to other tags to fill the preview's fields.
/// The title is taken from the <title> tag (if available).
/// The description is taken from the  <meta name="description"> tag (if available).
pub async fn fetch_preview_from_html(
    html_doc: &str,
    url: &Url,
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

    // like Signal-Android, the first date found in this order
    let date_properties = [
        "og:published_time",
        "article:published_time",
        "og:modified_time",
        "article:modified_time",
    ];
    let mut dates = [None; 4];

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
        let property = element
            .value()
            .attr("property")
            .unwrap_or("")
            .to_ascii_lowercase();
        if let Some(i) = date_properties.iter().position(|p| *p == property) {
            dates[i] = timestamp_from_iso(element.value().attr("content").unwrap_or(""));
        }
        if let Some(capture) = property.strip_prefix("og:") {
            let field = capture.trim();
            let content = element.value().attr("content").unwrap_or("").to_string();
            match field {
                "title" => preview.title = Some(content),
                "image" if preview.image.is_none() => {
                    // og:image may be relative to the page
                    let image_url = url.join(&content).ok().filter(is_previewable);
                    if let Some(image_url) = image_url {
                        if let Ok((bytes, content_type)) =
                            fetch_image_from_url(image_url, client).await
                        {
                            preview.image = Some(bytes);
                            preview.image_content_type = Some(content_type);
                        }
                    }
                }
                "description" => preview.description = Some(content),
                _ => (),
            }
        }
    }
    preview.date = dates.into_iter().flatten().next();

    // in case no og:title was found, get the value from <title>
    if preview.title.is_none() | (preview.title == Some("".to_string())) {
        let selector = Selector::parse("title").unwrap();
        let title = document
            .select(&selector)
            .next()
            .map(|x| x.text().collect::<String>().trim().to_owned());
        preview.title = title;
    }
    preview
}

// Characters that end a link, as in Signal-Android's `Linkifier`
const LINK_END: &str = r#"\s\x{85}\x{A0}\x{1680}\x{2000}-\x{200D}\x{2028}\x{2029}\x{202A}-\x{202F}\x{205F}\x{2066}-\x{2069}\x{3000}\x{FEFF}<>"`|\\"#;

/// Bidi controls and zero-width characters, used to spoof links.
fn is_format_char(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Finds links the way Signal-Android's `Linkifier` does: receivers drop a preview whose url
/// isn't exactly one of the links they find in the message body.
pub fn extract_urls_from_text_block(message: &str) -> Vec<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        // scheme, host (which can't contain an apostrophe), then path, query or fragment
        Regex::new(&format!(
            r"(?i)https?://[^{LINK_END}'/?#]+(?:[/?#][^{LINK_END}]*)?"
        ))
        .unwrap()
    });

    let mut urls = Vec::new();

    for m in RE.find_iter(message) {
        let before = message[..m.start()].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '@' || is_format_char(c))
        {
            continue;
        }

        // a comma or semicolon right before another link ends this one
        let mut candidate = m.as_str();
        if let Some((i, _)) = candidate.match_indices([',', ';']).find(|(i, _)| {
            let next = candidate[i + 1..].to_ascii_lowercase();
            ["http://", "https://", "www."]
                .iter()
                .any(|p| next.starts_with(p))
        }) {
            candidate = &candidate[..i];
        }

        // trim punctuation, and closing brackets without an opening one
        while let Some(last) = candidate.chars().next_back() {
            let rest = &candidate[..candidate.len() - last.len_utf8()];
            let opener = match last {
                '.' | ',' | '!' | '?' | ';' | ':' | '\'' | '"' | '`' | '|' | '<' | '>' => {
                    candidate = rest;
                    continue;
                }
                ')' => '(',
                ']' => '[',
                '}' => '{',
                _ => break,
            };
            if rest.matches(last).count() >= rest.matches(opener).count() {
                candidate = rest;
            } else {
                break;
            }
        }

        let after = message[m.start() + candidate.len()..].chars().next();
        if after.is_some_and(is_format_char) {
            continue;
        }

        if Url::parse(candidate).is_ok_and(|url| is_previewable(&url)) {
            urls.push(candidate.to_owned());
        }
    }
    urls
}

/// Returns `None` if `message` has no link to preview.
pub async fn generate_preview_from_message(
    message: &str,
    client: &reqwest::Client,
) -> Result<Option<PreviewContent>, Error> {
    // like Signal clients, only preview the first link
    let Some(url) = extract_urls_from_text_block(message).into_iter().next() else {
        return Ok(None);
    };

    generate_preview_from_url(url, client).await.map(Some)
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
    let response: reqwest::Response = client.get(url).send().await?.error_for_status()?;

    fetch_image_from_response(response).await
}

/// Fetches the body of `response`, returning its bytes along with the detected image MIME
/// (e.g. `image/jpeg`), preferring the response's own `Content-Type` header and falling
/// back to sniffing the file signature when that header is missing or not an image type.
async fn fetch_image_from_response(
    mut response: reqwest::Response,
) -> Result<(Vec<u8>, String), Error> {
    let header_content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Mime::from_str(value).ok())
        .filter(|mime| mime.type_() == mime::IMAGE)
        .map(|mime| mime.essence_str().to_string());

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_IMAGE_SIZE {
            return Err(Error::ImageTooLargeError);
        }
        bytes.extend_from_slice(&chunk);
    }

    let Some(content_type) =
        header_content_type.or_else(|| sniff_image_mime_type(&bytes).map(str::to_string))
    else {
        return Err(Error::NonImageBytesError);
    };

    Ok((bytes, content_type))
}

fn timestamp_from_iso(datetime_str: &str) -> Option<u64> {
    let datetime = chrono::DateTime::parse_from_rfc3339(datetime_str).ok()?;
    let timestamp = chrono::DateTime::timestamp_millis(&datetime);
    u64::try_from(timestamp)
        .ok()
        .filter(|&timestamp| timestamp > 0)
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
            extract_urls_from_text_block("check this out: https://signal.org/foo"),
            vec!["https://signal.org/foo"]
        );

        assert_eq!(
            extract_urls_from_text_block("see (https://signal.org/foo) for details"),
            vec!["https://signal.org/foo"]
        );

        assert_eq!(
            extract_urls_from_text_block("visit https://signal.org."),
            vec!["https://signal.org"]
        );

        assert_eq!(
            extract_urls_from_text_block("https://a.com and https://b.com/path?x=1"),
            vec!["https://a.com", "https://b.com/path?x=1"]
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
    async fn test_fetch_preview_from_html_uses_og_tags() {
        let html = r#"
            <html><head>
                <meta property="og:title" content="Example title">
                <meta property="og:description" content="Example description">
                <title>Fallback title</title>
            </head></html>
        "#;
        let client = reqwest::Client::new();
        let url = Url::parse("https://signal.org").unwrap();
        let preview = fetch_preview_from_html(html, &url, &client).await;

        assert_eq!(preview.title.as_deref(), Some("Example title"));
        assert_eq!(preview.description.as_deref(), Some("Example description"));
        assert!(preview.image.is_none());
    }

    #[tokio::test]
    async fn test_fetch_preview_from_html_falls_back_to_title_tag() {
        let html = r#"
            <html><head>
                <meta name="description" content="Meta description">
                <title>  Fallback title  </title>
            </head></html>
        "#;
        let client = reqwest::Client::new();
        let url = Url::parse("https://signal.org").unwrap();
        let preview = fetch_preview_from_html(html, &url, &client).await;

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
    use std::net::TcpListener;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    use axum::extract::State;
    use axum::http::{header, HeaderMap, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use axum_server::tls_rustls::RustlsConfig;
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
        client_builder()
            .tls_certs_only([reqwest::Certificate::from_der(&TLS.cert).unwrap()])
            .resolve(HOST, "127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap()
    }

    struct Route {
        path: &'static str,
        status: StatusCode,
        content_type: &'static str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        hang: bool,
    }

    impl Route {
        fn new(path: &'static str, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
            Self {
                path,
                status: StatusCode::OK,
                content_type,
                headers: Vec::new(),
                body: body.into(),
                hang: false,
            }
        }

        fn redirect(path: &'static str, location: String) -> Self {
            Self {
                status: StatusCode::FOUND,
                headers: vec![("location", location)],
                ..Self::new(path, "text/html", "")
            }
        }
    }

    struct Request {
        headers: HeaderMap,
    }

    impl Request {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name)?.to_str().ok()
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
        listener.set_nonblocking(true).unwrap();
        let base = format!(
            "{scheme}://{HOST}:{}",
            listener.local_addr().unwrap().port()
        );
        let requests = Requests::default();
        let app = axum::Router::new()
            .fallback(handle)
            .with_state((Arc::new(routes), requests.clone()))
            .into_make_service();
        if scheme == "https" {
            let config = RustlsConfig::from_config(TLS.config.clone());
            let server = axum_server::from_tcp_rustls(listener, config).unwrap();
            tokio::spawn(server.serve(app));
        } else {
            tokio::spawn(axum_server::from_tcp(listener).unwrap().serve(app));
        }
        (base, requests)
    }

    async fn handle(
        State((routes, seen)): State<(Arc<Vec<Route>>, Requests)>,
        uri: Uri,
        headers: HeaderMap,
    ) -> Response {
        seen.lock().unwrap().push(Request { headers });
        let Some(route) = routes.iter().find(|r| r.path == uri.path()) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if route.hang {
            std::future::pending::<()>().await;
        }
        let mut response = (
            route.status,
            [(header::CONTENT_TYPE, route.content_type)],
            route.body.clone(),
        )
            .into_response();
        for (name, value) in &route.headers {
            response.headers_mut().insert(*name, value.parse().unwrap());
        }
        response
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
    fn links_match_signal_android_linkifier() {
        for (body, link) in [
            ("see https://signal.org;", "https://signal.org"),
            ("see https://signal.org|", "https://signal.org"),
            ("https://signal.org/x[1]", "https://signal.org/x[1]"),
            ("[https://signal.org/x]", "https://signal.org/x"),
            ("https://signal.org's blog", "https://signal.org"),
            ("<https://signal.org/x>", "https://signal.org/x"),
            ("\"https://signal.org/x\"", "https://signal.org/x"),
            ("https://signal.org/a,https://b.org", "https://signal.org/a"),
            ("https://signal.org/a,b", "https://signal.org/a,b"),
            ("HTTPS://signal.org", "HTTPS://signal.org"),
        ] {
            assert_eq!(
                extracted(body).first().map(String::as_str),
                Some(link),
                "{body}"
            );
        }
    }

    #[test]
    fn links_glued_to_other_text_are_ignored() {
        for body in [
            "xhttps://signal.org",
            "@https://signal.org",
            "\u{202E}https://signal.org",
            "https://signal.org\u{200B}",
            "http://a.org/https://signal.org",
        ] {
            assert!(extracted(body).is_empty(), "{body:?}");
        }
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
        let url = Url::parse("https://signal.org").unwrap();
        let preview = fetch_preview_from_html(html, &url, &client()).await;
        assert_eq!(preview.title.as_deref(), Some("Signal & you"));
    }

    #[tokio::test]
    async fn date_is_article_published_time_in_millis() {
        let html = r#"<html><head>
            <meta property="og:title" content="t">
            <meta property="article:published_time" content="2024-01-01T00:00:00Z">
        </head></html>"#;
        let url = Url::parse("https://signal.org").unwrap();
        let preview = fetch_preview_from_html(html, &url, &client()).await;
        assert_eq!(preview.date, Some(1_704_067_200_000));
    }

    #[tokio::test]
    async fn date_prefers_published_over_modified() {
        let html = r#"<html><head>
            <meta property="article:modified_time" content="2024-02-01T00:00:00Z">
            <meta property="og:published_time" content="2024-01-01T00:00:00Z">
        </head></html>"#;
        let url = Url::parse("https://signal.org").unwrap();
        let preview = fetch_preview_from_html(html, &url, &client()).await;
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
    async fn image_file_name_is_decoded() {
        let (base, _) = serve(vec![Route::new(
            "/my%20logo.png",
            "image/png",
            b"\x89PNG\r\n\x1a\n".to_vec(),
        )]);
        let preview = generate_preview_from_url(format!("{base}/my%20logo.png"), &client())
            .await
            .unwrap();
        assert_eq!(preview.title.as_deref(), Some("my logo.png"));
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
    async fn large_page_is_rejected() {
        // Signal-Android gives up on pages over 2 MB
        let mut html = b"<title>t</title>".to_vec();
        html.resize(3 * 1024 * 1024, b' ');
        let (base, _) = serve(vec![Route::new("/page", "text/html", html)]);
        let result = generate_preview_from_url(format!("{base}/page"), &client()).await;
        assert!(matches!(result, Err(Error::HtmlTooLargeError)));
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

    #[test]
    fn trailing_dot_is_not_a_bypass() {
        assert!(extracted("https://localhost./ https://example.com./").is_empty());
    }

    #[tokio::test]
    async fn invalid_url_is_not_fetched() {
        let (base, requests) =
            serve_http(vec![Route::new("/page", "text/html", "<title>t</title>")]);
        let result = generate_preview_from_url(format!("{base}/page"), &client()).await;
        assert!(matches!(result, Err(Error::NotPreviewableError)));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dates_before_1970_are_ignored() {
        let html = r#"<meta property="article:published_time" content="1969-01-01T00:00:00Z">"#;
        let url = Url::parse("https://signal.org").unwrap();
        let preview = fetch_preview_from_html(html, &url, &client()).await;
        assert_eq!(preview.date, None);
    }

    #[tokio::test]
    async fn stopped_redirect_is_not_previewed() {
        let (base, _) = serve(vec![Route {
            body: b"<title>Moved</title>".to_vec(),
            ..Route::redirect("/page", "https://127.0.0.1/admin".to_owned())
        }]);
        let result = generate_preview_from_url(format!("{base}/page"), &client()).await;
        assert!(matches!(result, Err(Error::RedirectError)));
    }

    #[tokio::test]
    async fn only_first_og_image_is_fetched() {
        let png = b"\x89PNG\r\n\x1a\n".to_vec();
        let (base, requests) = serve(vec![
            Route::new(
                "/page",
                "text/html",
                r#"<meta property="og:image" content="/a.png">
                <meta property="og:image" content="/b.png"><title>t</title>"#,
            ),
            Route::new("/a.png", "image/png", png.clone()),
            Route::new("/b.png", "image/png", png),
        ]);
        let preview = generate_preview_from_url(format!("{base}/page"), &client())
            .await
            .unwrap();
        assert!(preview.image.is_some());
        assert_eq!(requests.lock().unwrap().len(), 2);
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
            headers: vec![("set-cookie", "session=secret".to_owned())],
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
