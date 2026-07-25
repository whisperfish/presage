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
