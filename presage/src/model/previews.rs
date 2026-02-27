use chrono;
use futures::stream::{self, StreamExt};
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
                        let image: Option<Vec<u8>> = fetch_image_from_response(response).await.ok();
                        PreviewContent {
                            url: None,
                            title: None,
                            image,
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
    let mut _previews: Vec<PreviewContent> = Vec::new();
    let mut preview = PreviewContent {
        url: None,
        title: None,
        image: None,
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
                "image" => preview.image = fetch_image_from_url(content, client).await.ok(),
                "description" => preview.description = Some(content),
                "date" | "article:published_time" | "article:modified_time" => {
                    preview.date = std::cmp::max(preview.date, timestamp_from_iso(&content))
                }
                _ => (),
            }
        }

        // Check whether the preview is still missing any fields; if not, break.
        // in practice, since date is never filled, this will never break early.
        if [
            &preview.url.is_none(),
            &preview.title.is_none(),
            &preview.image.is_none(),
            &preview.description.is_none(),
            &preview.date.is_none(),
        ]
        .iter()
        .any(|&field| !field)
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
    dbg!(preview)
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

async fn fetch_image_from_url<T: IntoUrl>(
    url: T,
    client: &reqwest::Client,
) -> Result<Vec<u8>, Error> {
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

async fn fetch_image_from_response(response: reqwest::Response) -> Result<Vec<u8>, Error> {
    let bytes = response.bytes().await?;

    if !check_if_image_signature(&bytes) {
        return Err(Error::NonImageBytesError);
    }

    let data: Vec<u8> = bytes.into();
    Ok(data)
}

fn timestamp_from_iso(datetime_str: &str) -> Option<u64> {
    let datetime = chrono::DateTime::parse_from_rfc3339(datetime_str).ok()?;
    let timestamp = chrono::DateTime::timestamp(&datetime);
    Some(timestamp as u64)
}

fn check_if_image_signature(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xD8, 0xFF]) ||               // JPEG
    bytes.starts_with(&[0x89, b'P', b'N', b'G']) ||        // PNG
    bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") || // GIF
    bytes.starts_with(b"BM") ||                             // BMP
    bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP")
}
