use regex::Regex;
use reqwest::IntoUrl;
use scraper::{Html, Selector};
use url::Url;
use futures::stream::{self, StreamExt};
use mime::Mime;
use reqwest::header::CONTENT_TYPE;
use std::str::FromStr;

use libsignal_service::proto::Preview;

pub async fn generate_preview_from_url<T: IntoUrl>(url: T) -> Result<Preview, String> {
    //let url = url.into_url()?;
    let url = url.into_url().map_err(|e| format!("Reqwest error: {e}"))?;
    // a default url value in case the og:url tag is missing
    let default_url_preview = url.clone().host_str().map(|y| y.to_string());
    let html = fetch_html_of_url(url).await?;

    let mut preview = generate_preview_from_html(&html);

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
pub fn generate_preview_from_html(html_doc: &str) -> Preview {
    let document = Html::parse_document(html_doc);
    let selector = Selector::parse("meta").unwrap();
    let mut _previews: Vec<Preview> = Vec::new();
    let mut preview = Preview {
        url: None,
        title: None,
        image: None,
        description: None,
        date: None,
    };

    let re = Regex::new(r"^og:(.*)").unwrap();
    for element in document.select(&selector) {
        // get description from <meta name="description">
        let name = element
            .value()
            .attr("name")
            .unwrap_or("")
            .trim()
            .to_string();

        if (name == "description") & (preview.description.is_none()) {
            if let Some(c) = element.value().attr("content") {
                preview.description = Some(c.to_string())
            }
        }

        // get fields from <meta property="og:"
        let property = element.value().attr("property").unwrap_or("").to_string();
        if let Some(capture) = re.captures(&property) {
            let field = capture[1].trim();
            let content = element.value().attr("content").unwrap_or("").to_string();
            match field {
                "url" => preview.url = Some(content),
                "title" => preview.title = Some(content),
                // todo()! "image" => preview.image = todo!(),
                "description" => preview.description = Some(content),
                "date" => preview.date = Some(content.parse().unwrap_or(0)),
                _ => (),
            }
        }

        // Check whether the preview is still missing any fields; if not, break.
        // in practice, since date is never filled, this will never break early.
        if ![
            &preview.url,
            &preview.title,
            //&preview.image,
            &preview.description,
            &preview.date.map(|v| v.to_string()),
        ]
        .iter()
        .any(|&field| field.is_none())
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

async fn fetch_html_of_url<T: IntoUrl>(url: T) -> Result<String, String> {
    let mut headers = reqwest::header::HeaderMap::new();

    // appeared in tutorials for scraping, but seems not to be necessary:
    // headers.insert("authorization", "<authorization>".parse().unwrap());
    headers.insert("user-agent", "CUSTOM_NAME/1.0".parse().unwrap());

    let response = reqwest::Client::new()
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("Reqwest error: {e}"))?;

    let headers = &response.headers();

    match headers.get(CONTENT_TYPE) {
        None => Err("The response does not contain a Content-Type header.".to_string()),
        Some(content_type) => {
            let content_type = content_type
                .to_str()
                .map_err(|e| format!("error converting content type to string: {e}"))?;
            let content_type = Mime::from_str(content_type)
                .map_err(|e| format!("error converting straing type to mime struct: {e}"))?;
            let media_type = match (content_type.type_(), content_type.subtype()) {
                (mime::TEXT, mime::HTML) => {
                    return response
                        .error_for_status()
                        .map_err(|e| format!("Status error: {e}"))?
                        .text()
                        .await
                        .map_err(|e| format!("Reqwest error: {e}"))
                }
                (mime::TEXT, _) => "non-html text document",
                (mime::IMAGE, mime::PNG) => "PNG image",
                (mime::IMAGE, mime::BMP) => "BMP image",
                (mime::IMAGE, mime::GIF) => "GIF image",
                (mime::IMAGE, mime::JPEG) => "JPEG image",
                (mime::IMAGE, mime::SVG) => "SVG image",
                (mime::IMAGE, _) => "image",
                (mime::AUDIO, mime::MPEG) => "mpeg audio",
                (mime::AUDIO, mime::MP4) => "mp4 audio",
                (mime::AUDIO, mime::OGG) => "ogg audio",
                (mime::AUDIO, _) => "audio",
                (mime::APPLICATION, mime::PDF) => "pdf",
                (mime::APPLICATION, mime::JSON) => "json",
                (mime::APPLICATION, _) => "application",
                _ => "neither HTML, text, image, audio nor application",
            };

            Err(format!("Got mime type:{}.", media_type))
        }
    }
}

pub async fn generate_previews_from_message(message: &str) -> Vec<Preview> {
    let urls = extract_urls_from_text_block(message);

    // consider buffering
    stream::iter(urls)
        .filter_map(async |url| generate_preview_from_url(url).await.ok())
        .collect()
        .await
}
