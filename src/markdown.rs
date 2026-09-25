//! Safe Markdown rendering for user-authored comment bodies.
//!
//! Comment text is stored as raw Markdown and must be safe to embed into
//! the operator UI. Rendering happens on the server so the sanitization
//! policy cannot be bypassed by API clients or forged form posts: the raw
//! source is parsed with `pulldown-cmark`, the generated HTML is passed
//! through `ammonia`, and only the sanitized result may ever cross into a
//! template with autoescaping disabled.

use std::collections::HashSet;

use ammonia::Builder;
use pulldown_cmark::{Options, Parser, html};

/// Link and image URL schemes accepted in rendered comments. Anything else
/// (notably `javascript:`, `data:`, and `file:`) is stripped by the
/// sanitizer; site-relative paths are always allowed.
const URL_SCHEMES: [&str; 3] = ["http", "https", "mailto"];

/// Renders untrusted Markdown into sanitized HTML.
///
/// Tables, strikethrough, and task lists are enabled to match what the
/// `EasyMDE` editor toolbar offers. Raw HTML in the source is treated as
/// untrusted: disallowed elements are removed (their text content kept),
/// event-handler attributes are dropped, and URLs are restricted to the
/// allowlisted schemes.
#[must_use]
pub fn render_markdown(source: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(source, options);

    let mut rendered = String::with_capacity(source.len() * 2);
    html::push_html(&mut rendered, parser);
    sanitize(&rendered)
}

/// Removes everything the comment UI must never contain from an HTML
/// fragment. The builder defaults already cover the dangerous baseline
/// (`script`/`style` contents dropped, no `iframe`, no event handlers, no
/// `style` attributes, links gain `rel="noopener noreferrer"`), so the
/// customization only tightens the policy for this application.
fn sanitize(html: &str) -> String {
    let mut sanitizer = Builder::default();
    sanitizer
        .url_schemes(URL_SCHEMES.iter().copied().collect::<HashSet<_>>())
        // Task-list items render an `<input>`; restrict it to the disabled
        // checkbox shape the Markdown parser produces.
        .add_tags(["input"])
        .add_tag_attributes("input", ["type", "checked", "disabled"])
        .set_tag_attribute_value("input", "type", "checkbox")
        .set_tag_attribute_value("input", "disabled", "")
        // Element ids are meaningless inside a comment card and would let
        // comment authors spoof or clobber the application's own anchors.
        .attribute_filter(|_element, attribute, value| {
            (attribute != "id").then_some(std::borrow::Cow::Borrowed(value))
        });
    sanitizer.clean(html).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::render_markdown;

    #[test]
    fn markdown_renders_common_constructs() {
        let html = render_markdown("# Title\n\n**bold** and _italic_\n\n- a\n- b\n");
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<em>italic</em>"));
        assert!(html.contains("<li>a</li>"));
    }

    #[test]
    fn tables_strikethrough_and_task_lists_render() {
        let html = render_markdown("| a | b |\n| - | - |\n| 1 | 2 |\n\n~~gone~~\n\n- [x] done\n");
        assert!(html.contains("<table>"));
        assert!(html.contains("<del>gone</del>"));
        assert!(html.contains(r#"type="checkbox""#));
    }

    #[test]
    fn code_and_quotes_render() {
        let html = render_markdown("> quoted\n\n`inline`\n\n```\nblock\n```\n");
        assert!(html.contains("<blockquote>"));
        assert!(html.contains("<code>inline</code>"));
        assert!(html.contains("<pre>"));
    }

    #[test]
    fn links_get_sandboxed_relationships() {
        let html = render_markdown("[site](https://example.com)");
        assert!(html.contains("rel=\"noopener noreferrer\""));
    }

    #[test]
    fn scripts_are_removed() {
        let html = render_markdown("hello <script>alert(1)</script> world");
        assert!(!html.contains("<script"));
        assert!(!html.contains("alert(1)"));
    }

    #[test]
    fn event_handlers_are_stripped() {
        let html = render_markdown("<img src=\"https://example.com/a.png\" onerror=\"alert(1)\">");
        assert!(!html.contains("onerror"));
        assert!(html.contains("src=\"https://example.com/a.png\""));
    }

    #[test]
    fn javascript_urls_are_removed() {
        let html = render_markdown("[click](javascript:alert(1))");
        assert!(!html.contains("javascript:"));
        let html = render_markdown("<a href=\"javascript:alert(1)\">x</a>");
        assert!(!html.contains("javascript:"));
    }

    #[test]
    fn data_urls_are_removed() {
        let html = render_markdown("![x](data:text/html;base64,PHNjcmlwdD4=)");
        assert!(!html.contains("data:"));
    }

    #[test]
    fn https_links_and_relative_paths_survive() {
        let html = render_markdown("[site](https://example.com) [rel](/projects)");
        assert!(html.contains("href=\"https://example.com\""));
        assert!(html.contains("href=\"/projects\""));
    }

    #[test]
    fn html_ids_and_styles_are_stripped() {
        let html = render_markdown("<span id=\"csrf_token\" style=\"color:red\">x</span>");
        assert!(!html.contains("id="));
        assert!(!html.contains("style="));
    }

    #[test]
    fn unsafe_markdown_source_is_never_emitted_raw() {
        let source =
            "# hi\n\n<script>alert(1)</script>\n\n<iframe src=\"https://evil\"></iframe>\n";
        let html = render_markdown(source);
        assert!(!html.contains("<iframe"));
        assert!(!html.contains("<script"));
        assert!(html.contains("<h1>hi</h1>"));
    }
}
