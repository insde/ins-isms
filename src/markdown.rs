use std::collections::{HashMap, HashSet};

use ammonia::{Builder, UrlRelative};
use pulldown_cmark::{Options, Parser, html};

pub fn is_valid_anchor_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_')
}

pub fn render_markdown_safe(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown, options);
    let mut raw_html = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut raw_html, parser);

    let allowed_tags: HashSet<&str> = [
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "p",
        "ul",
        "ol",
        "li",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "blockquote",
        "pre",
        "code",
        "strong",
        "em",
        "del",
        "hr",
        "br",
        "a",
    ]
    .into_iter()
    .collect();

    let mut tag_attributes: HashMap<&str, HashSet<&str>> = HashMap::new();
    tag_attributes.insert("a", ["href", "id"].into_iter().collect());

    let allowed_schemes: HashSet<&str> = ["http", "https", "mailto"].into_iter().collect();

    Builder::empty()
        .tags(allowed_tags)
        .tag_attributes(tag_attributes)
        .url_schemes(allowed_schemes)
        .url_relative(UrlRelative::PassThrough)
        .link_rel(Some("noopener noreferrer"))
        .attribute_filter(|tag, attr, value| {
            if tag == "a" && attr == "id" {
                if is_valid_anchor_id(value) {
                    Some(value.into())
                } else {
                    None
                }
            } else {
                Some(value.into())
            }
        })
        .clean(&raw_html)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_xss_payloads_and_dangerous_schemes() {
        let md = r#"
# Richtlinie

<script>alert('xss')</script>
<iframe src="https://evil.example/frame"></iframe>
<img src="x" onerror="alert(1)">
<p onclick="alert(2)">Text</p>

[Klick](javascript:alert(1))
[Daten](data:text/html,<script>alert(1)</script>)
"#;
        let html = render_markdown_safe(md);
        assert!(!html.contains("<script"));
        assert!(!html.contains("<iframe"));
        assert!(!html.contains("onerror"));
        assert!(!html.contains("onclick"));
        assert!(!html.contains("javascript:"));
        assert!(!html.contains("data:text/html"));
        assert!(html.contains("<h1>Richtlinie</h1>"));
        assert!(html.contains("<p>Text</p>"));
    }

    #[test]
    fn preserves_valid_anchor_ids_and_tables_while_rejecting_invalid_ids() {
        let md = r#"
## <a id="clean-desk"></a> 3.1 Clean-Desk-Regel

<a id="INVALID ID!"></a>

| Bereich | Vorgabe |
|---|---|
| Schreibtisch | Leer bei Abwesenheit |

Siehe [Abschnitt](#clean-desk).
"#;
        let html = render_markdown_safe(md);
        assert!(html.contains(r#"id="clean-desk""#));
        assert!(!html.contains("INVALID ID!"));
        assert!(html.contains("<table>"));
        assert!(html.contains(r##"href="#clean-desk""##));
    }
}
