use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use sqlx::PgPool;
use tokio::{process::Command, sync::Semaphore, time::timeout};

use crate::{config::Config, error::AppError, markdown::is_valid_anchor_id, storage::BlobStorage};

const MAX_PARALLEL_PDF_JOBS: usize = 4;
const PDF_RENDER_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_PDF_THEME: &str = include_str!("../templates/pdf/theme.typ");

/// Gibt die eingebettete Standard-Typst-Vorlage (`theme.typ`) zurück.
pub fn default_pdf_theme() -> &'static str {
    DEFAULT_PDF_THEME
}

/// Löst die aktive PDF-Designvorlage (externes `PDF_TEMPLATE_DIR/theme.typ` oder Standard) auf.
/// Das zweite Rückgabeelement ist `true`, wenn eine benutzerdefinierte Vorlage geladen wurde.
pub async fn resolve_pdf_theme(template_dir: Option<&Path>) -> Result<(String, bool), AppError> {
    if let Some(dir) = template_dir {
        let custom_path = dir.join("theme.typ");
        if tokio::fs::try_exists(&custom_path).await.unwrap_or(false) {
            let content = tokio::fs::read_to_string(&custom_path).await.map_err(|e| {
                AppError::Validation(vec![format!(
                    "Benutzerdefinierte PDF-Vorlage ({}) konnte nicht gelesen werden: {e}",
                    custom_path.display()
                )])
            })?;
            return Ok((content, true));
        }
    }
    Ok((DEFAULT_PDF_THEME.to_string(), false))
}

#[derive(Debug, Clone)]
pub struct PdfDocumentMetadata {
    pub organization_name: String,
    pub doc_code: String,
    pub title: String,
    pub version: String,
    pub status: String,
    pub classification: String,
    pub owner_unit: String,
    pub approved_by: String,
    pub approved_at: String,
    pub next_review_at: String,
}

#[async_trait]
pub trait PdfRenderer: Send + Sync {
    async fn render_markdown_document(
        &self,
        meta: &PdfDocumentMetadata,
        markdown: &str,
    ) -> Result<Vec<u8>, AppError>;

    async fn render_raw_typst(&self, typst_source: &str) -> Result<Vec<u8>, AppError>;
}

pub struct TypstCliRenderer {
    bin_path: PathBuf,
    font_paths: Option<PathBuf>,
    template_dir: Option<PathBuf>,
    logo: Option<(String, Vec<u8>)>,
    semaphore: Arc<Semaphore>,
    timeout_duration: Duration,
}

impl TypstCliRenderer {
    pub fn from_config(config: &Config) -> Self {
        Self {
            bin_path: config.typst_bin_path.clone(),
            font_paths: config.typst_font_paths.clone(),
            template_dir: config.pdf_template_dir.clone(),
            logo: None,
            semaphore: Arc::new(Semaphore::new(MAX_PARALLEL_PDF_JOBS)),
            timeout_duration: PDF_RENDER_TIMEOUT,
        }
    }

    pub async fn with_org_logo(mut self, pool: &PgPool, storage: &dyn BlobStorage) -> Self {
        let key_opt: Option<Option<String>> =
            sqlx::query_scalar("SELECT logo_storage_key FROM organization_profile WHERE id = 1")
                .fetch_optional(pool)
                .await
                .ok();
        if let Some(Some(key)) = key_opt
            && !key.trim().is_empty()
            && let Ok(bytes) = storage.get(&key).await
        {
            let ext = infer::get(&bytes)
                .map(|k| k.extension())
                .filter(|e| matches!(*e, "png" | "jpg" | "jpeg" | "webp"))
                .unwrap_or("png");
            self.logo = Some((format!("org_logo.{ext}"), bytes));
        }
        self
    }
}

#[async_trait]
impl PdfRenderer for TypstCliRenderer {
    async fn render_markdown_document(
        &self,
        meta: &PdfDocumentMetadata,
        markdown: &str,
    ) -> Result<Vec<u8>, AppError> {
        let body_typst = markdown_to_typst(markdown);
        let logo_name = self.logo.as_ref().map(|(name, _)| name.as_str());
        let source = build_iso_document_typst_with_logo(meta, &body_typst, logo_name);
        self.render_raw_typst(&source).await
    }

    async fn render_raw_typst(&self, typst_source: &str) -> Result<Vec<u8>, AppError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| AppError::Internal("PDF-Semaphore geschlossen.".to_string()))?;

        let (theme_source, is_custom_theme) =
            resolve_pdf_theme(self.template_dir.as_deref()).await?;

        let temp_dir = tempfile::TempDir::new()?;
        let theme_path = temp_dir.path().join("theme.typ");
        let input_path = temp_dir.path().join("document.typ");
        let output_path = temp_dir.path().join("document.pdf");

        tokio::fs::write(&theme_path, theme_source.as_bytes()).await?;
        tokio::fs::write(&input_path, typst_source.as_bytes()).await?;

        if let Some((ref logo_name, ref logo_bytes)) = self.logo {
            let safe_name = Path::new(logo_name)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("org_logo.png");
            tokio::fs::write(temp_dir.path().join(safe_name), logo_bytes).await?;
        }

        let mut cmd = Command::new(&self.bin_path);
        cmd.arg("compile")
            .arg("--root")
            .arg(temp_dir.path())
            .arg(&input_path)
            .arg(&output_path);

        if let Some(ref font_dir) = self.font_paths {
            cmd.arg("--font-path").arg(font_dir);
        }

        let output = timeout(self.timeout_duration, cmd.output())
            .await
            .map_err(|_| {
                AppError::Internal("PDF-Erzeugung hat das Zeitlimit überschritten.".to_string())
            })?
            .map_err(|err| {
                tracing::error!(error = %err, bin = %self.bin_path.display(), "Typst-Start fehlgeschlagen");
                AppError::Internal("PDF-Renderer (typst) konnte nicht gestartet werden.".to_string())
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(status = %output.status, custom_theme = is_custom_theme, stderr = %stderr, "Typst-Kompilierung fehlgeschlagen");
            if is_custom_theme {
                let first_line = stderr.lines().next().unwrap_or("Syntaxfehler").trim();
                return Err(AppError::Validation(vec![format!(
                    "Fehler in der benutzerdefinierten PDF-Vorlage (theme.typ): {first_line}"
                )]));
            }
            return Err(AppError::Internal(
                "PDF-Kompilierung fehlgeschlagen.".to_string(),
            ));
        }

        let pdf_bytes = tokio::fs::read(&output_path).await?;
        Ok(pdf_bytes)
    }
}

pub fn escape_typst(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' | '#' | '[' | ']' | '<' | '>' | '*' | '_' | '`' | '$' | '@' | '=' | '/' | '"'
            | '~' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

pub fn markdown_to_typst(markdown: &str) -> String {
    markdown_to_typst_with_labels(markdown, None).0
}

pub fn markdown_to_typst_with_labels(
    markdown: &str,
    label_prefix: Option<&str>,
) -> (String, std::collections::HashSet<String>) {
    let mut emitted_labels = std::collections::HashSet::new();
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown, options);
    let mut out = String::with_capacity(markdown.len() * 2);

    let mut list_stack: Vec<bool> = Vec::new();
    let mut in_code_block = false;
    let mut code_buffer = String::new();
    let mut code_lang = String::new();

    let mut in_table = false;
    let mut table_cols: usize = 0;
    let mut current_row_cells: Vec<String> = Vec::new();
    let mut table_rows: Vec<Vec<String>> = Vec::new();
    let mut in_table_cell = false;
    let mut cell_buffer = String::new();
    let mut in_blockquote = false;

    for event in parser {
        if in_code_block {
            match event {
                Event::End(TagEnd::CodeBlock) => {
                    in_code_block = false;
                    let safe_lang = sanitize_code_lang(&code_lang);
                    let escaped_code = code_buffer.replace('"', "\\\"");
                    if safe_lang.is_empty() {
                        out.push_str(&format!("#raw(\"{escaped_code}\", block: true)\n\n"));
                    } else {
                        out.push_str(&format!(
                            "#raw(\"{escaped_code}\", block: true, lang: \"{safe_lang}\")\n\n"
                        ));
                    }
                    code_buffer.clear();
                    code_lang.clear();
                }
                Event::Text(text) | Event::Code(text) => {
                    code_buffer.push_str(&text);
                }
                Event::SoftBreak | Event::HardBreak => {
                    code_buffer.push('\n');
                }
                _ => {}
            }
            continue;
        }

        let target = if in_table_cell {
            &mut cell_buffer
        } else {
            &mut out
        };

        match event {
            Event::Start(tag) => match tag {
                Tag::Heading { level, .. } => {
                    let eq_count = (level as usize).min(4);
                    target.push_str(&"=".repeat(eq_count));
                    target.push(' ');
                }
                Tag::Paragraph => {}
                Tag::BlockQuote(_) => {
                    in_blockquote = true;
                    target.push_str("#quote(block: true)[");
                }
                Tag::CodeBlock(kind) => {
                    in_code_block = true;
                    code_lang = match kind {
                        CodeBlockKind::Fenced(lang) => lang.to_string(),
                        CodeBlockKind::Indented => String::new(),
                    };
                }
                Tag::List(start) => {
                    list_stack.push(start.is_some());
                }
                Tag::Item => {
                    let indent = "  ".repeat(list_stack.len().saturating_sub(1));
                    let marker = if list_stack.last().copied().unwrap_or(false) {
                        "+ "
                    } else {
                        "- "
                    };
                    target.push_str(&indent);
                    target.push_str(marker);
                }
                Tag::Emphasis => target.push_str("#emph["),
                Tag::Strong => target.push_str("#strong["),
                Tag::Strikethrough => target.push_str("#strike["),
                Tag::Link { dest_url, .. } => {
                    if let Some(slug) = dest_url.strip_prefix('#')
                        && is_valid_anchor_id(slug)
                    {
                        target.push_str(&format!("#link(<{slug}>)["));
                    } else {
                        let safe_url = escape_typst_string_literal(&dest_url);
                        target.push_str(&format!("#link(\"{safe_url}\")["));
                    }
                }
                Tag::Table(alignments) => {
                    in_table = true;
                    table_cols = alignments.len().max(1);
                    table_rows.clear();
                }
                Tag::TableHead | Tag::TableRow => {
                    current_row_cells.clear();
                }
                Tag::TableCell => {
                    in_table_cell = true;
                    cell_buffer.clear();
                }
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Heading(_) => {
                    target.push_str("\n\n");
                }
                TagEnd::Paragraph => {
                    if !in_table_cell && list_stack.is_empty() && !in_blockquote {
                        target.push_str("\n\n");
                    } else if !list_stack.is_empty() {
                        target.push('\n');
                    }
                }
                TagEnd::BlockQuote(_) => {
                    in_blockquote = false;
                    target.push_str("]\n\n");
                }
                TagEnd::List(_) => {
                    list_stack.pop();
                    if list_stack.is_empty() {
                        target.push('\n');
                    }
                }
                TagEnd::Item => {
                    if !target.ends_with('\n') {
                        target.push('\n');
                    }
                }
                TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough | TagEnd::Link => {
                    target.push(']');
                }
                TagEnd::TableCell => {
                    in_table_cell = false;
                    current_row_cells.push(cell_buffer.trim().to_string());
                    cell_buffer.clear();
                }
                TagEnd::TableHead | TagEnd::TableRow => {
                    if !current_row_cells.is_empty() {
                        table_rows.push(std::mem::take(&mut current_row_cells));
                    }
                }
                TagEnd::Table => {
                    in_table = false;
                    if !table_rows.is_empty() {
                        out.push_str(&format!("#table(\n  columns: {table_cols},\n"));
                        for (row_idx, row) in table_rows.iter().enumerate() {
                            for cell in row {
                                if row_idx == 0 {
                                    out.push_str(&format!("  [*{}*],\n", cell));
                                } else {
                                    out.push_str(&format!("  [{}],\n", cell));
                                }
                            }
                        }
                        out.push_str(")\n\n");
                        table_rows.clear();
                    }
                }
                _ => {}
            },
            Event::Text(text) => {
                target.push_str(&escape_typst(&text));
            }
            Event::Code(code) => {
                let escaped = escape_typst_string_literal(&code);
                target.push_str(&format!("#raw(\"{escaped}\")"));
            }
            Event::Html(html) | Event::InlineHtml(html) => {
                if let Some(slug) = extract_anchor_id(&html) {
                    let label = match label_prefix {
                        Some(prefix) if !prefix.is_empty() => format!("{prefix}-{slug}"),
                        _ => slug,
                    };
                    emitted_labels.insert(label.clone());
                    target.push_str(&format!(" #box[]<{label}> "));
                }
            }
            Event::SoftBreak => {
                target.push(' ');
            }
            Event::HardBreak => {
                target.push_str(" \\\n");
            }
            Event::Rule => {
                if !in_table {
                    target.push_str("#line(length: 100%)\n\n");
                }
            }
            Event::TaskListMarker(checked) => {
                target.push_str(if checked { "[x] " } else { "[ ] " });
            }
            _ => {}
        }
    }

    (out, emitted_labels)
}

pub fn build_iso_document_typst(meta: &PdfDocumentMetadata, body_typst: &str) -> String {
    build_iso_document_typst_with_logo(meta, body_typst, None)
}

pub fn build_iso_document_typst_with_logo(
    meta: &PdfDocumentMetadata,
    body_typst: &str,
    logo_filename: Option<&str>,
) -> String {
    let org = escape_typst(&meta.organization_name);
    let code = escape_typst(&meta.doc_code);
    let title = escape_typst(&meta.title);
    let version = escape_typst(&meta.version);
    let status = escape_typst(&meta.status);
    let class = escape_typst(&meta.classification);
    let owner = escape_typst(&meta.owner_unit);
    let approved_by = escape_typst(&meta.approved_by);
    let approved_at = escape_typst(&meta.approved_at);
    let next_review = escape_typst(&meta.next_review_at);
    let logo_arg = match logo_filename {
        Some(name) => format!("\"{}\"", escape_typst_string_literal(name)),
        None => "none".to_string(),
    };

    format!(
        r##"#import "theme.typ": isms_document

#show: isms_document.with(
  org: [{org}],
  code: [{code}],
  title: [{title}],
  version: [{version}],
  status: [{status}],
  classification: [{class}],
  owner: [{owner}],
  approved_by: [{approved_by}],
  approved_at: [{approved_at}],
  next_review: [{next_review}],
  logo_path: {logo_arg},
)

{body_typst}
"##
    )
}

fn escape_typst_string_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sanitize_code_lang(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(24)
        .collect()
}

fn extract_anchor_id(html: &str) -> Option<String> {
    let trimmed = html.trim();
    if !trimmed.starts_with("<a ") {
        return None;
    }
    let idx = trimmed.find("id=\"")?;
    let rest = &trimmed[idx + 4..];
    let end = rest.find('"')?;
    let candidate = &rest[..end];
    if is_valid_anchor_id(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_typst_neutralizes_injection_payloads() {
        let payload = r#"#read("/etc/passwd") $x^2$ @ref [a] *b* _c_ `d` <lbl> \ ~ ="#;
        let escaped = escape_typst(payload);
        assert!(escaped.starts_with(r#"\#read(\"\/etc\/passwd\")"#));
        assert!(escaped.contains(r"\$x^2\$"));
        assert!(escaped.contains(r"\@ref"));
        assert!(escaped.contains(r"\[a\]"));
        assert!(escaped.contains(r"\*b\*"));
        assert!(escaped.contains(r"\_c\_"));
        assert!(escaped.contains(r"\`d\`"));
        assert!(escaped.contains(r"\<lbl\>"));
        assert!(escaped.contains(r"\\"));
        assert!(escaped.contains(r"\~"));
        assert!(escaped.contains(r"\="));
    }

    #[test]
    fn markdown_to_typst_converts_structure_and_valid_anchors() {
        let md = r#"
# Leitlinie

<a id="clean-desk"></a>

Ein **wichtiger** Text mit #read("/etc/passwd").

| Spalte A | Spalte B |
|---|---|
| Wert 1 | Wert 2 |

- Punkt 1
- Punkt 2
"#;
        let typst = markdown_to_typst(md);
        assert!(typst.contains("= Leitlinie"));
        assert!(typst.contains("<clean-desk>"));
        assert!(typst.contains("#strong[wichtiger]"));
        assert!(typst.contains(r##"\#read(\"\/etc\/passwd\")"##));
        assert!(typst.contains("#table("));
        assert!(typst.contains("- Punkt 1"));
    }

    #[test]
    fn iso_document_builder_escapes_metadata() {
        let meta = PdfDocumentMetadata {
            organization_name: "Muster #GmbH".to_string(),
            doc_code: "POL-001".to_string(),
            title: "Leitlinie [Test]".to_string(),
            version: "1.0".to_string(),
            status: "approved".to_string(),
            classification: "C2 Intern".to_string(),
            owner_unit: "IT".to_string(),
            approved_by: "Geschäftsführung".to_string(),
            approved_at: "2026-11-21".to_string(),
            next_review_at: "2027-11-21".to_string(),
        };
        let doc = build_iso_document_typst(&meta, "= Inhalt\n");
        assert!(doc.contains(r"Muster \#GmbH"));
        assert!(doc.contains(r"Leitlinie \[Test\]"));
        assert!(doc.contains(r#"#import "theme.typ": isms_document"#));
        assert!(DEFAULT_PDF_THEME.contains("Dokumentenlenkung gemäß ISO/IEC 27001 Kap. 7.5"));
    }
}
