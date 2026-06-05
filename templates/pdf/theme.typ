// Standard-PDF-Corporate-Design für ins-isms (Typst)
// Administratoren können diese Datei herunterladen, anpassen und unter
// PDF_TEMPLATE_DIR/theme.typ ablegen, damit das Design bei Updates erhalten bleibt.

#let isms_primary = rgb("#1e3a5f")
#let isms_muted = luma(90)
#let isms_border = luma(190)
#let isms_surface = rgb("#f6f8fa")

#let isms_document(
  org: "",
  code: "",
  title: "",
  version: "",
  status: "",
  classification: "",
  owner: "",
  approved_by: "",
  approved_at: "",
  next_review: "",
  logo_path: none,
  body,
) = {
  set page(
    paper: "a4",
    margin: (top: 2.5cm, bottom: 2.2cm, left: 2cm, right: 2cm),
    header: [
      #set text(size: 8.5pt, fill: isms_muted)
      #grid(
        columns: (1fr, auto),
        [#org · #code],
        [Version #version · #classification],
      )
      #line(length: 100%, stroke: 0.4pt + isms_border)
    ],
    footer: [
      #line(length: 100%, stroke: 0.4pt + isms_border)
      #set text(size: 8.5pt, fill: isms_muted)
      #grid(
        columns: (1fr, auto),
        [Gelenktes ISMS-Dokument · #code],
        [Seite #context counter(page).display("1 von 1", both: true)],
      )
    ],
  )

  set text(size: 10pt, lang: "de")
  set heading(numbering: "1.1")

  if logo_path != none {
    grid(
      columns: (1fr, auto),
      align: (left + horizon, right + horizon),
      [
        #text(size: 10pt, fill: isms_muted)[#org]
        #v(0.3em)
        #text(size: 20pt, weight: "bold", fill: isms_primary)[#title]
      ],
      image(logo_path, height: 1.8cm),
    )
  } else {
    text(size: 10pt, fill: isms_muted)[#org]
    v(0.3em)
    text(size: 20pt, weight: "bold", fill: isms_primary)[#title]
  }

  v(0.2em)
  text(size: 11pt, fill: luma(80))[Dokumentenlenkung gemäß ISO/IEC 27001 Kap. 7.5]
  v(1.2em)

  table(
    columns: (38%, 62%),
    stroke: 0.5pt + isms_border,
    fill: (col, _) => if col == 0 { isms_surface } else { none },
    inset: 7pt,
    [*Dokument-ID*], [#code],
    [*Version*], [#version],
    [*Status*], [#status],
    [*Klassifizierung*], [#classification],
    [*Verantwortliche Einheit*], [#owner],
    [*Freigegeben durch*], [#approved_by],
    [*Freigabedatum*], [#approved_at],
    [*Nächste Prüfung*], [#next_review],
  )

  pagebreak()

  body
}
