# Declared inspection coverage

| Format | Inspected channels | Gaps / behavior |
|---|---|---|
| UTF-8 TXT / source text | Lines, source location, inspected filename/hash | Binary and non-UTF-8 denied |
| Static HTML | Text including hidden text; attributes/meta/link destinations; comments | Active/embedded/media/style elements explicitly partial; script-generated content and resources not fetched |
| PDF | Extractable page text, standard metadata, annotation strings | Encrypted/malformed rejected; image/XObject/active/embedded/complex-object gaps withheld; no OCR |
| DOCX | XML body, comments, metadata, headers/footers, relationship targets, selected attributes | OLE/media/drawings and non-XML parts reported withheld; layout rendering not implemented |
| XLSX | Cells incl. hidden/veryHidden worksheets, inert formula strings, workbook/sheet names/state, comments, metadata/relationships | No formula execution/calculation; objects/drawings/media withheld |
| PNG/JPEG | String metadata, textual EXIF and English pixel OCR | English Tesseract pixel text plus metadata; recognition is imperfect and QR is not enabled; no whole-image safe claim |
| ZIP | Supported child files, inspected filenames, hashes, full recursive locations and child inventories | Max 2 nested archive levels, 32 members, 2 MB expansion, 100:1 compression ratio; unsupported children withheld |
| PPTX/audio/video/legacy binary | None | Unsupported; no release |

Input is limited to 1 MB per file, 12 PDF pages, 400 extracted fragments, 40 KB text per extraction, and 8 selected evidence artifacts. Larger content is rejected, not silently truncated into a safe claim. Model context has a separate disclosure/request-size budget.

The API is the authoritative coverage manifest. `inspection_status` refers to declared channels, not absence of every prompt attack. `release_scope`, `uninspected_channels` and `safe_claim: false` are enforced in release selection.

Seven named deterministic attack categories are instruction override, role change, secret extraction, tool abuse, credential theft, encoded instruction and indirect prompt injection. Known synthetic fixtures exercise these categories. A classifier contributes semantic signals where the router requests it; classification does not authorize tool effects. Small authored fixtures do not demonstrate comprehensive unseen-family coverage or official F3/D2 certification.

Current declared profile: `atf-extract-v2` in each manifest entry. Known PDF/ZIP/PNG/JPEG magic cannot be relabelled as text or another binary format. Detector signal percentages are not safety probabilities; the investigator labels rule matches and raw uncalibrated classifier scores. Routing records selected/skipped engines, reasons and completion.
