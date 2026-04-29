use std::collections::HashSet;

use super::{ScanRecord, ScanRequest};

pub(crate) const PREVIEW_MAX_CHARS: usize = 120;

pub(crate) struct ScanAccumulator {
    pub(crate) total_matches: usize,
    pub(crate) truncated: bool,
    display_values: Vec<String>,
    pub(crate) records: Vec<ScanRecord>,
    seen: HashSet<String>,
}

pub(crate) struct LineRecordContext<'a> {
    pub(crate) line_number: usize,
    pub(crate) line_text: &'a str,
    pub(crate) file_path: Option<&'a str>,
    pub(crate) source_kind: &'a str,
}

impl ScanAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            total_matches: 0,
            truncated: false,
            display_values: Vec::new(),
            records: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn output(&self, delimiter: &str) -> String {
        self.display_values.join(delimiter_value(delimiter))
    }

    pub(crate) fn output_count(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn push_text_match(
        &mut self,
        request: &ScanRequest,
        full_match: &str,
        captures: Vec<String>,
        start: usize,
        end: usize,
    ) {
        self.push_match(request, full_match, captures, start, end, None);
    }

    pub(crate) fn push_line_match(
        &mut self,
        request: &ScanRequest,
        full_match: &str,
        captures: Vec<String>,
        start: usize,
        end: usize,
        context: LineRecordContext<'_>,
    ) {
        self.push_match(request, full_match, captures, start, end, Some(context));
    }

    fn push_match(
        &mut self,
        request: &ScanRequest,
        full_match: &str,
        captures: Vec<String>,
        start: usize,
        end: usize,
        context: Option<LineRecordContext<'_>>,
    ) {
        self.total_matches += 1;
        let match_value = derive_match_value(full_match, &captures);
        if request.unique_only && !self.seen.insert(match_value.clone()) {
            return;
        }

        if self.records.len() >= request.output_limit {
            self.truncated = true;
            return;
        }

        self.display_values.push(match_value.clone());
        self.records.push(match context {
            Some(context) => ScanRecord {
                match_value,
                full_match: full_match.to_string(),
                captures,
                start: None,
                end: None,
                line: Some(context.line_number),
                column_start: Some(start + 1),
                column_end: Some(end),
                preview: Some(build_line_preview(context.line_text)),
                file_path: context.file_path.map(ToOwned::to_owned),
                source: context.source_kind.to_string(),
            },
            None => ScanRecord {
                match_value,
                full_match: full_match.to_string(),
                captures,
                start: Some(start),
                end: Some(end),
                line: None,
                column_start: None,
                column_end: None,
                preview: None,
                file_path: None,
                source: "text".to_string(),
            },
        });
    }
}

pub(crate) fn build_line_mode_warnings(
    engine_is_fancy: bool,
    output_limit: usize,
    truncated: bool,
    base_warning: &str,
) -> Vec<String> {
    let mut warnings = vec![base_warning.to_string()];
    if engine_is_fancy {
        warnings.push(
            "This pattern required the fancy-regex fallback. It preserves more behavior, but can be slower than the fast Rust engine on very large files.".to_string(),
        );
    }
    if truncated {
        warnings.push(format!(
            "Output is capped at the first {} displayed matches.",
            output_limit
        ));
    }
    warnings
}

pub(crate) fn build_line_mode_detail(
    request: &ScanRequest,
    output_count: usize,
    base_detail: &str,
) -> String {
    let mut detail = base_detail.to_string();
    if request.unique_only {
        detail.push_str(&format!(" Showing {} unique results.", output_count));
    }
    detail
}

pub(crate) fn replacement_disabled_warning(replacement: &str, mode_label: &str) -> Option<String> {
    if replacement.trim().is_empty() {
        return None;
    }

    Some(format!("Replacement preview is disabled in {mode_label}."))
}

pub(crate) fn truncate_preview(value: &str, max_chars: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max_chars {
        return value.to_string();
    }

    chars[..max_chars.saturating_sub(3)]
        .iter()
        .collect::<String>()
        + "..."
}

pub(crate) fn format_file_size(size_bytes: u64) -> String {
    let mut size = size_bytes as f64;
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut unit_index = 0usize;

    while size >= 1024.0 && unit_index < units.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size.round() as u64, units[unit_index])
    } else {
        format!("{size:.1} {}", units[unit_index])
    }
}

pub(crate) fn derive_match_value(full_match: &str, captures: &[String]) -> String {
    if captures.is_empty() {
        return full_match.to_string();
    }

    if captures.len() == 1 {
        return captures[0].clone();
    }

    captures
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<String>()
}

pub(crate) fn delimiter_value(delimiter: &str) -> &'static str {
    match delimiter {
        "Comma" => ", ",
        "Tab" => "\t",
        "Space" => " ",
        _ => "\n",
    }
}

fn build_line_preview(line: &str) -> String {
    let preview = line.trim_end_matches(['\n', '\r']).replace('\t', "    ");
    truncate_preview(&preview, PREVIEW_MAX_CHARS)
}
