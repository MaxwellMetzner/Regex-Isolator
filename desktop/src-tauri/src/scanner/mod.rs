mod engine;
mod response;
mod scan_job;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;

use self::engine::{build_replacement_preview, translate_python_replacement, RegexEngine};
use self::response::{
    build_line_mode_detail, build_line_mode_warnings, delimiter_value, derive_match_value,
    format_file_size, replacement_disabled_warning, ScanAccumulator,
};
use self::scan_job::collect_directory_files;
pub(crate) use self::scan_job::execute_scan_job;
use self::scan_job::{ensure_line_mode_supported, scan_line_reader, LineScanOptions};

const EDITOR_LOAD_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RegexFlags {
    pub ignore_case: bool,
    pub multiline: bool,
    pub dot_all: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub pattern: String,
    pub replacement: String,
    pub flags: RegexFlags,
    pub unique_only: bool,
    pub delimiter: String,
    pub output_limit: usize,
    pub source_text: Option<String>,
    pub file_path: Option<String>,
    pub directory_path: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileSource {
    pub path: String,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadSourceResponse {
    pub kind: String,
    pub text: Option<String>,
    pub file: Option<FileSource>,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecord {
    #[serde(rename = "match")]
    pub match_value: String,
    pub full_match: String,
    pub captures: Vec<String>,
    pub start: Option<usize>,
    pub end: Option<usize>,
    pub line: Option<usize>,
    pub column_start: Option<usize>,
    pub column_end: Option<usize>,
    pub preview: Option<String>,
    pub file_path: Option<String>,
    pub source: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanResponse {
    pub engine: String,
    pub engine_detail: String,
    pub source_kind: String,
    pub total_matches: usize,
    pub output: String,
    pub output_count: usize,
    pub truncated: bool,
    pub detail: String,
    pub status: String,
    pub warnings: Vec<String>,
    pub records: Vec<ScanRecord>,
    pub replacement_preview: Option<String>,
    pub replacement_warning: Option<String>,
    pub scanned_files: Option<usize>,
    pub completed_files: Option<usize>,
    pub scanned_lines: usize,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobProgress {
    pub source_kind: String,
    pub message: String,
    pub current_path: Option<String>,
    pub percent: Option<f64>,
    pub files_processed: usize,
    pub files_total: Option<usize>,
    pub lines_processed: usize,
    pub matches_found: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransformResponse {
    pub text: Option<String>,
    pub match_count: usize,
    pub written_count: usize,
    pub removed_count: usize,
    pub scanned_files: usize,
    pub scanned_lines: usize,
}

pub enum ScanJobOutcome {
    Completed(ScanResponse),
    Cancelled(ScanJobProgress),
}

pub fn load_source_file(path: &str) -> Result<LoadSourceResponse, String> {
    let file_path = Path::new(path);
    let metadata = fs::metadata(file_path).map_err(|error| error.to_string())?;
    let name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("selected file")
        .to_string();

    if metadata.len() > EDITOR_LOAD_MAX_BYTES {
        return Ok(LoadSourceResponse {
            kind: "file".to_string(),
            text: None,
            file: Some(FileSource {
                path: path.to_string(),
                name: name.clone(),
                size: metadata.len(),
            }),
            note: format!(
                "Loaded {name} in file-backed mode ({}). Press Match now to scan it line by line.",
                format_file_size(metadata.len())
            ),
        });
    }

    let text = read_text_lossy(path)?;
    Ok(LoadSourceResponse {
        kind: "text".to_string(),
        text: Some(text),
        file: None,
        note: format!(
            "Loaded {name} into editor mode ({}).",
            format_file_size(metadata.len())
        ),
    })
}

pub fn replace_source_text(request: ScanRequest) -> Result<String, String> {
    let text = request.source_text.as_deref().ok_or_else(|| {
        "Replacement copy currently works for editor-backed text only.".to_string()
    })?;

    if request.file_path.is_some() {
        return Err("Replacement copy is disabled in file-backed mode.".to_string());
    }

    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let replacement_plan = translate_python_replacement(&request.replacement);
    engine.replace_all(text, &replacement_plan.translated)
}

pub fn scan_source(request: ScanRequest) -> Result<ScanResponse, String> {
    if request.directory_path.is_some() {
        return Err("Directory scanning must run through a background scan job.".to_string());
    }

    if let Some(file_path) = request.file_path.as_deref() {
        return scan_file(file_path, &request);
    }

    scan_text(&request)
}

pub fn save_text_output(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|error| error.to_string())
}

pub fn save_jsonl_output(path: &str, records: &[ScanRecord]) -> Result<(), String> {
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    for record in records {
        let line = serde_json::to_string(record).map_err(|error| error.to_string())?;
        writeln!(file, "{line}").map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn extract_matches_text(request: ScanRequest) -> Result<TransformResponse, String> {
    let source_text = request
        .source_text
        .as_deref()
        .ok_or_else(|| "Match extraction requires editor-backed text.".to_string())?;
    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let output = collect_match_output(&engine, source_text, &request)?;
    Ok(TransformResponse {
        text: Some(output.text),
        match_count: output.match_count,
        written_count: output.written_count,
        removed_count: 0,
        scanned_files: 0,
        scanned_lines: source_text.lines().count(),
    })
}

pub fn delete_matches_text(request: ScanRequest) -> Result<TransformResponse, String> {
    let source_text = request
        .source_text
        .as_deref()
        .ok_or_else(|| "Delete matches requires editor-backed text.".to_string())?;
    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let (text, removed_count) = engine.replace_line(source_text, "")?;
    Ok(TransformResponse {
        text: Some(text),
        match_count: removed_count,
        written_count: 0,
        removed_count,
        scanned_files: 0,
        scanned_lines: source_text.lines().count(),
    })
}

pub fn save_matches_output(path: &str, request: ScanRequest) -> Result<TransformResponse, String> {
    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let mut output_file = File::create(path).map_err(|error| error.to_string())?;
    let mut writer = MatchWriter::new(&mut output_file, &request);

    if let Some(source_text) = request.source_text.as_deref() {
        write_text_matches(&engine, source_text, &request, &mut writer)?;
        return Ok(TransformResponse {
            text: None,
            match_count: writer.match_count,
            written_count: writer.written_count,
            removed_count: 0,
            scanned_files: 0,
            scanned_lines: source_text.lines().count(),
        });
    }

    ensure_line_mode_supported(&request, "save matches")?;

    if let Some(file_path) = request.file_path.as_deref() {
        let scanned_lines = write_file_matches(&engine, file_path, &request, &mut writer)?;
        return Ok(TransformResponse {
            text: None,
            match_count: writer.match_count,
            written_count: writer.written_count,
            removed_count: 0,
            scanned_files: 1,
            scanned_lines,
        });
    }

    if let Some(directory_path) = request.directory_path.as_deref() {
        let (scanned_files, scanned_lines) =
            write_directory_matches(&engine, directory_path, &request, &mut writer)?;
        return Ok(TransformResponse {
            text: None,
            match_count: writer.match_count,
            written_count: writer.written_count,
            removed_count: 0,
            scanned_files,
            scanned_lines,
        });
    }

    Err("Choose editor text, a file, or a directory before saving matches.".to_string())
}

pub fn save_cleaned_output(path: &str, request: ScanRequest) -> Result<TransformResponse, String> {
    if request.directory_path.is_some() {
        return Err(
            "Cleaned output is available for editor text and single file sources.".to_string(),
        );
    }

    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;

    if let Some(source_text) = request.source_text.as_deref() {
        let (text, removed_count) = engine.replace_line(source_text, "")?;
        fs::write(path, text).map_err(|error| error.to_string())?;
        return Ok(TransformResponse {
            text: None,
            match_count: removed_count,
            written_count: 0,
            removed_count,
            scanned_files: 0,
            scanned_lines: source_text.lines().count(),
        });
    }

    ensure_line_mode_supported(&request, "save cleaned output")?;

    let file_path = request.file_path.as_deref().ok_or_else(|| {
        "Choose editor text or a single file before saving cleaned output.".to_string()
    })?;
    let (removed_count, scanned_lines) = write_cleaned_file(&engine, file_path, path)?;
    Ok(TransformResponse {
        text: None,
        match_count: removed_count,
        written_count: 0,
        removed_count,
        scanned_files: 1,
        scanned_lines,
    })
}

fn scan_text(request: &ScanRequest) -> Result<ScanResponse, String> {
    let source_text = request.source_text.clone().unwrap_or_default();
    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let mut warnings = Vec::new();
    let mut accumulator = ScanAccumulator::new();

    engine.visit_matches(&source_text, |full_match, captures, start, end| {
        accumulator.push_text_match(request, full_match, captures, start, end);
        Ok(())
    })?;

    if accumulator.truncated {
        warnings.push(format!(
            "Output is capped at the first {} displayed matches.",
            request.output_limit
        ));
    }

    let mut detail = if accumulator.records.is_empty() {
        "No results for the current pattern.".to_string()
    } else {
        "Click a structured result row to jump back to its source span in the editor. Export JSONL preserves offsets and capture groups.".to_string()
    };

    if request.unique_only {
        detail.push_str(&format!(
            " Showing {} unique results.",
            accumulator.output_count()
        ));
    }

    let output = accumulator.output(&request.delimiter);
    let output_count = accumulator.output_count();
    let total_matches = accumulator.total_matches;
    let truncated = accumulator.truncated;
    let records = accumulator.records;
    let (replacement_preview, replacement_warning) =
        build_replacement_preview(&engine, request, &source_text)?;

    Ok(ScanResponse {
        engine: engine.label().to_string(),
        engine_detail: engine.detail(),
        source_kind: "text".to_string(),
        total_matches,
        output,
        output_count,
        truncated,
        detail,
        status: if records.is_empty() {
            "No matches found".to_string()
        } else {
            format!("Found {total_matches} matches in editor-backed text.")
        },
        warnings,
        records,
        replacement_preview,
        replacement_warning,
        scanned_files: None,
        completed_files: None,
        scanned_lines: source_text.lines().count(),
    })
}

fn scan_file(file_path: &str, request: &ScanRequest) -> Result<ScanResponse, String> {
    ensure_line_mode_supported(request, "file-backed mode")?;

    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let file = File::open(file_path).map_err(|error| error.to_string())?;
    let mut reader = std::io::BufReader::new(file);
    let mut accumulator = ScanAccumulator::new();
    let mut on_line_processed =
        |_lines_processed: usize, _processed_bytes: u64, _matches_found: usize| Ok(());
    let scan_state = scan_line_reader(
        &mut reader,
        request,
        &engine,
        &mut accumulator,
        LineScanOptions {
            file_path,
            source_kind: "file",
            cancel_flag: None::<&AtomicBool>,
        },
        &mut on_line_processed,
    )?;

    let warnings = build_line_mode_warnings(
        matches!(engine, RegexEngine::Fancy { .. }),
        request.output_limit,
        accumulator.truncated,
        "File-backed scans are line-based for speed and memory safety. Whole-file anchors and true cross-line matches still require editor mode.",
    );
    let detail = build_line_mode_detail(
        request,
        accumulator.output_count(),
        "Scanned directly from disk in line mode. Export JSONL preserves line numbers, columns, previews, and capture groups.",
    );

    let output = accumulator.output(&request.delimiter);
    let output_count = accumulator.output_count();
    let total_matches = accumulator.total_matches;
    let truncated = accumulator.truncated;
    let records = accumulator.records;
    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("selected file");

    Ok(ScanResponse {
        engine: engine.label().to_string(),
        engine_detail: engine.detail(),
        source_kind: "file".to_string(),
        total_matches,
        output,
        output_count,
        truncated,
        detail,
        status: if records.is_empty() {
            format!("Scanned {file_name} and found no matches.")
        } else {
            format!("Scanned {file_name} and found {total_matches} matches.")
        },
        warnings,
        records,
        replacement_preview: None,
        replacement_warning: replacement_disabled_warning(
            &request.replacement,
            "file-backed line mode",
        ),
        scanned_files: Some(1),
        completed_files: Some(1),
        scanned_lines: scan_state.lines_processed,
    })
}

struct MatchOutput {
    text: String,
    match_count: usize,
    written_count: usize,
}

fn collect_match_output(
    engine: &RegexEngine,
    source_text: &str,
    request: &ScanRequest,
) -> Result<MatchOutput, String> {
    let mut seen = HashSet::new();
    let mut values = Vec::new();
    let mut match_count = 0usize;

    engine.visit_matches(source_text, |full_match, captures, _start, _end| {
        match_count += 1;
        let match_value = derive_match_value(full_match, &captures);
        if request.unique_only && !seen.insert(match_value.clone()) {
            return Ok(());
        }

        values.push(match_value);
        Ok(())
    })?;

    let written_count = values.len();
    Ok(MatchOutput {
        text: values.join(delimiter_value(&request.delimiter)),
        match_count,
        written_count,
    })
}

struct MatchWriter<'a> {
    file: &'a mut File,
    delimiter: &'static str,
    seen: HashSet<String>,
    unique_only: bool,
    match_count: usize,
    written_count: usize,
}

impl<'a> MatchWriter<'a> {
    fn new(file: &'a mut File, request: &ScanRequest) -> Self {
        Self {
            file,
            delimiter: delimiter_value(&request.delimiter),
            seen: HashSet::new(),
            unique_only: request.unique_only,
            match_count: 0,
            written_count: 0,
        }
    }

    fn push(&mut self, full_match: &str, captures: Vec<String>) -> Result<(), String> {
        self.match_count += 1;
        let match_value = derive_match_value(full_match, &captures);
        if self.unique_only && !self.seen.insert(match_value.clone()) {
            return Ok(());
        }

        if self.written_count > 0 {
            self.file
                .write_all(self.delimiter.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        self.file
            .write_all(match_value.as_bytes())
            .map_err(|error| error.to_string())?;
        self.written_count += 1;
        Ok(())
    }
}

fn write_text_matches(
    engine: &RegexEngine,
    source_text: &str,
    _request: &ScanRequest,
    writer: &mut MatchWriter<'_>,
) -> Result<(), String> {
    engine.visit_matches(source_text, |full_match, captures, _start, _end| {
        writer.push(full_match, captures)
    })
}

fn write_file_matches(
    engine: &RegexEngine,
    file_path: &str,
    request: &ScanRequest,
    writer: &mut MatchWriter<'_>,
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|error| error.to_string())?;
    write_reader_matches(engine, BufReader::new(file), request, writer)
}

fn write_directory_matches(
    engine: &RegexEngine,
    directory_path: &str,
    request: &ScanRequest,
    writer: &mut MatchWriter<'_>,
) -> Result<(usize, usize), String> {
    let mut scanned_files = 0usize;
    let mut scanned_lines = 0usize;

    for path in collect_directory_files(directory_path)? {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        scanned_files += 1;
        scanned_lines += write_reader_matches(engine, BufReader::new(file), request, writer)?;
    }

    Ok((scanned_files, scanned_lines))
}

fn write_reader_matches(
    engine: &RegexEngine,
    mut reader: BufReader<File>,
    request: &ScanRequest,
    writer: &mut MatchWriter<'_>,
) -> Result<usize, String> {
    let mut buffer = Vec::new();
    let mut scanned_lines = 0usize;

    loop {
        buffer.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| error.to_string())?;
        if bytes_read == 0 {
            break;
        }

        scanned_lines += 1;
        let line = String::from_utf8_lossy(&buffer);
        write_text_matches(engine, &line, request, writer)?;
    }

    Ok(scanned_lines)
}

fn write_cleaned_file(
    engine: &RegexEngine,
    source_path: &str,
    output_path: &str,
) -> Result<(usize, usize), String> {
    let input = File::open(source_path).map_err(|error| error.to_string())?;
    let mut output = File::create(output_path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(input);
    let mut buffer = Vec::new();
    let mut removed_count = 0usize;
    let mut scanned_lines = 0usize;

    loop {
        buffer.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| error.to_string())?;
        if bytes_read == 0 {
            break;
        }

        scanned_lines += 1;
        let line = String::from_utf8_lossy(&buffer);
        let (cleaned, line_removed_count) = engine.replace_line(&line, "")?;
        removed_count += line_removed_count;
        output
            .write_all(cleaned.as_bytes())
            .map_err(|error| error.to_string())?;
    }

    Ok((removed_count, scanned_lines))
}

fn read_text_lossy(path: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
