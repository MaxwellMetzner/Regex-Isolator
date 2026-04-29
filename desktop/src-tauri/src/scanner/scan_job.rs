use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use super::engine::{collect_fancy_captures, collect_fast_captures, RegexEngine};
use super::response::{
    build_line_mode_detail, build_line_mode_warnings, replacement_disabled_warning,
    LineRecordContext, ScanAccumulator,
};
use super::{ScanJobOutcome, ScanJobProgress, ScanRequest, ScanResponse};

#[derive(Default)]
pub(crate) struct FileScanState {
    pub(crate) lines_processed: usize,
    pub(crate) processed_bytes: u64,
    pub(crate) canceled: bool,
}

pub(crate) struct LineScanOptions<'a> {
    pub(crate) file_path: &'a str,
    pub(crate) source_kind: &'a str,
    pub(crate) cancel_flag: Option<&'a AtomicBool>,
}

pub(crate) fn execute_scan_job<F>(
    request: ScanRequest,
    mut on_progress: F,
    cancel_flag: &AtomicBool,
) -> Result<ScanJobOutcome, String>
where
    F: FnMut(ScanJobProgress),
{
    if let Some(directory_path) = request.directory_path.as_deref() {
        return scan_directory_job(directory_path, &request, &mut on_progress, cancel_flag);
    }

    if let Some(file_path) = request.file_path.as_deref() {
        return scan_file_job(file_path, &request, &mut on_progress, cancel_flag);
    }

    Ok(ScanJobOutcome::Completed(super::scan_text(&request)?))
}

fn scan_file_job<F>(
    file_path: &str,
    request: &ScanRequest,
    on_progress: &mut F,
    cancel_flag: &AtomicBool,
) -> Result<ScanJobOutcome, String>
where
    F: FnMut(ScanJobProgress),
{
    ensure_line_mode_supported(request, "file-backed mode")?;

    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let metadata = fs::metadata(file_path).map_err(|error| error.to_string())?;
    let file = File::open(file_path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    let mut accumulator = ScanAccumulator::new();
    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("selected file")
        .to_string();

    on_progress(ScanJobProgress {
        source_kind: "file".to_string(),
        message: format!("Scanning {file_name}..."),
        current_path: Some(file_path.to_string()),
        percent: Some(0.0),
        files_processed: 0,
        files_total: Some(1),
        lines_processed: 0,
        matches_found: 0,
    });

    let mut on_line_processed =
        |lines_processed: usize, processed_bytes: u64, matches_found: usize| {
            if lines_processed == 1 || lines_processed % 2500 == 0 {
                on_progress(ScanJobProgress {
                    source_kind: "file".to_string(),
                    message: format!("Scanning {file_name}... {lines_processed} lines checked"),
                    current_path: Some(file_path.to_string()),
                    percent: Some(progress_percent(processed_bytes, metadata.len())),
                    files_processed: 0,
                    files_total: Some(1),
                    lines_processed,
                    matches_found,
                });
            }

            Ok(())
        };

    let scan_state = scan_line_reader(
        &mut reader,
        request,
        &engine,
        &mut accumulator,
        LineScanOptions {
            file_path,
            source_kind: "file",
            cancel_flag: Some(cancel_flag),
        },
        &mut on_line_processed,
    )?;

    if scan_state.canceled {
        return Ok(ScanJobOutcome::Cancelled(ScanJobProgress {
            source_kind: "file".to_string(),
            message: format!("Canceled scan for {file_name}."),
            current_path: Some(file_path.to_string()),
            percent: Some(progress_percent(scan_state.processed_bytes, metadata.len())),
            files_processed: 0,
            files_total: Some(1),
            lines_processed: scan_state.lines_processed,
            matches_found: accumulator.total_matches,
        }));
    }

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

    Ok(ScanJobOutcome::Completed(ScanResponse {
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
    }))
}

fn scan_directory_job<F>(
    directory_path: &str,
    request: &ScanRequest,
    on_progress: &mut F,
    cancel_flag: &AtomicBool,
) -> Result<ScanJobOutcome, String>
where
    F: FnMut(ScanJobProgress),
{
    ensure_line_mode_supported(request, "directory mode")?;

    on_progress(ScanJobProgress {
        source_kind: "directory".to_string(),
        message: "Discovering files in the selected directory...".to_string(),
        current_path: Some(directory_path.to_string()),
        percent: None,
        files_processed: 0,
        files_total: None,
        lines_processed: 0,
        matches_found: 0,
    });

    let files = collect_directory_files(directory_path)?;
    let total_files = files.len();
    let engine = RegexEngine::compile(&request.pattern, &request.flags)?;
    let mut lines_processed = 0usize;
    let mut files_processed = 0usize;
    let mut accumulator = ScanAccumulator::new();

    for path in files {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(ScanJobOutcome::Cancelled(ScanJobProgress {
                source_kind: "directory".to_string(),
                message: "Canceled directory scan.".to_string(),
                current_path: Some(directory_path.to_string()),
                percent: Some(progress_percent(files_processed as u64, total_files as u64)),
                files_processed,
                files_total: Some(total_files),
                lines_processed,
                matches_found: accumulator.total_matches,
            }));
        }

        let scan_state =
            scan_directory_file(&engine, &path, request, cancel_flag, &mut accumulator)?;
        lines_processed += scan_state.lines_processed;
        if scan_state.canceled {
            return Ok(ScanJobOutcome::Cancelled(ScanJobProgress {
                source_kind: "directory".to_string(),
                message: "Canceled directory scan.".to_string(),
                current_path: Some(path.to_string_lossy().into_owned()),
                percent: Some(progress_percent(files_processed as u64, total_files as u64)),
                files_processed,
                files_total: Some(total_files),
                lines_processed,
                matches_found: accumulator.total_matches,
            }));
        }

        files_processed += 1;
        on_progress(ScanJobProgress {
            source_kind: "directory".to_string(),
            message: format!(
                "Scanning directory... {files_processed} of {total_files} files complete"
            ),
            current_path: Some(path.to_string_lossy().into_owned()),
            percent: Some(progress_percent(files_processed as u64, total_files as u64)),
            files_processed,
            files_total: Some(total_files),
            lines_processed,
            matches_found: accumulator.total_matches,
        });
    }

    let directory_name = Path::new(directory_path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(directory_path)
        .to_string();
    let warnings = build_line_mode_warnings(
        matches!(engine, RegexEngine::Fancy { .. }),
        request.output_limit,
        accumulator.truncated,
        "Directory scans are line-based for speed and memory safety. Whole-file anchors and true cross-line matches still require editor mode.",
    );
    let detail = build_line_mode_detail(
        request,
        accumulator.output_count(),
        &format!(
            "Scanned {files_processed} files in directory mode. Export JSONL preserves file paths, line numbers, columns, previews, and capture groups."
        ),
    );
    let output = accumulator.output(&request.delimiter);
    let output_count = accumulator.output_count();
    let total_matches = accumulator.total_matches;
    let truncated = accumulator.truncated;
    let records = accumulator.records;

    Ok(ScanJobOutcome::Completed(ScanResponse {
        engine: engine.label().to_string(),
        engine_detail: engine.detail(),
        source_kind: "directory".to_string(),
        total_matches,
        output,
        output_count,
        truncated,
        detail,
        status: if records.is_empty() {
            format!("Scanned {directory_name} and found no matches.")
        } else {
            format!("Scanned {files_processed} files in {directory_name} and found {total_matches} matches.")
        },
        warnings,
        records,
        replacement_preview: None,
        replacement_warning: replacement_disabled_warning(&request.replacement, "directory mode"),
        scanned_files: Some(total_files),
        completed_files: Some(files_processed),
        scanned_lines: lines_processed,
    }))
}

fn scan_directory_file(
    engine: &RegexEngine,
    path: &Path,
    request: &ScanRequest,
    cancel_flag: &AtomicBool,
    accumulator: &mut ScanAccumulator,
) -> Result<FileScanState, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(FileScanState::default()),
    };
    let mut reader = BufReader::new(file);
    let path_string = path.to_string_lossy().into_owned();
    let mut on_line_processed =
        |_lines_processed: usize, _processed_bytes: u64, _matches_found: usize| Ok(());

    scan_line_reader(
        &mut reader,
        request,
        engine,
        accumulator,
        LineScanOptions {
            file_path: &path_string,
            source_kind: "directory",
            cancel_flag: Some(cancel_flag),
        },
        &mut on_line_processed,
    )
}

pub(crate) fn collect_directory_files(directory_path: &str) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in WalkDir::new(directory_path) {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

fn collect_line_matches(
    engine: &RegexEngine,
    line: &str,
    request: &ScanRequest,
    line_number: usize,
    file_path: Option<&str>,
    source_kind: &str,
    accumulator: &mut ScanAccumulator,
) -> Result<(), String> {
    match engine {
        RegexEngine::Fast(regex) => {
            for captures in regex.captures_iter(line) {
                let full_match = match captures.get(0) {
                    Some(value) => value,
                    None => continue,
                };
                let capture_values = collect_fast_captures(&captures);
                accumulator.push_line_match(
                    request,
                    full_match.as_str(),
                    capture_values,
                    full_match.start(),
                    full_match.end(),
                    LineRecordContext {
                        line_number,
                        line_text: line,
                        file_path,
                        source_kind,
                    },
                );
            }
        }
        RegexEngine::Fancy { regex, .. } => {
            for capture_result in regex.captures_iter(line) {
                let captures = capture_result.map_err(|error| error.to_string())?;
                let full_match = match captures.get(0) {
                    Some(value) => value,
                    None => continue,
                };
                let capture_values = collect_fancy_captures(&captures);
                accumulator.push_line_match(
                    request,
                    full_match.as_str(),
                    capture_values,
                    full_match.start(),
                    full_match.end(),
                    LineRecordContext {
                        line_number,
                        line_text: line,
                        file_path,
                        source_kind,
                    },
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn scan_line_reader<F>(
    reader: &mut BufReader<File>,
    request: &ScanRequest,
    engine: &RegexEngine,
    accumulator: &mut ScanAccumulator,
    options: LineScanOptions<'_>,
    on_line_processed: &mut F,
) -> Result<FileScanState, String>
where
    F: FnMut(usize, u64, usize) -> Result<(), String>,
{
    let mut buffer = Vec::new();
    let mut scan_state = FileScanState::default();

    loop {
        if options
            .cancel_flag
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            scan_state.canceled = true;
            return Ok(scan_state);
        }

        buffer.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| error.to_string())?;
        if bytes_read == 0 {
            break;
        }

        scan_state.lines_processed += 1;
        scan_state.processed_bytes += bytes_read as u64;

        let line = String::from_utf8_lossy(&buffer).into_owned();
        collect_line_matches(
            engine,
            &line,
            request,
            scan_state.lines_processed,
            Some(options.file_path),
            options.source_kind,
            accumulator,
        )?;
        on_line_processed(
            scan_state.lines_processed,
            scan_state.processed_bytes,
            accumulator.total_matches,
        )?;
    }

    Ok(scan_state)
}

pub(crate) fn ensure_line_mode_supported(
    request: &ScanRequest,
    mode_label: &str,
) -> Result<(), String> {
    if request.flags.dot_all || inline_dot_all_enabled(&request.pattern) {
        return Err(format!(
            "Dot All is disabled in {mode_label} because large-file scans run one line at a time. Load a smaller source into editor mode for cross-line matching."
        ));
    }

    Ok(())
}

fn inline_dot_all_enabled(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut index = 0usize;

    while index + 2 < chars.len() {
        if chars[index] != '(' || chars[index + 1] != '?' {
            index += 1;
            continue;
        }

        let mut flag_index = index + 2;
        let mut disabled_section = false;
        while flag_index < chars.len() {
            match chars[flag_index] {
                ':' | ')' => break,
                '-' => disabled_section = true,
                's' if !disabled_section => return true,
                _ => {}
            }
            flag_index += 1;
        }

        index += 2;
    }

    false
}

fn progress_percent(processed: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }

    ((processed as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
}
