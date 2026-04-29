#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod scanner;

use scanner::{
    delete_matches_text as delete_matches_text_impl, execute_scan_job,
    extract_matches_text as extract_matches_text_impl, load_source_file as load_source_file_impl,
    replace_source_text as replace_source_text_impl,
    save_cleaned_output as save_cleaned_output_impl, save_jsonl_output as save_jsonl_output_impl,
    save_matches_output as save_matches_output_impl, save_text_output as save_text_output_impl,
    scan_source as scan_source_impl, ScanJobOutcome, ScanJobProgress, ScanRecord, ScanRequest,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::Emitter;
use uuid::Uuid;

const SCAN_JOB_EVENT: &str = "scan-job-event";

#[derive(Default, Clone)]
struct ScanJobRegistry {
    jobs: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl ScanJobRegistry {
    fn register(&self, job_id: &str) -> Arc<AtomicBool> {
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let mut jobs = self.jobs.lock().expect("scan job registry poisoned");
        jobs.insert(job_id.to_string(), cancel_flag.clone());
        cancel_flag
    }

    fn cancel(&self, job_id: &str) -> bool {
        let jobs = self.jobs.lock().expect("scan job registry poisoned");
        if let Some(cancel_flag) = jobs.get(job_id) {
            cancel_flag.store(true, Ordering::Relaxed);
            return true;
        }

        false
    }

    fn remove(&self, job_id: &str) {
        let mut jobs = self.jobs.lock().expect("scan job registry poisoned");
        jobs.remove(job_id);
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanJobEvent {
    job_id: String,
    state: String,
    source_kind: String,
    message: String,
    current_path: Option<String>,
    percent: Option<f64>,
    files_processed: usize,
    files_total: Option<usize>,
    lines_processed: usize,
    matches_found: usize,
    result: Option<scanner::ScanResponse>,
    error: Option<String>,
}

fn progress_event(job_id: &str, progress: ScanJobProgress) -> ScanJobEvent {
    ScanJobEvent {
        job_id: job_id.to_string(),
        state: "running".to_string(),
        source_kind: progress.source_kind,
        message: progress.message,
        current_path: progress.current_path,
        percent: progress.percent,
        files_processed: progress.files_processed,
        files_total: progress.files_total,
        lines_processed: progress.lines_processed,
        matches_found: progress.matches_found,
        result: None,
        error: None,
    }
}

#[tauri::command]
async fn load_source_file(path: String) -> Result<scanner::LoadSourceResponse, String> {
    tauri::async_runtime::spawn_blocking(move || load_source_file_impl(&path))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn scan_source(request: ScanRequest) -> Result<scanner::ScanResponse, String> {
    tauri::async_runtime::spawn_blocking(move || scan_source_impl(request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn replace_source_text(request: ScanRequest) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || replace_source_text_impl(request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn extract_matches_text(request: ScanRequest) -> Result<scanner::TransformResponse, String> {
    tauri::async_runtime::spawn_blocking(move || extract_matches_text_impl(request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn delete_matches_text(request: ScanRequest) -> Result<scanner::TransformResponse, String> {
    tauri::async_runtime::spawn_blocking(move || delete_matches_text_impl(request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn save_text_output(path: String, content: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || save_text_output_impl(&path, &content))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn save_jsonl_output(path: String, records: Vec<ScanRecord>) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || save_jsonl_output_impl(&path, &records))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn save_matches_output(
    path: String,
    request: ScanRequest,
) -> Result<scanner::TransformResponse, String> {
    tauri::async_runtime::spawn_blocking(move || save_matches_output_impl(&path, request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn save_cleaned_output(
    path: String,
    request: ScanRequest,
) -> Result<scanner::TransformResponse, String> {
    tauri::async_runtime::spawn_blocking(move || save_cleaned_output_impl(&path, request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn start_scan_job(
    app: tauri::AppHandle,
    registry: tauri::State<'_, ScanJobRegistry>,
    request: ScanRequest,
) -> Result<String, String> {
    if request.file_path.is_none() && request.directory_path.is_none() {
        return Err(
            "Background scan jobs currently require a file or directory source.".to_string(),
        );
    }

    let job_id = Uuid::new_v4().to_string();
    let cancel_flag = registry.register(&job_id);
    let registry_handle = ScanJobRegistry {
        jobs: registry.jobs.clone(),
    };
    let spawned_job_id = job_id.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let progress_job_id = spawned_job_id.clone();
        let progress_app = app.clone();
        let progress_callback = move |progress: ScanJobProgress| {
            let _ = progress_app.emit(SCAN_JOB_EVENT, progress_event(&progress_job_id, progress));
        };

        let outcome = execute_scan_job(request, progress_callback, cancel_flag.as_ref());
        registry_handle.remove(&spawned_job_id);

        match outcome {
            Ok(ScanJobOutcome::Completed(response)) => {
                let _ = app.emit(
                    SCAN_JOB_EVENT,
                    ScanJobEvent {
                        job_id: spawned_job_id,
                        state: "completed".to_string(),
                        source_kind: response.source_kind.clone(),
                        message: response.status.clone(),
                        current_path: None,
                        percent: Some(100.0),
                        files_processed: response.completed_files.unwrap_or(0),
                        files_total: response.scanned_files,
                        lines_processed: response.scanned_lines,
                        matches_found: response.total_matches,
                        result: Some(response),
                        error: None,
                    },
                );
            }
            Ok(ScanJobOutcome::Cancelled(cancelled)) => {
                let _ = app.emit(
                    SCAN_JOB_EVENT,
                    ScanJobEvent {
                        job_id: spawned_job_id,
                        state: "cancelled".to_string(),
                        source_kind: cancelled.source_kind,
                        message: cancelled.message,
                        current_path: cancelled.current_path,
                        percent: cancelled.percent,
                        files_processed: cancelled.files_processed,
                        files_total: cancelled.files_total,
                        lines_processed: cancelled.lines_processed,
                        matches_found: cancelled.matches_found,
                        result: None,
                        error: None,
                    },
                );
            }
            Err(error) => {
                let _ = app.emit(
                    SCAN_JOB_EVENT,
                    ScanJobEvent {
                        job_id: spawned_job_id,
                        state: "error".to_string(),
                        source_kind: "unknown".to_string(),
                        message: error.clone(),
                        current_path: None,
                        percent: None,
                        files_processed: 0,
                        files_total: None,
                        lines_processed: 0,
                        matches_found: 0,
                        result: None,
                        error: Some(error),
                    },
                );
            }
        }
    });

    Ok(job_id)
}

#[tauri::command]
fn cancel_scan_job(
    registry: tauri::State<'_, ScanJobRegistry>,
    job_id: String,
) -> Result<(), String> {
    if registry.cancel(&job_id) {
        return Ok(());
    }

    Err(format!("No active scan job found for {job_id}."))
}

fn main() {
    tauri::Builder::default()
        .manage(ScanJobRegistry::default())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            load_source_file,
            scan_source,
            replace_source_text,
            extract_matches_text,
            delete_matches_text,
            save_text_output,
            save_jsonl_output,
            save_matches_output,
            save_cleaned_output,
            start_scan_job,
            cancel_scan_job
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
