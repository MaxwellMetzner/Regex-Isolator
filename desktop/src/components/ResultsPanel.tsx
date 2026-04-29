import type { ScanJobEvent, ScanRecord, ScanResponse } from "../types";

interface ResultsPanelProps {
  scanResponse: ScanResponse | null;
  activeJobId: string | null;
  isBusy: boolean;
  jobProgress: ScanJobEvent | null;
  progressPercent: number;
  engineBadge: string;
  statusMessage: string;
  detailText: string;
  errorMessage: string | null;
  emptyResultsMessage: string;
  onCopyOutput: () => void;
  onSaveOutput: () => void;
  onExportJsonl: () => void;
  onSaveAllMatches: () => void;
  onSaveCleanedOutput: () => void;
  onJumpToRecord: (record: ScanRecord) => void;
}

export function ResultsPanel({
  scanResponse,
  activeJobId,
  isBusy,
  jobProgress,
  progressPercent,
  engineBadge,
  statusMessage,
  detailText,
  errorMessage,
  emptyResultsMessage,
  onCopyOutput,
  onSaveOutput,
  onExportJsonl,
  onSaveAllMatches,
  onSaveCleanedOutput,
  onJumpToRecord,
}: ResultsPanelProps) {
  return (
    <article className="panel panel-soft result-panel">
      <div className="panel-heading sticky-row">
        <div>
          <p className="panel-label">Results</p>
          <h2>{scanResponse ? `${scanResponse.totalMatches.toLocaleString()} matches` : "No results yet"}</h2>
        </div>
        <div className="toolbar-row">
          <button className="ghost-button" onClick={onCopyOutput} disabled={isBusy}>Copy</button>
          <button className="ghost-button" onClick={onSaveOutput} disabled={isBusy}>Save</button>
          <button className="ghost-button" onClick={onSaveAllMatches} disabled={isBusy}>Save all matches</button>
          <button className="ghost-button" onClick={onSaveCleanedOutput} disabled={isBusy}>Save cleaned</button>
          <button className="primary-button" onClick={onExportJsonl} disabled={isBusy}>Export JSONL</button>
        </div>
      </div>

      <div className="status-strip">
        <span className="status-badge">{engineBadge}</span>
        <span>{statusMessage}</span>
      </div>

      {activeJobId && jobProgress ? (
        <div className="progress-panel">
          <div className="progress-row">
            <strong>{jobProgress.message}</strong>
            <span>{jobProgress.percent != null ? `${Math.round(progressPercent)}%` : "Working"}</span>
          </div>
          <progress className="progress-bar" max={100} value={progressPercent} />
          <div className="progress-meta">
            <span>{jobProgress.filesTotal ? `${jobProgress.filesProcessed}/${jobProgress.filesTotal} files` : `${jobProgress.linesProcessed.toLocaleString()} lines`}</span>
            <span>{jobProgress.matchesFound.toLocaleString()} matches so far</span>
          </div>
          {jobProgress.currentPath ? <p className="progress-path">{jobProgress.currentPath}</p> : null}
        </div>
      ) : null}

      {errorMessage ? <p className="error-banner">{errorMessage}</p> : null}

      {scanResponse?.warnings?.length ? (
        <div className="warning-list">
          {scanResponse.warnings.map((warning) => (
            <p key={warning}>{warning}</p>
          ))}
        </div>
      ) : null}

      <label className="field">
        <span>Output preview</span>
        <textarea className="output-editor" value={scanResponse?.output ?? ""} readOnly placeholder="Matches will appear here." />
      </label>

      <div className="detail-banner">
        <p>{detailText}</p>
        {scanResponse ? <p><strong>Engine:</strong> {scanResponse.engineDetail}</p> : null}
        {scanResponse?.scannedFiles ? <p><strong>Files scanned:</strong> {scanResponse.completedFiles ?? scanResponse.scannedFiles} / {scanResponse.scannedFiles}</p> : null}
        {scanResponse ? <p><strong>Lines scanned:</strong> {scanResponse.scannedLines.toLocaleString()}</p> : null}
        {scanResponse?.replacementPreview ? <p><strong>Replacement preview:</strong> {scanResponse.replacementPreview}</p> : null}
        {scanResponse?.replacementWarning ? <p>{scanResponse.replacementWarning}</p> : null}
      </div>

      <div className="record-list">
        {scanResponse?.records.length ? (
          scanResponse.records.map((record, index) => (
            <button
              key={`${record.match}-${index}-${record.line ?? record.start ?? 0}`}
              className="record-card"
              disabled={record.source !== "text"}
              onClick={() => onJumpToRecord(record)}
            >
              <div className="record-card-header">
                <strong>{record.match || "(empty match)"}</strong>
                <span>{record.source === "text" ? `Chars ${record.start}-${record.end}` : `Line ${record.line}`}</span>
              </div>
              <p>{record.preview ?? record.fullMatch}</p>
              {record.filePath ? <small>{record.filePath}</small> : null}
              {record.captures.length ? (
                <small>Captures: {record.captures.map((capture) => capture || "∅").join(" | ")}</small>
              ) : (
                <small>No capture groups</small>
              )}
            </button>
          ))
        ) : (
          <div className="empty-card">
            <strong>No results yet</strong>
            <p>{emptyResultsMessage}</p>
          </div>
        )}
      </div>
    </article>
  );
}
