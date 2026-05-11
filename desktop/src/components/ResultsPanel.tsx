import type { ScanRecord, ScanResponse } from "../types";

interface ResultsPanelProps {
  scanResponse: ScanResponse | null;
  isBusy: boolean;
  errorMessage: string | null;
  onCopyOutput: () => void;
  onSaveOutput: () => void;
  onExportJsonl: () => void;
  onJumpToRecord: (record: ScanRecord) => void;
}

export function ResultsPanel({
  scanResponse,
  isBusy,
  errorMessage,
  onCopyOutput,
  onSaveOutput,
  onExportJsonl,
  onJumpToRecord,
}: ResultsPanelProps) {
  function jumpToRecord(record: ScanRecord) {
    if (record?.source === "text") {
      onJumpToRecord(record);
    }
  }

  return (
    <article className="panel panel-soft result-panel">
      <div className="panel-heading sticky-row">
        <div>
          <p className="panel-label">Results</p>
          <h2>{scanResponse ? `${scanResponse.totalMatches.toLocaleString()} matches` : "No results yet"}</h2>
        </div>
        <div className="toolbar-row">
          <button className="ghost-button" onClick={onCopyOutput} disabled={isBusy} title="Copy the displayed results to the clipboard.">Copy</button>
          <button className="ghost-button" onClick={onSaveOutput} disabled={isBusy} title="Save the current result matches as a text file.">Save</button>
          <button className="primary-button" onClick={onExportJsonl} disabled={isBusy} title="Export displayed structured rows as JSON Lines with offsets, paths, and capture groups.">Export JSONL</button>
        </div>
      </div>

      <div className={`output-preview-shell ${errorMessage ? "output-preview-error" : ""}`}>
        {errorMessage ? (
          <div className="output-error-row">{errorMessage}</div>
        ) : scanResponse?.records.length ? (
          <div className="output-match-list">
            {scanResponse.records.map((record, index) => (
              <div
                key={`${record.match}-${index}-${record.line ?? record.start ?? 0}`}
                className="output-match-row"
                role="button"
                tabIndex={record.source === "text" ? 0 : -1}
                onClick={() => jumpToRecord(record)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    jumpToRecord(record);
                  }
                }}
              >
                <span className="output-line-icon" aria-hidden="true">{"\u21b5"}</span>
                <span className="output-match-text">{record.match || "(empty match)"}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </article>
  );
}
