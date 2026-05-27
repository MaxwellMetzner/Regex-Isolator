import type { ScanRecord, ScanResponse } from "../types";

interface ResultsPanelProps {
  scanResponse: ScanResponse | null;
  isBusy: boolean;
  errorMessage: string | null;
  onExportTxt: () => void;
  onExportCsv: () => void;
  onExportJsonl: () => void;
  onJumpToRecord: (record: ScanRecord) => void;
}

export function ResultsPanel({
  scanResponse,
  isBusy,
  errorMessage,
  onExportTxt,
  onExportCsv,
  onExportJsonl,
  onJumpToRecord,
}: ResultsPanelProps) {
  function jumpToRecord(record: ScanRecord) {
    if (record?.source === "text") {
      onJumpToRecord(record);
    }
  }

  function displayText(value: string) {
    return value || "(empty match)";
  }

  return (
    <article className="panel panel-soft result-panel">
      <div className="panel-heading sticky-row">
        <div>
          <h2>{scanResponse ? `${scanResponse.totalMatches.toLocaleString()} matches` : "No results yet"}</h2>
        </div>
        <div className="toolbar-row">
          <button className="primary-button" onClick={onExportTxt} disabled={isBusy} title="Export displayed result matches as a text file.">Export TXT</button>
          <button className="ghost-button" onClick={onExportCsv} disabled={isBusy} title="Export displayed structured rows as comma-separated values.">Export CSV</button>
          <button className="ghost-button" onClick={onExportJsonl} disabled={isBusy} title="Export displayed structured rows as JSON Lines with offsets, paths, and capture groups.">Export JSONL</button>
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
                <div className="output-match-body">
                  <div className="output-match-text">{displayText(record.match)}</div>
                  {record.captures.length > 0 ? (
                    <div className="output-capture-detail">
                      <span className="output-full-match">Full: {displayText(record.fullMatch)}</span>
                      <div className="output-capture-list" aria-label="Capture groups">
                        {record.captures.map((capture, captureIndex) => (
                          <span key={`${index}-${captureIndex}-${capture}`} className="output-capture-chip">
                            <strong>${captureIndex + 1}</strong>
                            <span>{displayText(capture)}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </article>
  );
}
