import { useDeferredValue, useMemo, useState } from "react";
import type { ScanRecord, ScanResponse } from "../types";

interface ResultsPanelProps {
  scanResponse: ScanResponse | null;
  isBusy: boolean;
  errorMessage: string | null;
  onExportTxt: () => void;
  onExportCsv: () => void;
  onExportJsonl: () => void;
  onCopyResults: (records: ScanRecord[]) => void;
  onJumpToRecord: (record: ScanRecord) => void;
}

export function ResultsPanel({
  scanResponse,
  isBusy,
  errorMessage,
  onExportTxt,
  onExportCsv,
  onExportJsonl,
  onCopyResults,
  onJumpToRecord,
}: ResultsPanelProps) {
  const [filter, setFilter] = useState("");
  const deferredFilter = useDeferredValue(filter.trim().toLocaleLowerCase());
  const displayedRecords = useMemo(() => {
    const records = scanResponse?.records ?? [];
    if (!deferredFilter) {
      return records;
    }

    return records.filter((record) => {
      const searchable = [record.match, record.fullMatch, ...record.captures, record.filePath ?? "", record.preview ?? ""];
      return searchable.some((value) => value.toLocaleLowerCase().includes(deferredFilter));
    });
  }, [deferredFilter, scanResponse]);

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
        <div className="panel-title-block">
          <span className="panel-index">02</span>
          <div>
            <p className="section-kicker">Output</p>
            <h2>{scanResponse ? `${scanResponse.totalMatches.toLocaleString()} matches` : "Results"}</h2>
            {deferredFilter && scanResponse ? <span className="panel-subtitle">{displayedRecords.length.toLocaleString()} shown</span> : null}
          </div>
        </div>
        <div className="toolbar-row results-toolbar">
          <label className="result-filter">
            <span aria-hidden="true">⌕</span>
            <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter results" aria-label="Filter results" />
          </label>
          <button className="ghost-button compact-button" onClick={() => onCopyResults(displayedRecords)} disabled={isBusy || !displayedRecords.length} title="Copy the currently visible matches.">Copy</button>
          <details className="action-menu action-menu-right">
            <summary className="primary-button compact-button">Export <span aria-hidden="true">⌄</span></summary>
            <div className="action-menu-popover">
              <p>Export displayed scan</p>
              <button onClick={onExportTxt} disabled={isBusy}>Plain text (.txt)</button>
              <button onClick={onExportCsv} disabled={isBusy}>Structured rows (.csv)</button>
              <button onClick={onExportJsonl} disabled={isBusy}>JSON Lines (.jsonl)</button>
            </div>
          </details>
        </div>
      </div>

      <div className={`output-preview-shell ${errorMessage ? "output-preview-error" : ""}`}>
        {errorMessage ? (
          <div className="output-error-row">{errorMessage}</div>
        ) : displayedRecords.length ? (
          <div className="output-match-list">
            {displayedRecords.map((record, index) => (
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
        ) : scanResponse ? (
          <div className="empty-state">
            <span>⌕</span>
            <strong>{deferredFilter ? "No results match this filter" : "No matches found"}</strong>
            <p>{deferredFilter ? "Try a broader result filter." : "Adjust the expression or source and run it again."}</p>
          </div>
        ) : (
          <div className="empty-state">
            <span>↳</span>
            <strong>Matches will appear here</strong>
            <p>Enter a pattern, add source text, then run a match.</p>
          </div>
        )}
      </div>
    </article>
  );
}
