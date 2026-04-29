import type { RefObject } from "react";

import type { DirectorySource, FileSource } from "../types";

interface SourcePanelProps {
  directorySource: DirectorySource | null;
  fileSource: FileSource | null;
  sourceText: string;
  sourceModeLabel: string;
  sourceEditorRef: RefObject<HTMLTextAreaElement | null>;
  onSourceTextChange: (value: string) => void;
  onPaste: () => void;
  onPickFile: () => void;
  onPickDirectory: () => void;
  onKeepMatches: () => void;
  onDeleteMatches: () => void;
}

function formatFileSize(size: number) {
  let value = size;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  if (unitIndex === 0) {
    return `${Math.round(value)} ${units[unitIndex]}`;
  }

  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

export function SourcePanel({
  directorySource,
  fileSource,
  sourceText,
  sourceModeLabel,
  sourceEditorRef,
  onSourceTextChange,
  onPaste,
  onPickFile,
  onPickDirectory,
  onKeepMatches,
  onDeleteMatches,
}: SourcePanelProps) {
  return (
    <article className="panel panel-elevated">
      <div className="panel-heading sticky-row">
        <div>
          <p className="panel-label">Source</p>
          <h2>{sourceModeLabel}</h2>
        </div>
        <div className="toolbar-row">
          <button className="primary-button" onClick={onPaste}>Paste</button>
          <button className="ghost-button" onClick={onPickFile}>Load file</button>
          <button className="ghost-button" onClick={onPickDirectory}>Load folder</button>
          <button className="ghost-button" onClick={onKeepMatches} disabled={Boolean(fileSource || directorySource)}>Keep matches</button>
          <button className="ghost-button" onClick={onDeleteMatches} disabled={Boolean(fileSource || directorySource)}>Delete matches</button>
        </div>
      </div>

      {directorySource ? (
        <div className="file-card">
          <div>
            <p className="panel-label">Selected directory</p>
            <h3>{directorySource.name}</h3>
          </div>
          <dl>
            <div>
              <dt>Path</dt>
              <dd>{directorySource.path}</dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>Recursive line-by-line directory scan</dd>
            </div>
            <div>
              <dt>Behavior</dt>
              <dd>Background job with progress and cancelation</dd>
            </div>
          </dl>
          <p className="support-copy">Every file under the selected folder is scanned through the Rust backend. Results keep file paths, line numbers, previews, and capture groups.</p>
        </div>
      ) : fileSource ? (
        <div className="file-card">
          <div>
            <p className="panel-label">Selected large file</p>
            <h3>{fileSource.name}</h3>
          </div>
          <dl>
            <div>
              <dt>Path</dt>
              <dd>{fileSource.path}</dd>
            </div>
            <div>
              <dt>Size</dt>
              <dd>{formatFileSize(fileSource.size)}</dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>Line-based direct scan</dd>
            </div>
          </dl>
          <p className="support-copy">The file stays on disk and is scanned by the Rust backend without loading the whole thing into the editor.</p>
        </div>
      ) : (
        <textarea
          ref={sourceEditorRef}
          className="source-editor"
          value={sourceText}
          onChange={(event) => onSourceTextChange(event.target.value)}
          placeholder="Paste source text here or load a file."
        />
      )}
    </article>
  );
}
