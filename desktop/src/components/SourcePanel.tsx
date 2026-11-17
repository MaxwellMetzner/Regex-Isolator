import { useMemo, useRef, type ChangeEvent, type RefObject, type UIEvent } from "react";

import type { DirectorySource, FileSource } from "../types";

interface MatchRange {
  start: number;
  end: number;
}

interface SourcePanelProps {
  fileSource: FileSource | null;
  directorySource: DirectorySource | null;
  sourceText: string;
  sourceModeLabel: string;
  sourceEditorRef: RefObject<HTMLTextAreaElement | null>;
  matchRanges: MatchRange[];
  wordWrapEnabled: boolean;
  onSourceTextChange: (value: string) => void;
  onWordWrapChange: (value: boolean) => void;
  onPaste: () => void;
  onPickFile: () => void;
  onPickDirectory: () => void;
  onClearSource: () => void;
  onSaveSource: () => void;
  onSaveWithoutMatches: () => void;
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

function buildHighlightSegments(sourceText: string, matchRanges: MatchRange[]) {
  if (!sourceText) {
    return [];
  }

  const ranges = matchRanges
    .filter((range) => Number.isFinite(range.start) && Number.isFinite(range.end) && range.end > range.start)
    .map((range) => ({
      start: Math.max(0, Math.min(sourceText.length, range.start)),
      end: Math.max(0, Math.min(sourceText.length, range.end)),
    }))
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || right.end - left.end);

  const segments: Array<{ text: string; highlight: boolean }> = [];
  let cursor = 0;

  for (const range of ranges) {
    const start = Math.max(cursor, range.start);
    const end = Math.max(start, range.end);

    if (start > cursor) {
      segments.push({ text: sourceText.slice(cursor, start), highlight: false });
    }

    if (end > start) {
      segments.push({ text: sourceText.slice(start, end), highlight: true });
    }

    cursor = end;
  }

  if (cursor < sourceText.length) {
    segments.push({ text: sourceText.slice(cursor), highlight: false });
  }

  return segments.length ? segments : [{ text: sourceText, highlight: false }];
}

function segmentKey(segment: { text: string; highlight: boolean }, index: number) {
  return `${segment.highlight ? "match" : "text"}-${index}-${segment.text.length}`;
}

export function SourcePanel({
  fileSource,
  directorySource,
  sourceText,
  sourceModeLabel,
  sourceEditorRef,
  matchRanges,
  wordWrapEnabled,
  onSourceTextChange,
  onWordWrapChange,
  onPaste,
  onPickFile,
  onPickDirectory,
  onClearSource,
  onSaveSource,
  onSaveWithoutMatches,
  onKeepMatches,
  onDeleteMatches,
}: SourcePanelProps) {
  const highlightLayerRef = useRef<HTMLDivElement | null>(null);
  const highlightSegments = useMemo(() => buildHighlightSegments(sourceText, matchRanges), [matchRanges, sourceText]);

  function handleEditorChange(event: ChangeEvent<HTMLTextAreaElement>) {
    onSourceTextChange(event.currentTarget.value);
  }

  function handleEditorScroll(event: UIEvent<HTMLTextAreaElement>) {
    if (!highlightLayerRef.current) {
      return;
    }

    highlightLayerRef.current.scrollTop = event.currentTarget.scrollTop;
    highlightLayerRef.current.scrollLeft = event.currentTarget.scrollLeft;
  }

  return (
    <article className="panel panel-elevated">
      <div className="panel-heading sticky-row">
        <div className="panel-title-block">
          <span className="panel-index">01</span>
          <div>
            <p className="section-kicker">Input</p>
          <h2>{sourceModeLabel}</h2>
          </div>
        </div>
        <div className="toolbar-row source-toolbar">
          <button className="ghost-button compact-button" onClick={onPaste} title="Replace the editor source with clipboard text.">Paste</button>
          <button className="primary-button compact-button" onClick={onPickFile} title="Open a text file. Large files stay on disk and scan directly.">Open file</button>
          <details className="action-menu">
            <summary className="ghost-button compact-button">Tools <span aria-hidden="true">⌄</span></summary>
            <div className="action-menu-popover">
              <p>Editor</p>
              <button onClick={onPickDirectory}>Open folder</button>
              <button onClick={onSaveSource} disabled={Boolean(fileSource || directorySource)}>Save source</button>
              <button onClick={() => onWordWrapChange(!wordWrapEnabled)} disabled={Boolean(fileSource || directorySource)}>{wordWrapEnabled ? "Turn wrapping off" : "Turn wrapping on"}</button>
              <button onClick={onClearSource}>Clear source</button>
              <p>Transform</p>
              <button onClick={onDeleteMatches} disabled={Boolean(fileSource || directorySource)}>Delete matches</button>
              <button onClick={onKeepMatches} disabled={Boolean(fileSource || directorySource)}>Keep only matches</button>
              <button onClick={onSaveWithoutMatches} disabled={Boolean(directorySource)}>Save without matches</button>
            </div>
          </details>
        </div>
      </div>

      {directorySource ? (
        <div className="file-card">
          <div>
            <p className="panel-label">Selected folder</p>
            <h3>{directorySource.name}</h3>
          </div>
          <dl>
            <div>
              <dt>Path</dt>
              <dd>{directorySource.path}</dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>Recursive line-based scan</dd>
            </div>
          </dl>
          <p className="support-copy">Files stay on disk while the Rust backend scans the folder recursively with progress and cancellation.</p>
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
        <div className={`source-editor-shell ${wordWrapEnabled ? "word-wrap-on" : "word-wrap-off"}`}>
          <div ref={highlightLayerRef} className="source-editor-highlight-layer" aria-hidden="true">
            {highlightSegments.map((segment, index) => (
              segment.highlight ? (
                <mark key={segmentKey(segment, index)} className="source-match-highlight">{segment.text}</mark>
              ) : (
                <span key={segmentKey(segment, index)}>{segment.text}</span>
              )
            ))}
          </div>
          <textarea
            ref={sourceEditorRef}
            className="source-editor source-editor-content"
            value={sourceText}
            placeholder="Paste source text here or load a file."
            onChange={handleEditorChange}
            onScroll={handleEditorScroll}
            aria-label="Source text"
            spellCheck={false}
            wrap={wordWrapEnabled ? "soft" : "off"}
          />
        </div>
      )}
    </article>
  );
}
