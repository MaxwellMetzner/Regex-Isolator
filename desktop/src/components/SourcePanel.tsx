import { useMemo, type FormEvent, type RefObject } from "react";

import type { FileSource } from "../types";

interface MatchRange {
  start: number;
  end: number;
}

interface SourcePanelProps {
  fileSource: FileSource | null;
  sourceText: string;
  sourceModeLabel: string;
  sourceEditorRef: RefObject<HTMLDivElement | null>;
  matchRanges: MatchRange[];
  onSourceTextChange: (value: string) => void;
  onPaste: () => void;
  onPickFile: () => void;
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

export function SourcePanel({
  fileSource,
  sourceText,
  sourceModeLabel,
  sourceEditorRef,
  matchRanges,
  onSourceTextChange,
  onPaste,
  onPickFile,
  onClearSource,
  onSaveSource,
  onSaveWithoutMatches,
  onKeepMatches,
  onDeleteMatches,
}: SourcePanelProps) {
  const highlightSegments = useMemo(() => buildHighlightSegments(sourceText, matchRanges), [matchRanges, sourceText]);

  function handleEditorInput(event: FormEvent<HTMLDivElement>) {
    onSourceTextChange(event.currentTarget.textContent ?? "");
  }

  return (
    <article className="panel panel-elevated">
      <div className="panel-heading sticky-row">
        <div>
          <p className="panel-label">Source</p>
          <h2>{sourceModeLabel}</h2>
        </div>
        <div className="toolbar-row">
          <button className="primary-button" onClick={onPaste} title="Replace the editor source with clipboard text.">Paste</button>
          <button className="ghost-button" onClick={onPickFile} title="Open a text file. Large files stay on disk and scan directly.">Load file</button>
          <button className="ghost-button" onClick={onSaveSource} disabled={Boolean(fileSource)} title="Save the editor text. Loaded editor files ask before overwriting; otherwise you can choose a new file.">Save source</button>
          <button className="ghost-button" onClick={onSaveWithoutMatches} title="Save a copy of the source with the current regex matches removed.">Save without matches</button>
          <button className="ghost-button" onClick={onClearSource} title="Clear only the source and current results. The regex pattern and options stay as they are.">Clear source</button>
          <button className="ghost-button" onClick={onKeepMatches} disabled={Boolean(fileSource)} title="Replace the editor text with only the full regex matches, joined by the selected delimiter. Capture groups do not change this action.">Keep matches</button>
          <button className="ghost-button" onClick={onDeleteMatches} disabled={Boolean(fileSource)} title="Remove the current regex matches from the editor text.">Delete matches</button>
        </div>
      </div>

      {fileSource ? (
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
        <div className="source-editor-shell">
          <div
            ref={sourceEditorRef}
            className="source-editor source-editor-content"
            contentEditable="plaintext-only"
            data-placeholder="Paste source text here or load a file."
            onInput={handleEditorInput}
            role="textbox"
            aria-multiline="true"
            spellCheck={false}
            suppressContentEditableWarning
          >{highlightSegments.map((segment, index) => (
              segment.highlight ? (
                <mark key={index} className="source-match-highlight">{segment.text}</mark>
              ) : (
                <span key={index}>{segment.text}</span>
              )
            ))}</div>
        </div>
      )}
    </article>
  );
}
