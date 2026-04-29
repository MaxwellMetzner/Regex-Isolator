import type { Delimiter } from "../types";
import type { PatternAnalysis } from "../lib/patternAnalysis";

interface PatternStudioPanelProps {
  modeLabel: string;
  hasBackgroundSource: boolean;
  patternAnalysis: PatternAnalysis;
  liveMatching: boolean;
  pattern: string;
  replacement: string;
  ignoreCase: boolean;
  multiline: boolean;
  dotAll: boolean;
  uniqueOnly: boolean;
  delimiter: Delimiter;
  isBusy: boolean;
  activeJobId: string | null;
  onPatternChange: (value: string) => void;
  onReplacementChange: (value: string) => void;
  onLiveMatchingChange: (value: boolean) => void;
  onIgnoreCaseChange: (value: boolean) => void;
  onMultilineChange: (value: boolean) => void;
  onDotAllChange: (value: boolean) => void;
  onUniqueOnlyChange: (value: boolean) => void;
  onDelimiterChange: (value: Delimiter) => void;
  onRunScan: () => void;
  onCancelScan: () => void;
  onCopyReplacement: () => void;
  onMinimize: () => void;
}

export function PatternStudioPanel({
  modeLabel,
  hasBackgroundSource,
  patternAnalysis,
  liveMatching,
  pattern,
  replacement,
  ignoreCase,
  multiline,
  dotAll,
  uniqueOnly,
  delimiter,
  isBusy,
  activeJobId,
  onPatternChange,
  onReplacementChange,
  onLiveMatchingChange,
  onIgnoreCaseChange,
  onMultilineChange,
  onDotAllChange,
  onUniqueOnlyChange,
  onDelimiterChange,
  onRunScan,
  onCancelScan,
  onCopyReplacement,
  onMinimize,
}: PatternStudioPanelProps) {
  return (
    <article className="panel panel-elevated">
      <div className="panel-heading">
        <div>
          <p className="panel-label">Pattern Studio</p>
          <h2>Pattern, replacement, and scan options</h2>
        </div>
        <span className={`mode-pill ${hasBackgroundSource ? "mode-pill-warning" : liveMatching ? "mode-pill-live" : "mode-pill-manual"}`}>
          {modeLabel}
        </span>
      </div>

      <label className="field">
        <span>Pattern</span>
        <input value={pattern} onChange={(event) => onPatternChange(event.target.value)} placeholder="Enter a regex pattern" />
      </label>

      <label className="field">
        <span>Replacement</span>
        <input value={replacement} onChange={(event) => onReplacementChange(event.target.value)} placeholder="Optional replacement" />
      </label>

      <div className={`pattern-coach pattern-coach-${patternAnalysis.tone}`}>
        <strong>{patternAnalysis.captureSummary}</strong>
        <span>{patternAnalysis.flagSummary}</span>
        <p>{patternAnalysis.hints.slice(0, 2).join(" ")}</p>
      </div>

      <div className="flag-row">
        <label><input type="checkbox" checked={liveMatching} disabled={hasBackgroundSource} onChange={(event) => onLiveMatchingChange(event.target.checked)} /> Live matching</label>
        <label><input type="checkbox" checked={ignoreCase} onChange={(event) => onIgnoreCaseChange(event.target.checked)} /> Ignore case</label>
        <label><input type="checkbox" checked={multiline} onChange={(event) => onMultilineChange(event.target.checked)} /> Multiline</label>
        <label><input type="checkbox" checked={dotAll} onChange={(event) => onDotAllChange(event.target.checked)} /> Dot all</label>
        <label><input type="checkbox" checked={uniqueOnly} onChange={(event) => onUniqueOnlyChange(event.target.checked)} /> Unique only</label>
      </div>

      <div className="toolbar-row">
        <label className="field compact-field">
          <span>Delimiter</span>
          <select value={delimiter} onChange={(event) => onDelimiterChange(event.target.value as Delimiter)}>
            <option>Newline</option>
            <option>Comma</option>
            <option>Tab</option>
            <option>Space</option>
          </select>
        </label>
        <button className="primary-button" onClick={onRunScan} disabled={isBusy}>
          {isBusy ? "Scanning..." : "Match now"}
        </button>
        {activeJobId ? (
          <button className="ghost-button" onClick={onCancelScan}>
            Cancel scan
          </button>
        ) : null}
        <button className="ghost-button" onClick={onCopyReplacement} disabled={!replacement}>
          Copy replacement
        </button>
        <button className="ghost-button" onClick={onMinimize}>
          Minimize studio
        </button>
      </div>
    </article>
  );
}
