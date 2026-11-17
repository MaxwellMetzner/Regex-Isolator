import type { KeyboardEvent, RefObject } from "react";
import type { Delimiter, PatternValidationState } from "../types";
import type { PatternAnalysis } from "../lib/patternAnalysis";

interface PatternStudioPanelProps {
  modeLabel: string;
  hasBackgroundSource: boolean;
  patternAnalysis: PatternAnalysis;
  patternValidation: PatternValidationState;
  patternInputRef: RefObject<HTMLInputElement | null>;
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
  onPatternKeyDown: (event: KeyboardEvent<HTMLInputElement>) => void;
  onPatternSelectionChange: (start: number, end: number) => void;
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
  patternValidation,
  patternInputRef,
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
  onPatternKeyDown,
  onPatternSelectionChange,
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
    <article className="panel pattern-studio-panel">
      <div className="panel-heading">
        <div>
          <p className="section-kicker">Expression</p>
          <h2>Pattern controls</h2>
        </div>
        <span
          className={`mode-pill ${hasBackgroundSource ? "mode-pill-warning" : liveMatching ? "mode-pill-live" : "mode-pill-manual"}`}
          title="Auto match runs after edits. Manual match waits for the Match now button. File sources always use manual background scans."
        >
          {modeLabel}
        </span>
      </div>

      <div className="pattern-field-grid">
        <label className="field">
          <span>Pattern</span>
          <div className={`pattern-input-shell ${patternValidation.status === "invalid" ? "pattern-input-invalid" : patternValidation.status === "valid" ? "pattern-input-valid" : ""}`}>
            <span className="pattern-slash" aria-hidden="true">/</span>
            <input
              ref={patternInputRef}
              value={pattern}
              onChange={(event) => onPatternChange(event.target.value)}
              onKeyDown={onPatternKeyDown}
              onSelect={(event) => onPatternSelectionChange(event.currentTarget.selectionStart ?? pattern.length, event.currentTarget.selectionEnd ?? pattern.length)}
              placeholder="Enter a regular expression"
              aria-invalid={patternValidation.status === "invalid"}
            />
            <span className="pattern-slash" aria-hidden="true">/</span>
          </div>
        </label>

        <label className="field">
          <span>Replacement</span>
          <input value={replacement} onChange={(event) => onReplacementChange(event.target.value)} placeholder="Optional replacement" />
        </label>
      </div>

      <div className={`pattern-coach pattern-coach-${patternAnalysis.tone}`} aria-live="polite">
        <strong>{patternAnalysis.captureSummary}</strong>
        <span>{patternAnalysis.flagSummary}</span>
        <p>{patternAnalysis.hints.slice(0, 2).join(" ")}</p>
      </div>

      <section className={`pattern-diagnostics pattern-diagnostics-${patternValidation.status}`} aria-label="Expression validation">
        <div className="pattern-diagnostics-heading">
          <span className="validation-indicator" aria-hidden="true" />
          <strong>
            {patternValidation.status === "idle" ? "Add an expression to validate it" :
              patternValidation.status === "checking" ? "Checking expression…" :
                patternValidation.valid ? `Valid · ${patternValidation.engine ?? "regex engine"}` : "Expression needs attention"}
          </strong>
        </div>
        {patternValidation.error ? <p className="validation-error">{patternValidation.error}</p> : null}
        <p><span>Likely behavior</span>{patternAnalysis.intentSummary}</p>
        {patternValidation.matchesEmpty ? <p className="validation-warning"><span>Check this</span>The expression can match empty text, which may produce surprising results.</p> : null}
        {patternAnalysis.issues.length ? (
          <ul>
            {patternAnalysis.issues.slice(0, 4).map((issue) => <li key={issue.message} className={`diagnostic-${issue.severity}`}>{issue.message}</li>)}
          </ul>
        ) : null}
      </section>

      <div className="option-strip" aria-label="Pattern options">
        <label className="option-chip" title="Run the regex automatically after editor changes. Disabled for file sources."><input type="checkbox" checked={liveMatching} disabled={hasBackgroundSource} onChange={(event) => onLiveMatchingChange(event.target.checked)} /> Live results</label>
        <label className="option-chip" title="Case-insensitive matching."><input type="checkbox" checked={ignoreCase} onChange={(event) => onIgnoreCaseChange(event.target.checked)} /> Ignore case <code>i</code></label>
        <label className="option-chip" title="Make ^ and $ match the start and end of each line."><input type="checkbox" checked={multiline} onChange={(event) => onMultilineChange(event.target.checked)} /> Multiline <code>m</code></label>
        <label className="option-chip" title="Make . match newline characters too."><input type="checkbox" checked={dotAll} onChange={(event) => onDotAllChange(event.target.checked)} /> Dot all <code>s</code></label>
        <label className="option-chip" title="Show each extracted match value only once."><input type="checkbox" checked={uniqueOnly} onChange={(event) => onUniqueOnlyChange(event.target.checked)} /> Unique</label>
      </div>

      <div className="toolbar-row scan-toolbar">
        <label className="field compact-field">
          <span>Delimiter</span>
          <select value={delimiter} onChange={(event) => onDelimiterChange(event.target.value as Delimiter)}>
            <option>Newline</option>
            <option>Comma</option>
            <option>Tab</option>
            <option>Space</option>
          </select>
        </label>
        <div className="action-field">
          <span>Actions</span>
          <div className="toolbar-row action-button-row">
            <button className="primary-button" onClick={onRunScan} disabled={isBusy || patternValidation.status === "invalid"} title={patternValidation.status === "invalid" ? "Fix the expression error before matching." : "Run the current regex against the active source immediately."}>
              {isBusy ? "Scanning..." : "Match"}
            </button>
            {activeJobId ? (
              <button className="ghost-button" onClick={onCancelScan} title="Request cancellation for the active background scan.">
                Cancel scan
              </button>
            ) : null}
            <button className="ghost-button" onClick={onCopyReplacement} disabled={!replacement} title="Copy the replacement result for editor-backed text.">
              Copy replacement
            </button>
            <button className="ghost-button" onClick={onMinimize} title="Collapse these controls so source and results get more space.">
              Done
            </button>
          </div>
        </div>
      </div>
    </article>
  );
}
