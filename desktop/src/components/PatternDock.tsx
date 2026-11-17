import type { KeyboardEvent, RefObject } from "react";
import type { PatternAnalysis } from "../lib/patternAnalysis";
import type { PatternValidationState } from "../types";

interface PatternDockProps {
  modeLabel: string;
  pattern: string;
  isBusy: boolean;
  patternAnalysis: PatternAnalysis;
  patternValidation: PatternValidationState;
  patternInputRef: RefObject<HTMLInputElement | null>;
  onPatternChange: (value: string) => void;
  onPatternKeyDown: (event: KeyboardEvent<HTMLInputElement>) => void;
  onPatternSelectionChange: (start: number, end: number) => void;
  onRunScan: () => void;
  onRestore: () => void;
}

export function PatternDock({
  modeLabel,
  pattern,
  isBusy,
  patternAnalysis,
  patternValidation,
  patternInputRef,
  onPatternChange,
  onPatternKeyDown,
  onPatternSelectionChange,
  onRunScan,
  onRestore,
}: PatternDockProps) {
  return (
    <section className="pattern-dock" aria-label="Regex pattern">
      <div className="pattern-dock-label">
        <span>Expression</span>
        <span className={`coach-dot coach-dot-${patternAnalysis.tone}`} title={patternAnalysis.hints.join(" ")} />
      </div>
      <div className={`pattern-input-shell ${patternValidation.status === "invalid" ? "pattern-input-invalid" : patternValidation.status === "valid" ? "pattern-input-valid" : ""}`}>
        <span className="pattern-slash" aria-hidden="true">/</span>
        <input
          ref={patternInputRef}
          value={pattern}
          onChange={(event) => onPatternChange(event.target.value)}
          onKeyDown={onPatternKeyDown}
          onSelect={(event) => onPatternSelectionChange(event.currentTarget.selectionStart ?? pattern.length, event.currentTarget.selectionEnd ?? pattern.length)}
          placeholder="Enter a regular expression"
          aria-label="Regular expression"
          aria-invalid={patternValidation.status === "invalid"}
        />
        <span className="pattern-slash" aria-hidden="true">/</span>
      </div>
      <span className="status-badge" title="Auto match runs after edits. Manual match waits for the Match button.">{modeLabel}</span>
      <button className="ghost-button compact-button" onClick={onRestore} title="Show flags, replacement, presets, and output options.">
        Options
      </button>
      <button className="primary-button run-button" onClick={onRunScan} disabled={isBusy || patternValidation.status === "invalid"} title={patternValidation.status === "invalid" ? "Fix the expression error before matching." : "Run the current regex. Shortcut: Ctrl+Enter."}>
        <span>{isBusy ? "Scanning..." : "Match"}</span>
        {!isBusy ? <kbd>Ctrl ↵</kbd> : null}
      </button>
      {patternValidation.status === "invalid" ? (
        <p className="pattern-dock-diagnostic" role="alert">{patternValidation.error}</p>
      ) : patternValidation.matchesEmpty ? (
        <p className="pattern-dock-diagnostic pattern-dock-warning">This expression can match empty text.</p>
      ) : null}
    </section>
  );
}
