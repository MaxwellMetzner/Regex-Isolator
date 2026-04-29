import type { PatternAnalysis } from "../lib/patternAnalysis";

interface PatternDockProps {
  modeLabel: string;
  pattern: string;
  isBusy: boolean;
  patternAnalysis: PatternAnalysis;
  onPatternChange: (value: string) => void;
  onRunScan: () => void;
  onRestore: () => void;
}

export function PatternDock({
  modeLabel,
  pattern,
  isBusy,
  patternAnalysis,
  onPatternChange,
  onRunScan,
  onRestore,
}: PatternDockProps) {
  return (
    <section className="pattern-dock" aria-label="Minimized pattern studio">
      <span className="status-badge">{modeLabel}</span>
      <input value={pattern} onChange={(event) => onPatternChange(event.target.value)} placeholder="Enter a regex pattern" />
      <span className={`coach-dot coach-dot-${patternAnalysis.tone}`} title={patternAnalysis.hints.join(" ")} />
      <button className="primary-button" onClick={onRunScan} disabled={isBusy}>
        {isBusy ? "Scanning..." : "Match now"}
      </button>
      <button className="ghost-button" onClick={onRestore}>
        Expand studio
      </button>
    </section>
  );
}
