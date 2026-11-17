import { useMemo, useState } from "react";
import { REGEX_HELP, type RegexHelpRow } from "../lib/regexHelp";

interface RegexHelpPanelProps {
  onInsertSnippet: (snippet: RegexHelpRow) => void;
  onClose: () => void;
}

export function RegexHelpPanel({ onInsertSnippet, onClose }: RegexHelpPanelProps) {
  const [query, setQuery] = useState("");
  const filteredSections = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    if (!normalized) {
      return REGEX_HELP;
    }

    return REGEX_HELP
      .map((section) => ({
        ...section,
        rows: section.rows.filter((row) => `${row.syntax} ${row.description}`.toLocaleLowerCase().includes(normalized)),
      }))
      .filter((section) => section.rows.length > 0);
  }, [query]);

  return (
    <section className="help-panel" aria-label="Regex expression builder">
      <div className="help-panel-header">
        <div>
          <p className="section-kicker">Expression builder</p>
          <h2>Insert regex elements</h2>
          <p>Click an element to insert it. Fill highlighted placeholders and press Tab to move to the next one.</p>
        </div>
        <button className="ghost-button compact-button" onClick={onClose} aria-label="Close reference">Close</button>
      </div>

      <label className="help-search">
        <span aria-hidden="true">⌕</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find a token or concept" />
      </label>

      {filteredSections.map((section) => (
        <article key={section.title} className="help-card">
          <h3>{section.title}</h3>
          {section.rows.map((row) => (
            row.insert ? (
              <button
                key={`${section.title}-${row.syntax}`}
                className="help-row help-row-insertable"
                onClick={() => onInsertSnippet(row)}
                title={`Insert ${row.syntax}`}
              >
                <code>{row.syntax}</code>
                <span>{row.description}</span>
                <span className="help-insert-icon" aria-hidden="true">+</span>
              </button>
            ) : (
              <div key={`${section.title}-${row.syntax}`} className="help-row">
                <code>{row.syntax}</code>
                <span>{row.description}</span>
              </div>
            )
          ))}
        </article>
      ))}
      {!filteredSections.length ? <div className="help-empty">No reference elements match “{query}”.</div> : null}
    </section>
  );
}
