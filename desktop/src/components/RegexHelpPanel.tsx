import { REGEX_HELP } from "../lib/regexHelp";

export function RegexHelpPanel() {
  return (
    <section className="help-panel">
      {REGEX_HELP.map((section) => (
        <article key={section.title} className="help-card">
          <h3>{section.title}</h3>
          {section.rows.map(([syntax, description]) => (
            <div key={`${section.title}-${syntax}`} className="help-row">
              <code>{syntax}</code>
              <span>{description}</span>
            </div>
          ))}
        </article>
      ))}
    </section>
  );
}