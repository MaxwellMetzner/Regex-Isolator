import { BUILTIN_PRESETS, DEFAULT_PRESET_PLACEHOLDER } from "../lib/presets";

interface PresetLibraryPanelProps {
  selectedPreset: string;
  presetName: string;
  customPresetNames: string[];
  onPresetChange: (value: string) => void;
  onPresetNameChange: (value: string) => void;
  onSavePreset: () => void;
  onDeletePreset: () => void;
}

export function PresetLibraryPanel({
  selectedPreset,
  presetName,
  customPresetNames,
  onPresetChange,
  onPresetNameChange,
  onSavePreset,
  onDeletePreset,
}: PresetLibraryPanelProps) {
  return (
    <article className="panel panel-soft">
      <div className="panel-heading">
        <div>
          <p className="panel-label">Preset Library</p>
          <h2>Built-ins plus saved workflows</h2>
        </div>
      </div>

      <label className="field">
        <span>Preset</span>
        <select value={selectedPreset} onChange={(event) => onPresetChange(event.target.value)}>
          <option>{DEFAULT_PRESET_PLACEHOLDER}</option>
          {BUILTIN_PRESETS.map((preset) => (
            <option key={preset.label} value={preset.label}>{preset.label}</option>
          ))}
          {customPresetNames.length > 0 ? <option disabled>Saved presets</option> : null}
          {customPresetNames.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
      </label>

      <label className="field">
        <span>Preset name</span>
        <input value={presetName} onChange={(event) => onPresetNameChange(event.target.value)} placeholder="Name this workflow" />
      </label>

      <div className="toolbar-row">
        <button className="ghost-button" onClick={onSavePreset}>Save preset</button>
        <button className="ghost-button" onClick={onDeletePreset}>Delete preset</button>
      </div>

      <div className="migration-note">
        <p>Migration note</p>
        <strong>Rust scans use a hybrid engine path.</strong>
        <span>Fast patterns stay on `regex`. Advanced constructs such as lookaround fall back to `fancy-regex` so current behavior is not dropped during the rewrite.</span>
      </div>
    </article>
  );
}