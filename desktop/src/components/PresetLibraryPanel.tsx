import { useEffect, useRef, useState, type KeyboardEvent } from "react";

import { BUILTIN_PRESETS, DEFAULT_PRESET_PLACEHOLDER } from "../lib/presets";

interface PresetLibraryPanelProps {
  selectedPreset: string;
  presetName: string;
  customPresetNames: string[];
  onPresetChange: (value: string) => void;
  onPresetNameChange: (value: string) => void;
  onSavePreset: () => void;
  onDeletePreset: (value?: string) => void;
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
  const [isPresetMenuOpen, setIsPresetMenuOpen] = useState(false);
  const presetSelectRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!isPresetMenuOpen) {
      return;
    }

    function handleDocumentPointerDown(event: MouseEvent) {
      if (!presetSelectRef.current?.contains(event.target as Node)) {
        setIsPresetMenuOpen(false);
      }
    }

    document.addEventListener("mousedown", handleDocumentPointerDown);
    return () => document.removeEventListener("mousedown", handleDocumentPointerDown);
  }, [isPresetMenuOpen]);

  function handleMenuKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape") {
      setIsPresetMenuOpen(false);
    }
  }

  function selectPreset(value: string) {
    onPresetChange(value);
    setIsPresetMenuOpen(false);
  }

  function deletePreset(value: string) {
    onDeletePreset(value);
    setIsPresetMenuOpen(false);
  }

  return (
    <article className="panel panel-soft preset-panel">
      <div className="panel-heading">
        <div>
          <h2>Presets</h2>
        </div>
      </div>

      <div className="field">
        <span>Preset</span>
        <div className="preset-select" ref={presetSelectRef} onKeyDown={handleMenuKeyDown}>
          <button
            type="button"
            className={`preset-select-trigger ${selectedPreset === DEFAULT_PRESET_PLACEHOLDER ? "preset-select-placeholder" : ""}`}
            aria-haspopup="listbox"
            aria-expanded={isPresetMenuOpen}
            onClick={() => setIsPresetMenuOpen((current) => !current)}
          >
            <span>{selectedPreset}</span>
            <span className="preset-select-caret" aria-hidden="true">v</span>
          </button>

          {isPresetMenuOpen ? (
            <div className="preset-menu" role="listbox" aria-label="Preset choices">
              <button
                type="button"
                className="preset-menu-item preset-menu-placeholder"
                role="option"
                aria-selected={selectedPreset === DEFAULT_PRESET_PLACEHOLDER}
                onClick={() => selectPreset(DEFAULT_PRESET_PLACEHOLDER)}
              >
                {DEFAULT_PRESET_PLACEHOLDER}
              </button>

              <div className="preset-menu-label">Built-in presets</div>
              {BUILTIN_PRESETS.map((preset) => (
                <button
                  key={preset.label}
                  type="button"
                  className="preset-menu-item"
                  role="option"
                  aria-selected={selectedPreset === preset.label}
                  onClick={() => selectPreset(preset.label)}
                >
                  {preset.label}
                </button>
              ))}

              <div className="preset-menu-label preset-menu-label-saved">Saved presets</div>
              {customPresetNames.length > 0 ? (
                customPresetNames.map((name) => (
                  <div key={name} className="preset-menu-row">
                    <button
                      type="button"
                      className="preset-menu-item preset-menu-load"
                      role="option"
                      aria-selected={selectedPreset === name}
                      onClick={() => selectPreset(name)}
                    >
                      {name}
                    </button>
                    <button
                      type="button"
                      className="preset-delete-button"
                      onClick={() => deletePreset(name)}
                      title={`Delete preset "${name}"`}
                      aria-label={`Delete preset ${name}`}
                    >
                      <span aria-hidden="true">&#128465;</span>
                    </button>
                  </div>
                ))
              ) : (
                <div className="preset-menu-empty">No saved presets</div>
              )}
            </div>
          ) : null}
        </div>
      </div>

      <label className="field">
        <span>Preset name</span>
        <input value={presetName} onChange={(event) => onPresetNameChange(event.target.value)} placeholder="Name this workflow" />
      </label>

      <div className="toolbar-row">
        <button className="ghost-button" onClick={onSavePreset} title="Save the pattern, replacement, flags, delimiter, and auto-match setting.">Save preset</button>
      </div>
    </article>
  );
}
