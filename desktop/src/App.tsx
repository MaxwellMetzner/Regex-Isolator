import { startTransition, useEffect, useRef, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { PatternDock } from "./components/PatternDock";
import { PatternStudioPanel } from "./components/PatternStudioPanel";
import { PresetLibraryPanel } from "./components/PresetLibraryPanel";
import { RegexHelpPanel } from "./components/RegexHelpPanel";
import { ResultsPanel } from "./components/ResultsPanel";
import { SourcePanel } from "./components/SourcePanel";
import { analyzePattern } from "./lib/patternAnalysis";
import { BUILTIN_PRESETS, createPresetPayload, DEFAULT_PRESET_PLACEHOLDER } from "./lib/presets";
import type {
  Delimiter,
  DirectorySource,
  FileSource,
  LoadSourceResponse,
  SavedPreset,
  ScanJobEvent,
  ScanRecord,
  ScanRequest,
  ScanResponse,
  TransformResponse,
} from "./types";

const CUSTOM_PRESETS_KEY = "regex-isolator.desktop.custom-presets";
const OUTPUT_LIMIT = 5000;
const EMPTY_RESULTS_MESSAGE = "Run a pattern to isolate results.";

function loadSavedPresets() {
  try {
    const raw = window.localStorage.getItem(CUSTOM_PRESETS_KEY);
    if (!raw) {
      return {} as Record<string, SavedPreset>;
    }

    const parsed = JSON.parse(raw) as Record<string, SavedPreset>;
    return parsed ?? {};
  } catch {
    return {} as Record<string, SavedPreset>;
  }
}

async function copyText(value: string) {
  await navigator.clipboard.writeText(value);
}

function pathLabel(path: string) {
  const segments = path.split(/[/\\]+/).filter(Boolean);
  return segments[segments.length - 1] ?? path;
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

export default function App() {
  const sourceEditorRef = useRef<HTMLTextAreaElement | null>(null);
  const activeJobIdRef = useRef<string | null>(null);
  const [pattern, setPattern] = useState("");
  const [replacement, setReplacement] = useState("");
  const [sourceText, setSourceText] = useState("");
  const [fileSource, setFileSource] = useState<FileSource | null>(null);
  const [directorySource, setDirectorySource] = useState<DirectorySource | null>(null);
  const [ignoreCase, setIgnoreCase] = useState(false);
  const [multiline, setMultiline] = useState(false);
  const [dotAll, setDotAll] = useState(false);
  const [uniqueOnly, setUniqueOnly] = useState(false);
  const [liveMatching, setLiveMatching] = useState(true);
  const [delimiter, setDelimiter] = useState<Delimiter>("Newline");
  const [customPresets, setCustomPresets] = useState<Record<string, SavedPreset>>(loadSavedPresets);
  const [selectedPreset, setSelectedPreset] = useState(DEFAULT_PRESET_PLACEHOLDER);
  const [presetName, setPresetName] = useState("");
  const [scanResponse, setScanResponse] = useState<ScanResponse | null>(null);
  const [statusMessage, setStatusMessage] = useState("Ready to scan");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobProgress, setJobProgress] = useState<ScanJobEvent | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [isPatternStudioMinimized, setIsPatternStudioMinimized] = useState(false);

  useEffect(() => {
    window.localStorage.setItem(CUSTOM_PRESETS_KEY, JSON.stringify(customPresets));
  }, [customPresets]);

  useEffect(() => {
    activeJobIdRef.current = activeJobId;
  }, [activeJobId]);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;

    void listen<ScanJobEvent>("scan-job-event", (event) => {
      const payload = event.payload;
      if (!activeJobIdRef.current || payload.jobId !== activeJobIdRef.current) {
        return;
      }

      if (payload.state === "running") {
        setJobProgress(payload);
        setStatusMessage(payload.message);
        return;
      }

      setJobProgress(payload);
      setActiveJobId(null);
      setIsBusy(false);

      if (payload.state === "completed" && payload.result) {
        startTransition(() => {
          setScanResponse(payload.result ?? null);
        });
        setErrorMessage(null);
        setStatusMessage(payload.message);
        return;
      }

      if (payload.state === "cancelled") {
        setStatusMessage(payload.message);
        return;
      }

      setScanResponse(null);
      setErrorMessage(payload.error ?? payload.message);
      setStatusMessage(payload.message);
    }).then((dispose) => {
      unlisten = dispose;
    });

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, []);

  useEffect(() => {
    if (!liveMatching || fileSource || directorySource || !pattern || !sourceText) {
      return;
    }

    const handle = window.setTimeout(() => {
      void runScan();
    }, 260);

    return () => {
      window.clearTimeout(handle);
    };
  }, [liveMatching, fileSource, directorySource, pattern, replacement, sourceText, ignoreCase, multiline, dotAll, uniqueOnly, delimiter]);

  function resetScanResults(options?: { clearError?: boolean }) {
    setScanResponse(null);
    setJobProgress(null);
    if (options?.clearError ?? true) {
      setErrorMessage(null);
    }
  }

  function resetJobState() {
    setActiveJobId(null);
    activeJobIdRef.current = null;
    setIsBusy(false);
  }

  function handleOperationError(error: unknown) {
    const message = getErrorMessage(error);
    setErrorMessage(message);
    setStatusMessage(message);
    return message;
  }

  function applyEditorSource(nextSourceText: string, note: string) {
    setFileSource(null);
    setDirectorySource(null);
    setSourceText(nextSourceText);
    resetScanResults();
    setStatusMessage(note);
  }

  function applyFileSource(nextFileSource: FileSource, note: string) {
    setFileSource(nextFileSource);
    setDirectorySource(null);
    setSourceText("");
    setLiveMatching(false);
    resetScanResults();
    setStatusMessage(note);
  }

  function applyDirectorySource(nextDirectoryPath: string) {
    setDirectorySource({
      path: nextDirectoryPath,
      name: pathLabel(nextDirectoryPath),
    });
    setFileSource(null);
    setSourceText("");
    setLiveMatching(false);
    resetScanResults();
    setStatusMessage(`Loaded ${pathLabel(nextDirectoryPath)} in recursive directory mode.`);
  }

  function buildScanRequest(): ScanRequest {
    return {
      pattern,
      replacement,
      flags: {
        ignoreCase,
        multiline,
        dotAll,
      },
      uniqueOnly,
      delimiter,
      outputLimit: OUTPUT_LIMIT,
      sourceText: fileSource || directorySource ? null : sourceText,
      filePath: fileSource?.path ?? null,
      directoryPath: directorySource?.path ?? null,
    };
  }

  async function startBackgroundScan(request: ScanRequest) {
    resetScanResults();
    setIsBusy(true);

    try {
      const jobId = await invoke<string>("start_scan_job", { request });
      setActiveJobId(jobId);
      activeJobIdRef.current = jobId;
      setStatusMessage("Background scan started.");
    } catch (error) {
      handleOperationError(error);
      setIsBusy(false);
    }
  }

  async function runScan() {
    setErrorMessage(null);

    if (!pattern) {
      setScanResponse(null);
      setStatusMessage("Enter a regex pattern to begin.");
      return;
    }

    if (!sourceText && !fileSource) {
      if (!directorySource) {
        setScanResponse(null);
        setStatusMessage("Paste text or load a file or folder.");
        return;
      }
    }

    const request = buildScanRequest();

    if (fileSource || directorySource) {
      await startBackgroundScan(request);
      return;
    }

    if (!sourceText) {
      setScanResponse(null);
      setStatusMessage("Paste text or load a file or folder.");
      return;
    }

    setIsBusy(true);
    setJobProgress(null);

    try {
      const response = await invoke<ScanResponse>("scan_source", { request });
      startTransition(() => {
        setScanResponse(response);
      });
      setStatusMessage(response.status);
    } catch (error) {
      setScanResponse(null);
      handleOperationError(error);
    } finally {
      setIsBusy(false);
    }
  }

  async function handlePickFile() {
    const path = await open({
      directory: false,
      multiple: false,
      title: "Choose a source file",
    });

    if (typeof path !== "string") {
      return;
    }

    try {
      setErrorMessage(null);
      const response = await invoke<LoadSourceResponse>("load_source_file", { path });
      setSelectedPreset(DEFAULT_PRESET_PLACEHOLDER);
      if (response.kind === "text") {
        applyEditorSource(response.text ?? "", response.note);
      } else {
        applyFileSource(response.file ?? { path, name: pathLabel(path), size: 0 }, response.note);
      }
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handlePickDirectory() {
    const path = await open({
      directory: true,
      multiple: false,
      title: "Choose a folder to scan",
    });

    if (typeof path !== "string") {
      return;
    }

    applyDirectorySource(path);
  }

  async function handlePaste() {
    try {
      const pasted = await navigator.clipboard.readText();
      if (!pasted) {
        setStatusMessage("Clipboard is empty.");
        return;
      }

      applyEditorSource(pasted, "Pasted source text from the clipboard.");
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleClearAll() {
    if (activeJobIdRef.current) {
      try {
        await invoke("cancel_scan_job", { jobId: activeJobIdRef.current });
      } catch {
        // Ignore cancel errors during teardown.
      }
    }

    setPattern("");
    setReplacement("");
    setSourceText("");
    setFileSource(null);
    setDirectorySource(null);
    setIgnoreCase(false);
    setMultiline(false);
    setDotAll(false);
    setUniqueOnly(false);
    setLiveMatching(true);
    setDelimiter("Newline");
    setSelectedPreset(DEFAULT_PRESET_PLACEHOLDER);
    setPresetName("");
    resetScanResults();
    resetJobState();
    setStatusMessage("Cleared.");
  }

  function applyPreset(payload: SavedPreset, name: string) {
    setPattern(payload.pattern);
    setReplacement(payload.replacement);
    setIgnoreCase(payload.flags.ignoreCase);
    setMultiline(payload.flags.multiline);
    setDotAll(payload.flags.dotAll);
    setUniqueOnly(payload.uniqueOnly);
    setDelimiter(payload.delimiter);
    setLiveMatching(payload.liveMatching && !fileSource && !directorySource);
    setPresetName(name);
    setSelectedPreset(name);
    setStatusMessage(`Loaded preset "${name}".`);
  }

  function handlePresetChange(value: string) {
    setSelectedPreset(value);
    const builtin = BUILTIN_PRESETS.find((preset) => preset.label === value);
    if (builtin) {
      setPattern(builtin.pattern);
      setStatusMessage(`Loaded built-in preset "${value}".`);
      return;
    }

    if (customPresets[value]) {
      applyPreset(customPresets[value], value);
    }
  }

  function handleSavePreset() {
    const name = presetName.trim();
    if (!name) {
      setStatusMessage("Enter a preset name to save.");
      return;
    }

    if (BUILTIN_PRESETS.some((preset) => preset.label === name)) {
      setStatusMessage("Choose a preset name that does not collide with a built-in preset.");
      return;
    }

    const payload = createPresetPayload({
      pattern,
      replacement,
      ignoreCase,
      multiline,
      dotAll,
      uniqueOnly,
      delimiter,
      liveMatching,
    });

    setCustomPresets((current) => ({
      ...current,
      [name]: payload,
    }));
    setSelectedPreset(name);
    setStatusMessage(`Saved preset "${name}".`);
  }

  function handleDeletePreset() {
    const name = presetName.trim() || selectedPreset;
    if (!name || !customPresets[name]) {
      setStatusMessage("Select a saved custom preset to delete.");
      return;
    }

    setCustomPresets((current) => {
      const next = { ...current };
      delete next[name];
      return next;
    });
    setPresetName("");
    setSelectedPreset(DEFAULT_PRESET_PLACEHOLDER);
    setStatusMessage(`Deleted preset "${name}".`);
  }

  async function handleCopyOutput() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before copying output.");
      return;
    }

    if (!scanResponse?.output) {
      setStatusMessage("Nothing to copy.");
      return;
    }

    try {
      await copyText(scanResponse.output);
      setStatusMessage("Copied result output to the clipboard.");
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleSaveOutput() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before saving output.");
      return;
    }

    if (!scanResponse?.output) {
      setStatusMessage("Nothing to save.");
      return;
    }

    const target = await save({
      title: "Save output",
      filters: [{ name: "Text", extensions: ["txt"] }],
      defaultPath: "regex-isolator-results.txt",
    });

    if (typeof target !== "string") {
      return;
    }

    try {
      await invoke("save_text_output", { path: target, content: scanResponse.output });
      setStatusMessage(`Saved result output to ${target}.`);
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleExportJsonl() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before exporting JSONL.");
      return;
    }

    if (!scanResponse?.records.length) {
      setStatusMessage("Nothing to export.");
      return;
    }

    const target = await save({
      title: "Export JSONL",
      filters: [{ name: "JSON Lines", extensions: ["jsonl"] }],
      defaultPath: "regex-isolator-results.jsonl",
    });

    if (typeof target !== "string") {
      return;
    }

    try {
      await invoke("save_jsonl_output", { path: target, records: scanResponse.records });
      setStatusMessage(`Exported ${scanResponse.records.length.toLocaleString()} structured rows to ${target}.`);
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleKeepMatches() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before transforming source text.");
      return;
    }

    if (!pattern || !sourceText || fileSource || directorySource) {
      setStatusMessage("Keep matches works on editor-backed text.");
      return;
    }

    try {
      const response = await invoke<TransformResponse>("extract_matches_text", { request: buildScanRequest() });
      applyEditorSource(response.text ?? "", `Kept ${response.writtenCount.toLocaleString()} match(es) in the editor.`);
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleDeleteMatches() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before transforming source text.");
      return;
    }

    if (!pattern || !sourceText || fileSource || directorySource) {
      setStatusMessage("Delete matches works on editor-backed text.");
      return;
    }

    try {
      const response = await invoke<TransformResponse>("delete_matches_text", { request: buildScanRequest() });
      applyEditorSource(response.text ?? "", `Deleted ${response.removedCount.toLocaleString()} match(es) from the editor.`);
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleSaveAllMatches() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before saving all matches.");
      return;
    }

    if (!pattern || (!sourceText && !fileSource && !directorySource)) {
      setStatusMessage("Choose a pattern and source before saving matches.");
      return;
    }

    const target = await save({
      title: "Save all regex matches",
      filters: [{ name: "Text", extensions: ["txt"] }],
      defaultPath: "regex-isolator-all-matches.txt",
    });

    if (typeof target !== "string") {
      return;
    }

    try {
      setIsBusy(true);
      setStatusMessage("Saving all matches...");
      const response = await invoke<TransformResponse>("save_matches_output", { path: target, request: buildScanRequest() });
      setStatusMessage(`Saved ${response.writtenCount.toLocaleString()} match(es) to ${target}.`);
    } catch (error) {
      handleOperationError(error);
    } finally {
      setIsBusy(false);
    }
  }

  async function handleSaveCleanedOutput() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before saving cleaned output.");
      return;
    }

    if (directorySource) {
      setStatusMessage("Save cleaned output works with editor text or a single file source.");
      return;
    }

    if (!pattern || (!sourceText && !fileSource)) {
      setStatusMessage("Choose a pattern and editor/file source before saving cleaned output.");
      return;
    }

    const target = await save({
      title: "Save cleaned source",
      filters: [{ name: "Text", extensions: ["txt"] }],
      defaultPath: "regex-isolator-cleaned.txt",
    });

    if (typeof target !== "string") {
      return;
    }

    try {
      setIsBusy(true);
      setStatusMessage("Saving cleaned output...");
      const response = await invoke<TransformResponse>("save_cleaned_output", { path: target, request: buildScanRequest() });
      setStatusMessage(`Saved cleaned output to ${target} after removing ${response.removedCount.toLocaleString()} match(es).`);
    } catch (error) {
      handleOperationError(error);
    } finally {
      setIsBusy(false);
    }
  }

  async function handleCopyReplacement() {
    if (activeJobId) {
      setStatusMessage("Wait for the current background scan to finish before copying a replacement result.");
      return;
    }

    if (!pattern || !replacement || !sourceText || fileSource || directorySource) {
      setStatusMessage("Replacement copy currently works for editor-backed text only.");
      return;
    }

    try {
      const replaced = await invoke<string>("replace_source_text", {
        request: {
          pattern,
          replacement,
          flags: {
            ignoreCase,
            multiline,
            dotAll,
          },
          uniqueOnly,
          delimiter,
          outputLimit: OUTPUT_LIMIT,
          sourceText,
          filePath: null,
          directoryPath: null,
        } satisfies ScanRequest,
      });
      await copyText(replaced);
      setStatusMessage("Copied replacement output to the clipboard.");
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleCancelScan() {
    if (!activeJobIdRef.current) {
      return;
    }

    try {
      await invoke("cancel_scan_job", { jobId: activeJobIdRef.current });
      setStatusMessage("Cancel requested. Finishing the current scan chunk before stopping.");
    } catch (error) {
      handleOperationError(error);
    }
  }

  function jumpToRecord(record: ScanRecord) {
    if (!sourceEditorRef.current || typeof record.start !== "number" || typeof record.end !== "number") {
      return;
    }

    sourceEditorRef.current.focus();
    sourceEditorRef.current.setSelectionRange(record.start, record.end);
  }

  const customPresetNames = Object.keys(customPresets).sort((left, right) => left.localeCompare(right));
  const backgroundSource = directorySource ?? fileSource;
  const patternAnalysis = analyzePattern(
    pattern,
    { ignoreCase, multiline, dotAll },
    Boolean(backgroundSource),
  );
  const sourceModeLabel = directorySource
    ? `Directory source • ${directorySource.name}`
    : fileSource
      ? `File-backed source • ${fileSource.name}`
      : sourceText
        ? "Editor source"
        : "No source loaded";
  const modeLabel = directorySource ? "DIRECTORY MODE" : fileSource ? "FILE MODE" : liveMatching ? "LIVE" : "MANUAL";
  const detailText = errorMessage ?? (activeJobId && jobProgress ? jobProgress.message : scanResponse?.detail ?? EMPTY_RESULTS_MESSAGE);
  const progressPercent = Math.max(0, Math.min(100, jobProgress?.percent ?? 0));
  const engineBadge = activeJobId ? "Background scan" : scanResponse ? scanResponse.engine : "Idle";

  return (
    <div className={`app-shell ${isPatternStudioMinimized ? "studio-minimized" : ""}`}>
      <header className="app-header">
        <div>
          <p className="eyebrow">Regex Isolator Desktop</p>
          <h1>Regex Isolator</h1>
        </div>
        <div className="header-actions">
          <span className="status-badge">{engineBadge}</span>
          <button className="ghost-button" onClick={() => setShowHelp((current) => !current)}>
            {showHelp ? "Hide help" : "Regex help"}
          </button>
          <button className="primary-button" onClick={() => void handleClearAll()}>
            Clear all
          </button>
        </div>
      </header>

      {isPatternStudioMinimized ? (
        <PatternDock
          modeLabel={modeLabel}
          pattern={pattern}
          isBusy={isBusy}
          patternAnalysis={patternAnalysis}
          onPatternChange={setPattern}
          onRunScan={() => void runScan()}
          onRestore={() => setIsPatternStudioMinimized(false)}
        />
      ) : (
        <section className="control-grid">
          <PatternStudioPanel
            modeLabel={modeLabel}
            hasBackgroundSource={Boolean(backgroundSource)}
            patternAnalysis={patternAnalysis}
            liveMatching={liveMatching}
            pattern={pattern}
            replacement={replacement}
            ignoreCase={ignoreCase}
            multiline={multiline}
            dotAll={dotAll}
            uniqueOnly={uniqueOnly}
            delimiter={delimiter}
            isBusy={isBusy}
            activeJobId={activeJobId}
            onPatternChange={setPattern}
            onReplacementChange={setReplacement}
            onLiveMatchingChange={setLiveMatching}
            onIgnoreCaseChange={setIgnoreCase}
            onMultilineChange={setMultiline}
            onDotAllChange={setDotAll}
            onUniqueOnlyChange={setUniqueOnly}
            onDelimiterChange={setDelimiter}
            onRunScan={() => void runScan()}
            onCancelScan={() => void handleCancelScan()}
            onCopyReplacement={() => void handleCopyReplacement()}
            onMinimize={() => setIsPatternStudioMinimized(true)}
          />

          <PresetLibraryPanel
            selectedPreset={selectedPreset}
            presetName={presetName}
            customPresetNames={customPresetNames}
            onPresetChange={handlePresetChange}
            onPresetNameChange={setPresetName}
            onSavePreset={handleSavePreset}
            onDeletePreset={handleDeletePreset}
          />
        </section>
      )}

      <section className="workspace-grid">
        <SourcePanel
          directorySource={directorySource}
          fileSource={fileSource}
          sourceText={sourceText}
          sourceModeLabel={sourceModeLabel}
          sourceEditorRef={sourceEditorRef}
          onSourceTextChange={setSourceText}
          onPaste={() => void handlePaste()}
          onPickFile={() => void handlePickFile()}
          onPickDirectory={() => void handlePickDirectory()}
          onKeepMatches={() => void handleKeepMatches()}
          onDeleteMatches={() => void handleDeleteMatches()}
        />

        <ResultsPanel
          scanResponse={scanResponse}
          activeJobId={activeJobId}
          isBusy={isBusy}
          jobProgress={jobProgress}
          progressPercent={progressPercent}
          engineBadge={engineBadge}
          statusMessage={statusMessage}
          detailText={detailText}
          errorMessage={errorMessage}
          emptyResultsMessage={EMPTY_RESULTS_MESSAGE}
          onCopyOutput={() => void handleCopyOutput()}
          onSaveOutput={() => void handleSaveOutput()}
          onExportJsonl={() => void handleExportJsonl()}
          onSaveAllMatches={() => void handleSaveAllMatches()}
          onSaveCleanedOutput={() => void handleSaveCleanedOutput()}
          onJumpToRecord={jumpToRecord}
        />
      </section>

      {showHelp ? <RegexHelpPanel /> : null}
    </div>
  );
}
