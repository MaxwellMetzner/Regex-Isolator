import { startTransition, useEffect, useRef, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { downloadDir, join } from "@tauri-apps/api/path";
import { PatternDock } from "./components/PatternDock";
import { PatternStudioPanel } from "./components/PatternStudioPanel";
import { PresetLibraryPanel } from "./components/PresetLibraryPanel";
import { RegexHelpPanel } from "./components/RegexHelpPanel";
import { ResultsPanel } from "./components/ResultsPanel";
import { SourcePanel } from "./components/SourcePanel";
import { analyzePattern } from "./lib/patternAnalysis";
import { BUILTIN_PRESETS, createPresetPayload, DEFAULT_PRESET_PLACEHOLDER } from "./lib/presets";
import {
  deleteBrowserMatches,
  extractBrowserFullMatches,
  replaceBrowserSource,
  scanBrowserSource,
} from "./lib/webRegex";
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
const IS_TAURI_RUNTIME = typeof window !== "undefined" && Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);

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

async function defaultDownloadPath(fileName: string) {
  if (!IS_TAURI_RUNTIME) {
    return fileName;
  }

  try {
    return await join(await downloadDir(), fileName);
  } catch {
    return fileName;
  }
}

function downloadTextFile(fileName: string, content: string, type = "text/plain;charset=utf-8") {
  const url = window.URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  window.setTimeout(() => window.URL.revokeObjectURL(url), 0);
}

function pickBrowserTextFile() {
  return new Promise<{ name: string; text: string; size: number } | null>((resolve, reject) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "text/*,.txt,.csv,.json,.jsonl,.log,.md,.html,.xml,.yaml,.yml";

    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) {
        resolve(null);
        return;
      }

      file.text()
        .then((text) => resolve({ name: file.name, text, size: file.size }))
        .catch(reject);
    };

    input.click();
  });
}

function pathLabel(path: string) {
  const segments = path.split(/[/\\]+/).filter(Boolean);
  return segments[segments.length - 1] ?? path;
}

function getErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

interface EditorSourceFile {
  path?: string;
  name: string;
}

function textPointAtOffset(root: HTMLElement, targetOffset: number) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let currentOffset = 0;
  let node = walker.nextNode();

  while (node) {
    const textLength = node.textContent?.length ?? 0;
    if (currentOffset + textLength >= targetOffset) {
      return {
        node,
        offset: Math.max(0, Math.min(textLength, targetOffset - currentOffset)),
      };
    }

    currentOffset += textLength;
    node = walker.nextNode();
  }

  return {
    node: root,
    offset: root.childNodes.length,
  };
}

function selectEditableRange(root: HTMLElement, start: number, end: number) {
  const range = document.createRange();
  const startPoint = textPointAtOffset(root, start);
  const endPoint = textPointAtOffset(root, end);
  range.setStart(startPoint.node, startPoint.offset);
  range.setEnd(endPoint.node, endPoint.offset);

  const selection = window.getSelection();
  selection?.removeAllRanges();
  selection?.addRange(range);
  root.focus();

  const rangeRect = range.getBoundingClientRect();
  const rootRect = root.getBoundingClientRect();
  if (rangeRect.height > 0) {
    root.scrollTop += rangeRect.top - rootRect.top - root.clientHeight / 2 + rangeRect.height / 2;
    root.scrollLeft += rangeRect.left - rootRect.left - 20;
  }
}

export default function App() {
  const sourceEditorRef = useRef<HTMLDivElement | null>(null);
  const activeJobIdRef = useRef<string | null>(null);
  const [pattern, setPattern] = useState("");
  const [replacement, setReplacement] = useState("");
  const [sourceText, setSourceText] = useState("");
  const [editorSourceFile, setEditorSourceFile] = useState<EditorSourceFile | null>(null);
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
  const [statusMessage, setStatusMessage] = useState("");
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
    if (!IS_TAURI_RUNTIME) {
      return;
    }

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

  function applyEditorSource(nextSourceText: string, note: string, sourceFile: EditorSourceFile | null = null) {
    setFileSource(null);
    setDirectorySource(null);
    setEditorSourceFile(sourceFile);
    setSourceText(nextSourceText);
    resetScanResults();
    setStatusMessage(note);
  }

  function handleSourceTextChange(nextSourceText: string) {
    setSourceText(nextSourceText);
    if (scanResponse) {
      resetScanResults();
    }
  }

  function applyFileSource(nextFileSource: FileSource, note: string) {
    setFileSource(nextFileSource);
    setDirectorySource(null);
    setEditorSourceFile(null);
    setSourceText("");
    setLiveMatching(false);
    resetScanResults();
    setStatusMessage(note);
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

    if (!IS_TAURI_RUNTIME) {
      setIsBusy(false);
      setStatusMessage("Folder and background scans are not available in the browser view.");
      return;
    }

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
        setStatusMessage("Paste text or load a file.");
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
      setStatusMessage("Paste text or load a file.");
      return;
    }

    setIsBusy(true);
    setJobProgress(null);

    try {
      const response = IS_TAURI_RUNTIME
        ? await invoke<ScanResponse>("scan_source", { request })
        : scanBrowserSource(request);
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
    if (!IS_TAURI_RUNTIME) {
      try {
        const loaded = await pickBrowserTextFile();
        if (!loaded) {
          return;
        }

        setSelectedPreset(DEFAULT_PRESET_PLACEHOLDER);
        applyEditorSource(loaded.text, `Loaded ${loaded.name} into the browser editor.`, { name: loaded.name });
      } catch (error) {
        handleOperationError(error);
      }
      return;
    }

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
        applyEditorSource(response.text ?? "", response.note, { path, name: pathLabel(path) });
      } else {
        applyFileSource(response.file ?? { path, name: pathLabel(path), size: 0 }, response.note);
      }
    } catch (error) {
      handleOperationError(error);
    }
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

  async function handleClearSource() {
    if (activeJobIdRef.current) {
      try {
        if (IS_TAURI_RUNTIME) {
          await invoke("cancel_scan_job", { jobId: activeJobIdRef.current });
        }
      } catch {
        // Ignore cancel errors during teardown.
      }
    }

    setSourceText("");
    setEditorSourceFile(null);
    setFileSource(null);
    setDirectorySource(null);
    resetScanResults();
    resetJobState();
    setStatusMessage("Source cleared.");
  }

  async function handleSaveSource() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before saving source text.");
      return;
    }

    if (!sourceText || fileSource || directorySource) {
      setStatusMessage("There is no editor source text to save.");
      return;
    }

    if (!IS_TAURI_RUNTIME) {
      downloadTextFile(editorSourceFile?.name ?? "regex-isolator-source.txt", sourceText);
      setStatusMessage("Downloaded source text.");
      return;
    }

    let target = editorSourceFile?.path ?? null;
    if (target) {
      const overwrite = window.confirm(`Overwrite the loaded file?\n\n${target}\n\nChoose Cancel to save as a new file instead.`);
      if (!overwrite) {
        target = null;
      }
    }

    if (!target) {
      const picked = await save({
        title: "Save source text",
        filters: [{ name: "Text", extensions: ["txt"] }],
        defaultPath: await defaultDownloadPath(editorSourceFile?.name ?? "regex-isolator-source.txt"),
      });

      if (typeof picked !== "string") {
        return;
      }

      target = picked;
    }

    try {
      await invoke("save_text_output", { path: target, content: sourceText });
      setEditorSourceFile({ path: target, name: pathLabel(target) });
      setStatusMessage(`Saved source text to ${target}.`);
    } catch (error) {
      handleOperationError(error);
    }
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

    if (!IS_TAURI_RUNTIME) {
      downloadTextFile("regex-isolator-results.txt", scanResponse.output);
      setStatusMessage("Downloaded result output.");
      return;
    }

    const target = await save({
      title: "Save output",
      filters: [{ name: "Text", extensions: ["txt"] }],
      defaultPath: await defaultDownloadPath("regex-isolator-results.txt"),
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

    if (!IS_TAURI_RUNTIME) {
      const jsonl = scanResponse.records.map((record) => JSON.stringify(record)).join("\n");
      downloadTextFile("regex-isolator-results.jsonl", jsonl ? `${jsonl}\n` : "", "application/x-ndjson;charset=utf-8");
      setStatusMessage(`Downloaded ${scanResponse.records.length.toLocaleString()} structured row(s).`);
      return;
    }

    const target = await save({
      title: "Export JSONL",
      filters: [{ name: "JSON Lines", extensions: ["jsonl"] }],
      defaultPath: await defaultDownloadPath("regex-isolator-results.jsonl"),
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
      const request = buildScanRequest();
      const response = IS_TAURI_RUNTIME
        ? await invoke<TransformResponse>("extract_matches_text", { request })
        : extractBrowserFullMatches(request);
      applyEditorSource(response.text ?? "", `Kept ${response.writtenCount.toLocaleString()} full match(es) in the editor.`, editorSourceFile);
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
      const request = buildScanRequest();
      const response = IS_TAURI_RUNTIME
        ? await invoke<TransformResponse>("delete_matches_text", { request })
        : deleteBrowserMatches(request);
      applyEditorSource(response.text ?? "", `Deleted ${response.removedCount.toLocaleString()} match(es) from the editor.`, editorSourceFile);
    } catch (error) {
      handleOperationError(error);
    }
  }

  async function handleSaveCleanedOutput() {
    if (activeJobId) {
      setStatusMessage("Wait for the background scan to finish before saving text without matches.");
      return;
    }

    if (directorySource) {
      setStatusMessage("Save text without matches works with editor text or a single file source.");
      return;
    }

    if (!pattern || (!sourceText && !fileSource)) {
      setStatusMessage("Choose a pattern and editor/file source before saving text without matches.");
      return;
    }

    if (!IS_TAURI_RUNTIME) {
      try {
        const response = deleteBrowserMatches(buildScanRequest());
        downloadTextFile("regex-isolator-without-matches.txt", response.text ?? "");
        setStatusMessage(`Downloaded text without ${response.removedCount.toLocaleString()} match(es).`);
      } catch (error) {
        handleOperationError(error);
      }
      return;
    }

    const target = await save({
      title: "Save source without matches",
      filters: [{ name: "Text", extensions: ["txt"] }],
      defaultPath: await defaultDownloadPath("regex-isolator-without-matches.txt"),
    });

    if (typeof target !== "string") {
      return;
    }

    try {
      setIsBusy(true);
      setStatusMessage("Saving text without matches...");
      const response = await invoke<TransformResponse>("save_cleaned_output", { path: target, request: buildScanRequest() });
      setStatusMessage(`Saved text without matches to ${target} after removing ${response.removedCount.toLocaleString()} match(es).`);
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
      const request = {
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
      } satisfies ScanRequest;
      const replaced = IS_TAURI_RUNTIME
        ? await invoke<string>("replace_source_text", { request })
        : replaceBrowserSource(request);
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

    if (!IS_TAURI_RUNTIME) {
      setStatusMessage("There is no background scan to cancel in the browser view.");
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

    selectEditableRange(sourceEditorRef.current, record.start, record.end);
  }

  const customPresetNames = Object.keys(customPresets).sort((left, right) => left.localeCompare(right));
  const backgroundSource = directorySource ?? fileSource;
  const patternAnalysis = analyzePattern(
    pattern,
    { ignoreCase, multiline, dotAll },
    Boolean(backgroundSource),
  );
  const displayedSourceModeLabel = directorySource
    ? `Directory source - ${directorySource.name}`
    : fileSource
      ? `File source - ${fileSource.name}`
      : sourceText
        ? editorSourceFile
          ? `Editor source - ${editorSourceFile.name}`
          : "Editor source"
        : "No source loaded";
  const modeLabel = directorySource ? "Folder source" : fileSource ? "File source" : liveMatching ? "Auto match" : "Manual match";
  const sourceMatchRanges = scanResponse?.sourceKind === "text"
    ? scanResponse.records
        .filter((record) => record.source === "text" && typeof record.start === "number" && typeof record.end === "number")
        .map((record) => ({ start: record.start as number, end: record.end as number }))
    : [];

  return (
    <div className={`app-shell ${isPatternStudioMinimized ? "studio-minimized" : ""}`}>
      <header className="app-header">
        <div>
          <p className="eyebrow">Regex Isolator</p>
          <h1>Regex Isolator</h1>
        </div>
        <div className="header-actions">
          <button className="ghost-button" onClick={() => setShowHelp((current) => !current)} title="Show or hide the regex syntax reference.">
            {showHelp ? "Hide help" : "Regex help"}
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
          fileSource={fileSource}
          sourceText={sourceText}
          sourceModeLabel={displayedSourceModeLabel}
          sourceEditorRef={sourceEditorRef}
          matchRanges={sourceMatchRanges}
          onSourceTextChange={handleSourceTextChange}
          onPaste={() => void handlePaste()}
          onPickFile={() => void handlePickFile()}
          onClearSource={() => void handleClearSource()}
          onSaveSource={() => void handleSaveSource()}
          onSaveWithoutMatches={() => void handleSaveCleanedOutput()}
          onKeepMatches={() => void handleKeepMatches()}
          onDeleteMatches={() => void handleDeleteMatches()}
        />

        <ResultsPanel
          scanResponse={scanResponse}
          isBusy={isBusy}
          errorMessage={errorMessage}
          onCopyOutput={() => void handleCopyOutput()}
          onSaveOutput={() => void handleSaveOutput()}
          onExportJsonl={() => void handleExportJsonl()}
          onJumpToRecord={jumpToRecord}
        />
      </section>

      {showHelp ? <RegexHelpPanel /> : null}
    </div>
  );
}
