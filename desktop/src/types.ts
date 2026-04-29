export type Delimiter = "Newline" | "Comma" | "Tab" | "Space";

export interface RegexFlags {
  ignoreCase: boolean;
  multiline: boolean;
  dotAll: boolean;
}

export interface FileSource {
  path: string;
  name: string;
  size: number;
}

export interface DirectorySource {
  path: string;
  name: string;
}

export interface LoadSourceResponse {
  kind: "text" | "file";
  text?: string;
  file?: FileSource;
  note: string;
}

export interface ScanRecord {
  match: string;
  fullMatch: string;
  captures: string[];
  start?: number;
  end?: number;
  line?: number;
  columnStart?: number;
  columnEnd?: number;
  preview?: string;
  filePath?: string;
  source: "text" | "file" | "directory";
}

export interface ScanResponse {
  engine: string;
  engineDetail: string;
  sourceKind: "text" | "file" | "directory";
  totalMatches: number;
  output: string;
  outputCount: number;
  truncated: boolean;
  detail: string;
  status: string;
  warnings: string[];
  records: ScanRecord[];
  replacementPreview?: string | null;
  replacementWarning?: string | null;
  scannedFiles?: number | null;
  completedFiles?: number | null;
  scannedLines: number;
}

export interface ScanRequest {
  pattern: string;
  replacement: string;
  flags: RegexFlags;
  uniqueOnly: boolean;
  delimiter: Delimiter;
  outputLimit: number;
  sourceText?: string | null;
  filePath?: string | null;
  directoryPath?: string | null;
}

export interface ScanJobEvent {
  jobId: string;
  state: "running" | "completed" | "cancelled" | "error";
  sourceKind: "text" | "file" | "directory" | "unknown";
  message: string;
  currentPath?: string | null;
  percent?: number | null;
  filesProcessed: number;
  filesTotal?: number | null;
  linesProcessed: number;
  matchesFound: number;
  result?: ScanResponse | null;
  error?: string | null;
}

export interface TransformResponse {
  text?: string | null;
  matchCount: number;
  writtenCount: number;
  removedCount: number;
  scannedFiles: number;
  scannedLines: number;
}

export interface SavedPreset {
  pattern: string;
  replacement: string;
  flags: RegexFlags;
  uniqueOnly: boolean;
  delimiter: Delimiter;
  liveMatching: boolean;
}
