import type { ScanRecord, ScanRequest, ScanResponse, TransformResponse } from "../types";

function delimiterValue(delimiter: string) {
  switch (delimiter) {
    case "Comma":
      return ",";
    case "Tab":
      return "\t";
    case "Space":
      return " ";
    default:
      return "\n";
  }
}

function scannedLineCount(text: string) {
  if (!text) {
    return 0;
  }

  return text.split(/\r\n|\r|\n/).length;
}

function normalizePattern(pattern: string) {
  return pattern.replace(/\(\?P<([A-Za-z_]\w*)>/g, "(?<$1>");
}

function buildFlags(request: ScanRequest) {
  const flags = new Set(["g"]);
  if (request.flags.ignoreCase) {
    flags.add("i");
  }
  if (request.flags.multiline) {
    flags.add("m");
  }
  if (request.flags.dotAll) {
    flags.add("s");
  }
  return [...flags].join("");
}

function compileBrowserRegex(request: ScanRequest) {
  try {
    return new RegExp(normalizePattern(request.pattern), buildFlags(request));
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : String(error));
  }
}

function capturesFor(match: RegExpExecArray) {
  return match.slice(1).map((capture) => capture ?? "");
}

function displayValue(fullMatch: string, captures: string[]) {
  if (captures.length === 0) {
    return fullMatch;
  }

  if (captures.length === 1) {
    return captures[0] ?? "";
  }

  return captures.filter(Boolean).join("");
}

function eachMatch(request: ScanRequest, callback: (match: RegExpExecArray) => void) {
  const sourceText = request.sourceText ?? "";
  const regex = compileBrowserRegex(request);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(sourceText)) !== null) {
    callback(match);

    if (match[0].length === 0) {
      regex.lastIndex += 1;
    }
  }
}

export function scanBrowserSource(request: ScanRequest): ScanResponse {
  const sourceText = request.sourceText ?? "";
  const seen = new Set<string>();
  const displayValues: string[] = [];
  const records: ScanRecord[] = [];
  let totalMatches = 0;
  let truncated = false;

  eachMatch(request, (match) => {
    totalMatches += 1;
    const fullMatch = match[0];
    const captures = capturesFor(match);
    const value = displayValue(fullMatch, captures);

    if (request.uniqueOnly && seen.has(value)) {
      return;
    }
    seen.add(value);

    if (records.length >= request.outputLimit) {
      truncated = true;
      return;
    }

    displayValues.push(value);
    records.push({
      match: value,
      fullMatch,
      captures,
      start: match.index,
      end: match.index + fullMatch.length,
      source: "text",
    });
  });

  const visibleCount = records.length;
  const uniqueNote = request.uniqueOnly ? ` Showing ${visibleCount.toLocaleString()} unique result(s).` : "";
  const capNote = truncated ? ` Output is capped at the first ${request.outputLimit.toLocaleString()} displayed matches.` : "";

  return {
    engine: "Browser",
    engineDetail: "Browser JavaScript RegExp",
    sourceKind: "text",
    totalMatches,
    output: displayValues.join(delimiterValue(request.delimiter)),
    outputCount: visibleCount,
    truncated,
    detail: totalMatches
      ? `Click a result row to select its source span.${uniqueNote}${capNote}`
      : "No results for the current pattern.",
    status: totalMatches ? `Found ${totalMatches.toLocaleString()} match(es).` : "No matches found.",
    warnings: [],
    records,
    replacementPreview: buildReplacementPreview(request),
    replacementWarning: null,
    scannedFiles: null,
    completedFiles: null,
    scannedLines: scannedLineCount(sourceText),
  };
}

export function extractBrowserFullMatches(request: ScanRequest): TransformResponse {
  const seen = new Set<string>();
  const values: string[] = [];
  let matchCount = 0;

  eachMatch(request, (match) => {
    matchCount += 1;
    const value = match[0];
    if (request.uniqueOnly && seen.has(value)) {
      return;
    }
    seen.add(value);
    values.push(value);
  });

  return {
    text: values.join(delimiterValue(request.delimiter)),
    matchCount,
    writtenCount: values.length,
    removedCount: 0,
    scannedFiles: 0,
    scannedLines: scannedLineCount(request.sourceText ?? ""),
  };
}

export function deleteBrowserMatches(request: ScanRequest): TransformResponse {
  const sourceText = request.sourceText ?? "";
  const regex = compileBrowserRegex(request);
  let removedCount = 0;
  const text = sourceText.replace(regex, () => {
    removedCount += 1;
    return "";
  });

  return {
    text,
    matchCount: removedCount,
    writtenCount: 0,
    removedCount,
    scannedFiles: 0,
    scannedLines: scannedLineCount(sourceText),
  };
}

export function replaceBrowserSource(request: ScanRequest) {
  return (request.sourceText ?? "").replace(compileBrowserRegex(request), translateReplacement(request.replacement));
}

function buildReplacementPreview(request: ScanRequest) {
  if (!request.replacement.trim() || !request.sourceText) {
    return null;
  }

  const replaced = replaceBrowserSource(request).replace(/\s+/g, " ").trim();
  return replaced.length > 120 ? `${replaced.slice(0, 120)}...` : replaced;
}

function translateReplacement(replacement: string) {
  return replacement
    .replace(/\\g<([A-Za-z_]\w*)>/g, "$<$1>")
    .replace(/\\g<(\d+)>/g, "$$$1")
    .replace(/\\([1-9]\d*)/g, "$$$1")
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\r/g, "\r");
}
