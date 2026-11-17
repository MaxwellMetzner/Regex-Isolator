import type { RegexFlags } from "../types";

export interface PatternIssue {
  severity: "warning" | "error";
  message: string;
}

export interface PatternAnalysis {
  captureSummary: string;
  flagSummary: string;
  hints: string[];
  issues: PatternIssue[];
  intentSummary: string;
  tone: "neutral" | "success" | "warning" | "error";
}

export function analyzePattern(pattern: string, flags: RegexFlags, hasLineModeSource: boolean): PatternAnalysis {
  if (!pattern) {
    return {
      captureSummary: "Waiting for a pattern",
      flagSummary: formatFlagSummary(flags),
      hints: ["Enter a regex or use the Reference builder to assemble one."],
      issues: [],
      intentSummary: "No matching behavior to describe yet.",
      tone: "neutral",
    };
  }

  const issues = inspectStructure(pattern);
  const hints: string[] = [];
  let tone: PatternAnalysis["tone"] = issues.some((issue) => issue.severity === "error") ? "error" : "success";

  function warn(message: string, severity: PatternIssue["severity"] = "warning") {
    issues.push({ severity, message });
    if (severity === "error") {
      tone = "error";
    } else if (tone !== "error") {
      tone = "warning";
    }
  }

  if (pattern.startsWith(".*") || pattern.startsWith("^.*")) {
    warn("Leading dot-star scans broadly before it can prove a match.");
  }

  if (/\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{)/.test(pattern)) {
    warn("Nested unbounded quantifiers can cause severe backtracking.", "error");
  }

  if (/\.\*.*\.\*/.test(pattern) || /\.\+.*\.\+/.test(pattern)) {
    warn("Multiple wildcard repeats may be expensive on large lines.");
  }

  if (/\\[1-9]/.test(pattern) || pattern.includes("\\g<")) {
    warn("Backreferences require the compatibility engine and may scan more slowly.");
  }

  if (["(?=", "(?!", "(?<=", "(?<!"].some((token) => pattern.includes(token))) {
    warn("Lookaround may use the compatibility engine instead of the fast scan path.");
  }

  if (hasLineModeSource && (flags.dotAll || inlineDotAllEnabled(pattern))) {
    warn("Dot All cannot provide true cross-line matching in file or folder line mode.", "error");
  }

  if (/(^|[^\\])\|($|\))/.test(pattern) || /\(\|/.test(pattern)) {
    warn("An empty alternation branch can match without consuming text.");
  }

  const literalPrefix = findLiteralPrefix(pattern);
  if (literalPrefix) {
    hints.push(`Literal prefix “${literalPrefix.slice(0, 32)}” gives the engine a useful starting point.`);
  }

  if (!issues.length && !hints.length) {
    hints.push("Looks structurally sound and friendly to line-based scanning.");
  } else if (!hints.length) {
    hints.push("Test against representative source text to confirm the intended matches and exclusions.");
  }

  return {
    captureSummary: formatCaptureSummary(pattern),
    flagSummary: formatFlagSummary(flags),
    hints,
    issues,
    intentSummary: describeLikelyIntent(pattern, flags),
    tone,
  };
}

function inspectStructure(pattern: string): PatternIssue[] {
  const issues: PatternIssue[] = [];
  const openGroups: number[] = [];
  let escaped = false;
  let inClass = false;
  let classStart = -1;

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (inClass) {
      if (char === "]" && index > classStart + 1) {
        inClass = false;
      }
      continue;
    }
    if (char === "[") {
      inClass = true;
      classStart = index;
      continue;
    }
    if (char === "(") {
      openGroups.push(index);
      continue;
    }
    if (char === ")") {
      if (!openGroups.length) {
        issues.push({ severity: "error", message: `Closing parenthesis at character ${index + 1} has no matching opening parenthesis.` });
      } else {
        openGroups.pop();
      }
    }
  }

  if (escaped) {
    issues.push({ severity: "error", message: "The expression ends with an incomplete escape (\\)." });
  }
  if (inClass) {
    issues.push({ severity: "error", message: `Character class opened at character ${classStart + 1} is not closed.` });
  }
  if (openGroups.length) {
    const last = openGroups[openGroups.length - 1];
    issues.push({ severity: "error", message: `Group opened at character ${last + 1} is not closed.` });
  }

  return issues;
}

function describeLikelyIntent(pattern: string, flags: RegexFlags) {
  const parts: string[] = [];
  const anchoredStart = pattern.startsWith("^");
  const anchoredEnd = unescapedEndsWith(pattern, "$");

  if (anchoredStart && anchoredEnd) {
    parts.push(flags.multiline ? "Matches complete lines" : "Matches the complete source text");
  } else if (anchoredStart) {
    parts.push(flags.multiline ? "Matches from the start of a line" : "Matches from the start of the source");
  } else if (anchoredEnd) {
    parts.push(flags.multiline ? "Matches text ending at a line boundary" : "Matches text ending at the source boundary");
  } else {
    parts.push("Searches anywhere in the source");
  }

  const subjects: string[] = [];
  if (/\\d|\[0-9/.test(pattern)) subjects.push("digits");
  if (/\\w/.test(pattern)) subjects.push("word characters");
  if (/\\s/.test(pattern)) subjects.push("whitespace");
  if (/\[[^\]]+\]/.test(pattern)) subjects.push("a character set");
  if (/\.\*|\.\+/.test(pattern)) subjects.push("variable text");
  if (subjects.length) parts.push(`using ${subjects.slice(0, 3).join(", ")}`);

  if (/[+*]|\{\d+(?:,\d*)?\}/.test(pattern)) parts.push("with repeated elements");
  if (pattern.includes("|")) parts.push("and alternative branches");
  if (flags.ignoreCase) parts.push("without case sensitivity");

  return `${parts.join(" ")}.`;
}

function formatFlagSummary(flags: RegexFlags) {
  const active = [
    flags.ignoreCase ? "Ignore Case" : null,
    flags.multiline ? "Multiline" : null,
    flags.dotAll ? "Dot All" : null,
  ].filter(Boolean);
  return active.length ? active.join(", ") : "No flags";
}

function formatCaptureSummary(pattern: string) {
  const captureCount = countCapturingGroups(pattern);
  return `${captureCount} capture group${captureCount === 1 ? "" : "s"}`;
}

function countCapturingGroups(pattern: string) {
  let count = 0;
  let escaped = false;
  let inClass = false;
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (escaped) { escaped = false; continue; }
    if (char === "\\") { escaped = true; continue; }
    if (char === "[") { inClass = true; continue; }
    if (char === "]" && inClass) { inClass = false; continue; }
    if (inClass || char !== "(") continue;
    const next = pattern[index + 1];
    const afterNext = pattern[index + 2];
    if (next === "?" && afterNext !== "P") continue;
    count += 1;
  }
  return count;
}

function findLiteralPrefix(pattern: string) {
  let text = pattern.startsWith("^") ? pattern.slice(1) : pattern;
  const inlineFlagMatch = text.match(/^\(\?[a-zA-Z-]+:?\)/);
  if (inlineFlagMatch) text = text.slice(inlineFlagMatch[0].length);

  let prefix = "";
  let escaped = false;
  for (const char of text) {
    if (escaped) {
      if ("AbBdDsSwWZ0123456789".includes(char)) break;
      prefix += char;
      escaped = false;
      continue;
    }
    if (char === "\\") { escaped = true; continue; }
    if (/[\w _\-:/@.]/.test(char)) { prefix += char; continue; }
    break;
  }
  return prefix.trim();
}

function inlineDotAllEnabled(pattern: string) {
  const inlineGroups = pattern.matchAll(/\(\?([a-zA-Z-]+)(?::|\))/g);
  for (const group of inlineGroups) {
    const flags = group[1];
    const disabledIndex = flags.indexOf("-");
    const enabledFlags = disabledIndex >= 0 ? flags.slice(0, disabledIndex) : flags;
    if (enabledFlags.includes("s")) return true;
  }
  return false;
}

function unescapedEndsWith(pattern: string, token: string) {
  if (!pattern.endsWith(token)) return false;
  let slashes = 0;
  for (let index = pattern.length - token.length - 1; index >= 0 && pattern[index] === "\\"; index -= 1) slashes += 1;
  return slashes % 2 === 0;
}
