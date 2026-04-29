import type { RegexFlags } from "../types";

export interface PatternAnalysis {
  captureSummary: string;
  flagSummary: string;
  hints: string[];
  tone: "neutral" | "success" | "warning" | "error";
}

export function analyzePattern(pattern: string, flags: RegexFlags, hasLineModeSource: boolean): PatternAnalysis {
  if (!pattern) {
    return {
      captureSummary: "Waiting for a pattern",
      flagSummary: formatFlagSummary(flags),
      hints: ["Enter a regex to see capture, flag, and performance guidance."],
      tone: "neutral",
    };
  }

  const hints: string[] = [];
  let tone: PatternAnalysis["tone"] = "success";

  if (pattern.startsWith(".*") || pattern.startsWith("^.*")) {
    hints.push("Leading dot-star can force broad scans before a match is proven.");
    tone = "warning";
  }

  if (/\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{)/.test(pattern)) {
    hints.push("Nested unbounded quantifiers can backtrack heavily.");
    tone = "error";
  }

  if (/\.\*.*\.\*/.test(pattern) || /\.\+.*\.\+/.test(pattern)) {
    hints.push("Multiple wildcard repeats are expensive on very large lines.");
    if (tone !== "error") {
      tone = "warning";
    }
  }

  if (/\\[1-9]/.test(pattern) || pattern.includes("\\g<")) {
    hints.push("Backreferences are slower than regular captures at gigabyte scale.");
    if (tone !== "error") {
      tone = "warning";
    }
  }

  if (["(?=", "(?!", "(?<=", "(?<!"].some((token) => pattern.includes(token))) {
    hints.push("Lookaround may trigger the compatibility engine and scan slower.");
    if (tone !== "error") {
      tone = "warning";
    }
  }

  if (hasLineModeSource && (flags.dotAll || inlineDotAllEnabled(pattern))) {
    hints.push("Dot All is disabled for file and directory line mode.");
    tone = "error";
  }

  const literalPrefix = findLiteralPrefix(pattern);
  if (literalPrefix) {
    hints.push(`Literal prefix "${literalPrefix.slice(0, 32)}" gives the engine a useful starting point.`);
  }

  if (!hints.length) {
    hints.push("Looks line-scan friendly. Prefer literals, bounded repeats, and non-capturing groups when possible.");
  }

  return {
    captureSummary: formatCaptureSummary(pattern),
    flagSummary: formatFlagSummary(flags),
    hints,
    tone,
  };
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

    if (char !== "(") {
      continue;
    }

    const next = pattern[index + 1];
    const afterNext = pattern[index + 2];
    if (next === "?" && afterNext !== "P") {
      continue;
    }

    count += 1;
  }

  return count;
}

function findLiteralPrefix(pattern: string) {
  let text = pattern.startsWith("^") ? pattern.slice(1) : pattern;
  const inlineFlagMatch = text.match(/^\(\?[a-zA-Z-]+:?\)/);
  if (inlineFlagMatch) {
    text = text.slice(inlineFlagMatch[0].length);
  }

  let prefix = "";
  let escaped = false;
  for (const char of text) {
    if (escaped) {
      if ("AbBdDsSwWZ0123456789".includes(char)) {
        break;
      }
      prefix += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if (/[\w _\-:/@.]/.test(char)) {
      prefix += char;
      continue;
    }

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
    if (enabledFlags.includes("s")) {
      return true;
    }
  }

  return false;
}
