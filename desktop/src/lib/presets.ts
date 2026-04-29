import type { Delimiter, SavedPreset } from "../types";

export const DEFAULT_PRESET_PLACEHOLDER = "Select a preset";

export const BUILTIN_PRESETS: Array<{ label: string; pattern: string }> = [
  { label: "Email", pattern: String.raw`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+` },
  { label: "URL", pattern: String.raw`https?://[^\s/$.?#].[^\s]*` },
  {
    label: "Video src URL",
    pattern: String.raw`(?<=\bsrc=")[^"]+\.(?:mp4|webm|ogg|ogv|mov|m4v|avi|mkv)(?:\?[^"]*)?(?=")`,
  },
  {
    label: "Image src URL",
    pattern: String.raw`(?<=\bsrc=")[^"]+\.(?:png|jpe?g|gif|webp|svg)(?:\?[^"]*)?(?=")`,
  },
  { label: "Link href URL", pattern: String.raw`(?<=\bhref=")[^"]+(?=")` },
  { label: "Domain", pattern: String.raw`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b` },
  { label: "UUID", pattern: String.raw`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b` },
  {
    label: "ISO 8601 DateTime",
    pattern: String.raw`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})\b`,
  },
  { label: "Hashtag", pattern: String.raw`(?<!\w)#\w+` },
  { label: "@Mention", pattern: String.raw`(?<!\w)@[A-Za-z0-9_]+` },
  { label: "MAC Address", pattern: String.raw`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` },
  { label: "IPv4 Address", pattern: String.raw`\b\d{1,3}(?:\.\d{1,3}){3}\b` },
  { label: "Phone (US)", pattern: String.raw`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}` },
  { label: "Hex Color", pattern: String.raw`#(?:[0-9a-fA-F]{3}){1,2}\b` },
  { label: "Date (YYYY-MM-DD)", pattern: String.raw`\d{4}-\d{2}-\d{2}` },
  { label: "HTML Tag", pattern: String.raw`<[^>]+>` },
  { label: "Integer", pattern: String.raw`-?\d+` },
  { label: "Decimal Number", pattern: String.raw`-?\d+\.\d+` },
];

export function createPresetPayload(current: {
  pattern: string;
  replacement: string;
  ignoreCase: boolean;
  multiline: boolean;
  dotAll: boolean;
  uniqueOnly: boolean;
  delimiter: Delimiter;
  liveMatching: boolean;
}): SavedPreset {
  return {
    pattern: current.pattern,
    replacement: current.replacement,
    flags: {
      ignoreCase: current.ignoreCase,
      multiline: current.multiline,
      dotAll: current.dotAll,
    },
    uniqueOnly: current.uniqueOnly,
    delimiter: current.delimiter,
    liveMatching: current.liveMatching,
  };
}
