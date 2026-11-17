export interface RegexSnippetPlaceholder {
  start: number;
  end: number;
}

export interface RegexHelpRow {
  syntax: string;
  description: string;
  insert?: string;
  placeholders?: RegexSnippetPlaceholder[];
  wrapPlaceholderIndex?: number;
}

export interface RegexHelpSection {
  title: string;
  rows: RegexHelpRow[];
}

export const REGEX_HELP: RegexHelpSection[] = [
  {
    title: "Characters",
    rows: [
      { syntax: String.raw`.`, description: "Any character except newline", insert: "." },
      { syntax: String.raw`\d`, description: "Digit [0-9]", insert: String.raw`\d` },
      { syntax: String.raw`\D`, description: "Non-digit", insert: String.raw`\D` },
      { syntax: String.raw`\w`, description: "Word character [a-zA-Z0-9_]", insert: String.raw`\w` },
      { syntax: String.raw`\W`, description: "Non-word character", insert: String.raw`\W` },
      { syntax: String.raw`\s`, description: "Whitespace", insert: String.raw`\s` },
      { syntax: String.raw`\S`, description: "Non-whitespace", insert: String.raw`\S` },
      { syntax: "[abc]", description: "Any listed character", insert: "[abc]", placeholders: [{ start: 1, end: 4 }] },
      { syntax: "[^abc]", description: "Any character not listed", insert: "[^abc]", placeholders: [{ start: 2, end: 5 }] },
      { syntax: "[a-z]", description: "Character range", insert: "[a-z]", placeholders: [{ start: 1, end: 2 }, { start: 3, end: 4 }] },
    ],
  },
  {
    title: "Anchors & boundaries",
    rows: [
      { syntax: "^", description: "Start of text or line", insert: "^" },
      { syntax: "$", description: "End of text or line", insert: "$" },
      { syntax: String.raw`\b`, description: "Word boundary", insert: String.raw`\b` },
      { syntax: String.raw`\B`, description: "Not a word boundary", insert: String.raw`\B` },
    ],
  },
  {
    title: "Quantifiers",
    rows: [
      { syntax: "*", description: "0 or more", insert: "*" },
      { syntax: "+", description: "1 or more", insert: "+" },
      { syntax: "?", description: "0 or 1", insert: "?" },
      { syntax: "{n}", description: "Exactly n", insert: "{n}", placeholders: [{ start: 1, end: 2 }] },
      { syntax: "{n,}", description: "n or more", insert: "{n,}", placeholders: [{ start: 1, end: 2 }] },
      { syntax: "{n,m}", description: "Between n and m", insert: "{n,m}", placeholders: [{ start: 1, end: 2 }, { start: 3, end: 4 }] },
      { syntax: "*?", description: "Lazy 0 or more", insert: "*?" },
      { syntax: "+?", description: "Lazy 1 or more", insert: "+?" },
    ],
  },
  {
    title: "Groups",
    rows: [
      { syntax: "(...)", description: "Capturing group", insert: "(...)", placeholders: [{ start: 1, end: 4 }], wrapPlaceholderIndex: 0 },
      { syntax: "(?:...)", description: "Non-capturing group", insert: "(?:...)", placeholders: [{ start: 3, end: 6 }], wrapPlaceholderIndex: 0 },
      { syntax: "(?P<name>...)", description: "Named capture group", insert: "(?P<name>...)", placeholders: [{ start: 4, end: 8 }, { start: 9, end: 12 }], wrapPlaceholderIndex: 1 },
      { syntax: String.raw`\1`, description: "Back-reference to group 1", insert: String.raw`\1`, placeholders: [{ start: 1, end: 2 }] },
      { syntax: "(a|b)", description: "Alternation", insert: "(a|b)", placeholders: [{ start: 1, end: 2 }, { start: 3, end: 4 }], wrapPlaceholderIndex: 0 },
    ],
  },
  {
    title: "Lookaround",
    rows: [
      { syntax: "(?=...)", description: "Positive lookahead", insert: "(?=...)", placeholders: [{ start: 3, end: 6 }], wrapPlaceholderIndex: 0 },
      { syntax: "(?!...)", description: "Negative lookahead", insert: "(?!...)", placeholders: [{ start: 3, end: 6 }], wrapPlaceholderIndex: 0 },
      { syntax: "(?<=...)", description: "Positive lookbehind", insert: "(?<=...)", placeholders: [{ start: 4, end: 7 }], wrapPlaceholderIndex: 0 },
      { syntax: "(?<!...)", description: "Negative lookbehind", insert: "(?<!...)", placeholders: [{ start: 4, end: 7 }], wrapPlaceholderIndex: 0 },
    ],
  },
  {
    title: "Flags",
    rows: [
      { syntax: "Ignore Case", description: "Case-insensitive matching" },
      { syntax: "Multiline", description: "^ and $ match each line" },
      { syntax: "Dot All", description: ". also matches newline" },
    ],
  },
  {
    title: "Performance",
    rows: [
      { syntax: "literal", description: "Start with a literal prefix when possible" },
      { syntax: ".*", description: "Avoid leading or repeated wildcards" },
      { syntax: "(?:...)", description: "Use non-capturing groups when captures are not needed" },
      { syntax: "{0,200}", description: "Prefer bounded repeats on huge files", insert: "{0,200}", placeholders: [{ start: 1, end: 2 }, { start: 3, end: 6 }] },
    ],
  },
];
