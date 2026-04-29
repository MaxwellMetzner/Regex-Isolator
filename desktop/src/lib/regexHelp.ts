export const REGEX_HELP: Array<{ title: string; rows: Array<[string, string]> }> = [
  {
    title: "Characters",
    rows: [
      [String.raw`.`, "Any character except newline"],
      [String.raw`\d`, "Digit [0-9]"],
      [String.raw`\D`, "Non-digit"],
      [String.raw`\w`, "Word character [a-zA-Z0-9_]"],
      [String.raw`\W`, "Non-word character"],
      [String.raw`\s`, "Whitespace"],
      [String.raw`\S`, "Non-whitespace"],
      [String.raw`\b`, "Word boundary"],
    ],
  },
  {
    title: "Quantifiers",
    rows: [
      ["*", "0 or more"],
      ["+", "1 or more"],
      ["?", "0 or 1"],
      ["{n}", "Exactly n"],
      ["{n,}", "n or more"],
      ["{n,m}", "Between n and m"],
      ["*? +? ??", "Non-greedy versions"],
    ],
  },
  {
    title: "Groups",
    rows: [
      ["(...)", "Capturing group"],
      ["(?:...)", "Non-capturing group"],
      ["(?P<name>...)", "Named group in Python-style syntax"],
      [String.raw`\1`, "Back-reference to group 1"],
      ["(a|b)", "Alternation"],
    ],
  },
  {
    title: "Lookaround",
    rows: [
      ["(?=...)", "Positive lookahead"],
      ["(?!...)", "Negative lookahead"],
      ["(?<=...)", "Positive lookbehind"],
      ["(?<!...)", "Negative lookbehind"],
    ],
  },
  {
    title: "Flags",
    rows: [
      ["Ignore Case", "Case-insensitive matching"],
      ["Multiline", "^ and $ match each line"],
      ["Dot All", ". also matches newline"],
    ],
  },
  {
    title: "Replacement",
    rows: [
      [String.raw`\1`, "Insert capture group 1"],
      [String.raw`\g<name>`, "Insert a named capture"],
      [String.raw`\n \t`, "Insert newline or tab"],
      ["Empty replacement", "Delete each match"],
    ],
  },
  {
    title: "Large Files",
    rows: [
      ["Line mode", "Large files stay on disk"],
      ["Save all matches", "Streams every match beyond preview limits"],
      ["Save cleaned", "Writes a copy with matches removed"],
      ["Dot All", "Use editor mode for true cross-line matching"],
    ],
  },
  {
    title: "Performance",
    rows: [
      ["literal", "Start with a literal prefix when possible"],
      [".*", "Avoid leading or repeated wildcards"],
      ["(?:...)", "Use non-capturing groups when captures are not needed"],
      ["{0,200}", "Prefer bounded repeats on huge files"],
    ],
  },
];
