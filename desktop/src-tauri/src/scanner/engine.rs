use fancy_regex as fancy;
use regex as fast_regex;

use super::response::{truncate_preview, PREVIEW_MAX_CHARS};
use super::{RegexFlags, ScanRequest};

const REPLACEMENT_PREVIEW_THRESHOLD: usize = 300_000;

pub(crate) enum RegexEngine {
    Fast(fast_regex::Regex),
    Fancy {
        regex: fancy::Regex,
        fallback_reason: String,
    },
}

pub(crate) struct ReplacementPlan {
    pub(crate) translated: String,
    pub(crate) notes: Vec<String>,
}

impl RegexEngine {
    pub(crate) fn compile(pattern: &str, flags: &RegexFlags) -> Result<Self, String> {
        let compiled_pattern = apply_inline_flags(pattern, flags);
        match fast_regex::Regex::new(&compiled_pattern) {
            Ok(regex) => Ok(Self::Fast(regex)),
            Err(fast_error) => match fancy::Regex::new(&compiled_pattern) {
                Ok(regex) => Ok(Self::Fancy {
                    regex,
                    fallback_reason: fast_error.to_string(),
                }),
                Err(fancy_error) => Err(format!(
                    "Pattern failed in both engines. fast-regex: {fast_error}; fancy-regex: {fancy_error}"
                )),
            },
        }
    }

    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Fast(_) => "fast-regex",
            Self::Fancy { .. } => "fancy-regex fallback",
        }
    }

    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Fast(_) => {
                "Used Rust's fast regex engine for the scan path. This is the preferred engine for large text and file workloads.".to_string()
            }
            Self::Fancy { fallback_reason, .. } => format!(
                "The fast Rust regex engine rejected this pattern ({fallback_reason}). The scan fell back to fancy-regex to preserve advanced constructs such as lookaround."
            ),
        }
    }

    pub(crate) fn replace_all(&self, text: &str, replacement: &str) -> Result<String, String> {
        match self {
            Self::Fast(regex) => Ok(regex.replace_all(text, replacement).to_string()),
            Self::Fancy { regex, .. } => Ok(regex.replace_all(text, replacement).to_string()),
        }
    }

    pub(crate) fn replace_line(
        &self,
        text: &str,
        replacement: &str,
    ) -> Result<(String, usize), String> {
        let mut count = 0usize;
        self.visit_matches(text, |_full_match, _captures, _start, _end| {
            count += 1;
            Ok(())
        })?;
        Ok((self.replace_all(text, replacement)?, count))
    }

    pub(crate) fn visit_matches<F>(&self, text: &str, mut visit: F) -> Result<(), String>
    where
        F: FnMut(&str, Vec<String>, usize, usize) -> Result<(), String>,
    {
        match self {
            Self::Fast(regex) => {
                for captures in regex.captures_iter(text) {
                    let full_match = match captures.get(0) {
                        Some(value) => value,
                        None => continue,
                    };
                    visit(
                        full_match.as_str(),
                        collect_fast_captures(&captures),
                        full_match.start(),
                        full_match.end(),
                    )?;
                }
            }
            Self::Fancy { regex, .. } => {
                for capture_result in regex.captures_iter(text) {
                    let captures = capture_result.map_err(|error| error.to_string())?;
                    let full_match = match captures.get(0) {
                        Some(value) => value,
                        None => continue,
                    };
                    visit(
                        full_match.as_str(),
                        collect_fancy_captures(&captures),
                        full_match.start(),
                        full_match.end(),
                    )?;
                }
            }
        }

        Ok(())
    }
}

pub(crate) fn build_replacement_preview(
    engine: &RegexEngine,
    request: &ScanRequest,
    source_text: &str,
) -> Result<(Option<String>, Option<String>), String> {
    if request.replacement.trim().is_empty() {
        return Ok((None, None));
    }

    if source_text.len() > REPLACEMENT_PREVIEW_THRESHOLD {
        return Ok((
            None,
            Some(
                "Replacement preview is skipped for large editor text. Use Copy replacement when you need the full output.".to_string(),
            ),
        ));
    }

    let replacement_plan = translate_python_replacement(&request.replacement);
    let replaced = engine.replace_all(source_text, &replacement_plan.translated)?;
    let preview = truncate_preview(&replaced, PREVIEW_MAX_CHARS);
    let mut notes = replacement_plan.notes;
    notes.push(
        "Python-style replacement syntax is accepted here, including \\1, \\g<1>, and \\g<name> backreferences.".to_string(),
    );
    Ok((Some(preview), Some(notes.join(" "))))
}

pub(crate) fn translate_python_replacement(replacement: &str) -> ReplacementPlan {
    let mut translated = String::new();
    let mut notes = Vec::new();
    let mut saw_backreference = false;
    let mut saw_dollar_escape = false;
    let mut chars = replacement.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            translated.push_str("$$");
            saw_dollar_escape = true;
            continue;
        }

        if ch != '\\' {
            translated.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('\\') => {
                chars.next();
                translated.push('\\');
            }
            Some('n') => {
                chars.next();
                translated.push('\n');
            }
            Some('r') => {
                chars.next();
                translated.push('\r');
            }
            Some('t') => {
                chars.next();
                translated.push('\t');
            }
            Some('g') => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    chars.next();
                    let mut capture_name = String::new();
                    let mut closed = false;
                    for next in chars.by_ref() {
                        if next == '>' {
                            closed = true;
                            break;
                        }
                        capture_name.push(next);
                    }

                    if closed && !capture_name.is_empty() {
                        translated.push('$');
                        translated.push_str(&capture_name);
                        saw_backreference = true;
                    } else {
                        translated.push_str("\\g<");
                        translated.push_str(&capture_name);
                    }
                } else {
                    translated.push('g');
                }
            }
            Some(next) if next.is_ascii_digit() => {
                let mut capture_index = String::new();
                while let Some(digit) = chars.peek().copied() {
                    if !digit.is_ascii_digit() {
                        break;
                    }
                    capture_index.push(digit);
                    chars.next();
                }

                translated.push('$');
                translated.push_str(&capture_index);
                saw_backreference = true;
            }
            Some(other) => {
                chars.next();
                translated.push(other);
            }
            None => translated.push('\\'),
        }
    }

    if saw_backreference {
        notes.push(
            "Backreferences in Python replacement form were translated for the Rust backend."
                .to_string(),
        );
    }
    if saw_dollar_escape {
        notes.push(
            "Literal dollar signs are escaped automatically in replacement mode.".to_string(),
        );
    }

    ReplacementPlan { translated, notes }
}

pub(crate) fn collect_fast_captures(captures: &fast_regex::Captures<'_>) -> Vec<String> {
    (1..captures.len())
        .map(|index| {
            captures
                .get(index)
                .map(|value| value.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

pub(crate) fn collect_fancy_captures(captures: &fancy::Captures<'_>) -> Vec<String> {
    (1..captures.len())
        .map(|index| {
            captures
                .get(index)
                .map(|value| value.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

fn apply_inline_flags(pattern: &str, flags: &RegexFlags) -> String {
    let mut enabled = String::new();
    if flags.ignore_case {
        enabled.push('i');
    }
    if flags.multiline {
        enabled.push('m');
    }
    if flags.dot_all {
        enabled.push('s');
    }

    if enabled.is_empty() {
        pattern.to_string()
    } else {
        format!("(?{enabled}){pattern}")
    }
}
