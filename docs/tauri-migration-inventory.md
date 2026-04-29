# Tauri Migration Inventory

## Current State

Regex Isolator has completed the app-level migration to Tauri 2 + React + Rust. The former Python/Tkinter entrypoint has been removed from the active product surface.

## Preserved Capabilities

- Regex pattern input with Ignore Case, Multiline, and Dot All toggles.
- Live editor matching plus manual Match Now mode.
- Replacement preview and replacement copy for editor-backed text.
- Built-in presets plus custom named presets stored in local storage.
- Clipboard, editor, file, and recursive folder source workflows.
- Large-file behavior that keeps files over 16 MiB on disk.
- Line-by-line Rust scanning for file and folder sources.
- Match records with captures, offsets, line numbers, columns, file paths, and previews.
- Plain-text result save and structured JSONL export.
- Save all matches beyond the preview cap.
- Save cleaned output for editor and single-file sources.
- Keep-only-matches and delete-matches editor transforms.
- Regex tutorial/reference panel.
- Collapsible Pattern Studio for source/result focused work.

## Engine Constraints

- The fast path uses Rust's `regex` crate.
- Patterns that need constructs unsupported by `regex`, such as lookaround, fall back to `fancy-regex`.
- File and folder scans are line-based for speed and memory safety.
- Dot All and true cross-line matching require editor-backed text.

## Follow-Up Work

- Job history and rerun support.
- CSV export for named capture groups.
- Context windows around each result.
- More configurable directory filters.
- Signed release pipeline credentials.
- Optional memory-mapped strategies for selected file types.
