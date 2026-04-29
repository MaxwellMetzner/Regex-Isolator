# Tauri + Rust Architecture

Regex Isolator now uses Tauri 2 for the desktop shell, React for the interface, and Rust for scanning, transformation, and export work.

## Why This Stack

- Tauri keeps the desktop footprint much smaller than Electron.
- React keeps the UI easier to evolve than the former native widget app.
- Rust owns the large-file path, cancellation checks, directory traversal, JSONL serialization, and text transforms.
- The hybrid regex path keeps common patterns fast while preserving advanced constructs through `fancy-regex`.

## Active Architecture

1. **Rust scanner module**
   - editor scans
   - file and folder scans
   - match extraction
   - cleaned-output writing
   - replacement preview/copy
   - JSONL and text output

2. **Tauri command layer**
   - source file loading
   - scan commands
   - background jobs and cancellation
   - save/export commands
   - progress events

3. **React frontend**
   - collapsible Pattern Studio
   - source and result panes
   - preset library
   - regex help/reference
   - transform and export controls

## Performance Rules

- Keep large files on disk and scan line by line.
- Prefer the fast `regex` crate whenever the pattern supports it.
- Fall back to `fancy-regex` only when needed for compatibility.
- Keep preview output capped; stream full exports directly to disk.
- Block Dot All in line mode, including inline `(?s)` flags, because true cross-line matching is an editor-mode operation.

## Next Engineering Targets

- Directory include/exclude filters.
- Named-capture CSV export.
- Result context windows.
- Saved job history.
- Release signing and installer polish.
