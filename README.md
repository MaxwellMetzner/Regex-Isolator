# Regex Isolator

Regex Isolator is now a single Tauri 2 desktop app with a React frontend and a Rust scanning core.

The application lives in [desktop](desktop). The old Python/Tkinter app has been removed so feature work, packaging, and performance tuning all happen in one place.

## Features

- **Rust-backed regex scanning** with a fast `regex` path and `fancy-regex` fallback for advanced constructs.
- **Editor, large-file, and recursive folder sources** with background progress and cancellation for file-backed scans.
- **Collapsible Pattern Studio** so source and result panes can use nearly the full window.
- **Match preview and structured records** with captures, offsets, lines, columns, file paths, and line previews.
- **JSONL and plain-text exports** for displayed results.
- **Save all matches** to disk, including full file/folder scans beyond the preview cap.
- **Save cleaned output** for editor text or one large file with matches removed.
- **Editor transforms** to keep only matches or delete matches in place.
- **Pattern performance coach** for expensive constructs such as leading wildcards, nested repeats, lookaround, and backreferences.
- **Custom presets and regex help** stored in the desktop app.

## Commands

From the `desktop` folder:

```bash
npm install
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

Portable/release build helpers are documented in [desktop/README.md](desktop/README.md).

## Large File Notes

- Files over 16 MiB are kept on disk and scanned line by line.
- Dot All and true cross-line patterns require editor mode because line mode is designed for gigabyte-scale sources.
- Preview output is capped, but **Save all matches** streams the full output to disk.

## License

MIT
