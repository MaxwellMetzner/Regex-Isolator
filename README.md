# Regex Isolator

Regex Isolator is a compact React regex workbench with a browser runtime and an optional Tauri/Rust shell for large local files.

The application lives in [desktop](desktop).

## Features

- **Browser regex scanning** for the web UI, with a Rust-backed path in the packaged app.
- **Editor and large-file sources** with background progress and cancellation for file-backed scans.
- **Collapsible Pattern Studio** so source and result panes can use nearly the full window.
- **Match preview and structured records** with captures, offsets, lines, columns, file paths, and line previews.
- **JSONL and plain-text exports** for displayed results.
- **Source-side save actions** to save editor text or save a copy with matches removed.
- **Editor transforms** to keep only matches or delete matches in place.
- **Pattern performance coach** for expensive constructs such as leading wildcards, nested repeats, lookaround, and backreferences.
- **Custom presets and regex help** stored locally.

## Commands

From the `desktop` folder:

```bash
npm install
npm run build
npm run dev
cargo check --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

Portable/release build helpers are documented in [desktop/README.md](desktop/README.md).

## Large File Notes

- Files over 16 MiB are kept on disk and scanned line by line.
- Dot All and true cross-line patterns require editor mode because line mode is designed for gigabyte-scale sources.
- Preview output is capped for very large scans; JSONL export preserves the displayed structured rows.

## License

MIT
