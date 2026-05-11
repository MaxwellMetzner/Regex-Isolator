# Regex Isolator Desktop

This folder contains the React/Vite UI and the Tauri 2 + Rust desktop shell for Regex Isolator.

## Commands

```bash
npm install
npm run dev
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

## App Surface

- `src/` contains the React app, panels, browser regex fallback, presets, and regex help data.
- `src-tauri/src/scanner/` contains the Rust scan engine, file/directory jobs, transforms, and export commands.
- `scripts/` contains icon generation and repeatable portable build helpers.

## Build Outputs

Tauri release builds write the executable to:

```text
desktop/src-tauri/target/release/regex-isolator-desktop.exe
```

The portable helper stages a copy here:

```text
desktop/artifacts/portable/regex-isolator-desktop.exe
```

Run:

```bash
npm run build:portable
```

## Signing

The portable build script signs the executable when these variables are set:

```text
SIGNTOOL_PATH
WINDOWS_CERT_THUMBPRINT
WINDOWS_TIMESTAMP_URL
```

Run:

```bash
npm run build:portable:signed
```

Without those variables, the script still produces an unsigned portable executable.

## Scanner Notes

- Editor mode supports full-text matches, source highlighting, result jumps, replacement copy, and source transforms.
- File and directory mode scan one line at a time for memory safety.
- Dot All and inline `(?s)` forms are blocked in line mode because they imply cross-line matching.
- The Rust scanner tries the fast `regex` engine first and falls back to `fancy-regex` when advanced constructs require it.
