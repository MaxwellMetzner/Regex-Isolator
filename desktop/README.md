# Regex Isolator Desktop

This is the sole Regex Isolator app: Tauri 2 + React + Rust.

## What Works

- modern desktop UI with a collapsible Pattern Studio
- Rust-backed editor scans
- file-backed large-file scans with progress and cancellation
- recursive folder scans
- hybrid regex engine selection
  - `regex` for the fast path
  - `fancy-regex` fallback for advanced constructs such as lookaround
- pattern preview and performance coaching
- custom presets in local storage
- plain-text output save
- JSONL export
- save all matches from editor, file, or folder sources
- save cleaned output from editor or single-file sources
- keep-only-matches and delete-matches editor transforms
- editor-mode replacement copy with Python-style replacement backreferences
- regex help and large-file guidance

## Commands

From this folder:

```bash
npm install
npm run build
cargo check --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

## Portable Build Output

After the release build, the executable is written to:

```text
desktop/src-tauri/target/release/regex-isolator-desktop.exe
```

The repeatable portable build script stages a copy here:

```text
desktop/artifacts/portable/regex-isolator-desktop.exe
```

Run:

```bash
npm run build:portable
```

## Signing-Ready Flow

The portable build script can sign the executable if these environment variables are present:

```text
SIGNTOOL_PATH
WINDOWS_CERT_THUMBPRINT
WINDOWS_TIMESTAMP_URL
```

Run:

```bash
npm run build:portable:signed
```

If those variables are not present, the script still produces an unsigned portable executable.

## Notes

- Dot All is blocked in file and folder line mode, including inline `(?s)` forms.
- Replacement parity focuses on Python-style backreferences and common escapes used by the previous app.
