# Regex Isolator

A lightweight desktop tool for testing regular expressions and extracting matches from text — built with Python's standard library only.

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)

## Features

- **Live/manual matching** — keep live updates on (300 ms debounce) or turn them off and press **Match** manually for large inputs
- **Cache & unload mode** — move huge input into a temp cache file so the textbox stays light; restore it later when needed
- **Match highlighting** — matched regions are highlighted yellow in the input pane
- **Click-to-jump** — click any output line to scroll to that match in the input
- **Regex flags** — toggle Ignore Case, Multiline, and Dot All
- **Named presets** — load built-in regex presets and save/load/delete your own custom named presets
- **Clipboard support** — paste input / copy output via tkinter's native clipboard
- **File I/O** — load input from a file or save matches to a file
- **Zero dependencies** — only uses `tkinter` and `re` from the standard library

## Requirements

- Python 3.8 or newer
- `tkinter` (included with most Python installations; on some Linux distros install `python3-tk`)

No third-party packages are needed.

## Usage

```bash
python main.py
```

1. Enter a regex pattern in the top bar.
2. Optionally type a preset name and click **Save Preset** to store current settings.
2. Paste or type text into the left pane (or click **📋 Paste from Clipboard**).
3. With **Live matching** enabled, matches update as you type; for very large text, disable it and click **Match**.
4. For extremely large text, click **Cache Input** to unload the textbox, then run matches with **Match**.
5. Use **Restore Cached** if you need the full source text back in the input pane.
4. Click a match on the right to jump to it on the left.
5. Use the bottom buttons to copy results, save to file, load input, or clear everything.

## License

MIT
