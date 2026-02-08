# Regex Isolator

A lightweight desktop tool for testing regular expressions and extracting matches from text — built with Python's standard library only.

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)

## Features

- **Live matching** — results update as you type (300 ms debounce)
- **Match highlighting** — matched regions are highlighted yellow in the input pane
- **Click-to-jump** — click any output line to scroll to that match in the input
- **Regex flags** — toggle Ignore Case, Multiline, and Dot All
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
2. Paste or type text into the left pane (or click **📋 Paste from Clipboard**).
3. Matches appear instantly in the right pane, highlighted in the input.
4. Click a match on the right to jump to it on the left.
5. Use the bottom buttons to copy results, save to file, load input, or clear everything.

## License

MIT
