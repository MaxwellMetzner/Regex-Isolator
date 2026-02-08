"""Regex Isolator - A GUI tool for testing and extracting regex matches."""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import re


class RegexIsolatorApp:
    """Main application window for testing regex patterns against input text.

    Features:
        - Live regex matching with debounced updates
        - Match highlighting in the input text
        - Click-to-jump from output matches to their input positions
        - Regex flag toggles (ignore case, multiline, dot-all)
        - Clipboard paste/copy and file load/save
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Regex Isolator")
        self.root.geometry("900x700")

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.update_timer = None
        self.match_positions = []

        self._build_ui()
        self._bind_events()
        self._check_paste_button()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self):
        """Build all UI elements."""
        main = ttk.Frame(self.root, padding="10")
        main.grid(row=0, column=0, sticky="nsew")
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=1)

        self._build_regex_bar(main)
        self._build_input_panel(main)
        self._build_output_panel(main)
        self._build_button_bar(main)

        self.status_label = ttk.Label(main, text="Ready", foreground="green")
        self.status_label.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))

    # Common regex presets: (display name, pattern)
    _PRESETS = [
        ("— Presets —",    ""),
        ("Email",          r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        ("URL",            r"https?://[^\s/$.?#].[^\s]*"),
        ("IPv4 Address",   r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        ("Phone (US)",     r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
        ("Hex Color",      r"#(?:[0-9a-fA-F]{3}){1,2}\b"),
        ("Date (YYYY-MM-DD)", r"\d{4}-\d{2}-\d{2}"),
        ("HTML Tag",       r"<[^>]+>"),
        ("Integer",        r"-?\d+"),
        ("Decimal Number", r"-?\d+\.\d+"),
    ]

    def _build_regex_bar(self, parent):
        """Regex entry, replacement entry, presets dropdown, and flag checkboxes."""
        frame = ttk.Frame(parent)
        frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        frame.grid_columnconfigure(1, weight=1)

        # Row 0 — pattern + flags
        ttk.Label(frame, text="Regex Pattern:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.regex_entry = ttk.Entry(frame, width=50)
        self.regex_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        self.ignore_case = tk.BooleanVar()
        self.multiline = tk.BooleanVar()
        self.dotall = tk.BooleanVar()

        ttk.Checkbutton(frame, text="Ignore Case", variable=self.ignore_case,
                        command=self._on_content_change).grid(row=0, column=2, padx=5)
        ttk.Checkbutton(frame, text="Multiline", variable=self.multiline,
                        command=self._on_content_change).grid(row=0, column=3, padx=5)
        ttk.Checkbutton(frame, text="Dot All", variable=self.dotall,
                        command=self._on_content_change).grid(row=0, column=4, padx=5)

        # Row 1 — replacement string + presets dropdown
        ttk.Label(frame, text="Replace With:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(5, 0))
        self.replace_entry = ttk.Entry(frame, width=50)
        self.replace_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(5, 0))
        self.replace_entry.bind("<KeyRelease>", self._on_content_change)

        self.preset_var = tk.StringVar(value=self._PRESETS[0][0])
        preset_combo = ttk.Combobox(frame, textvariable=self.preset_var,
                                    values=[p[0] for p in self._PRESETS],
                                    state="readonly", width=20)
        preset_combo.grid(row=1, column=2, columnspan=3, sticky="w", padx=5, pady=(5, 0))
        preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # Row 2 — inline replacement preview + copy button
        self.replace_preview_label = ttk.Label(frame, text="", foreground="#555555",
                                               font=("Segoe UI", 9))
        self.replace_preview_label.grid(row=2, column=0, columnspan=4, sticky="w",
                                        padx=(0, 5), pady=(2, 0))
        self.replace_copy_btn = ttk.Button(frame, text="Copy Result",
                                           command=self._copy_replace_result)
        # Hidden initially; shown when there's a replacement preview
        self._replace_result = ""

    def _build_input_panel(self, parent):
        """Left column: input text area with a centered paste-button overlay."""
        ttk.Label(parent, text="Input Text:").grid(row=1, column=0, sticky="w", pady=(0, 5))

        container = ttk.Frame(parent)
        container.grid(row=2, column=0, sticky="nsew", padx=(0, 5))
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.input_text = scrolledtext.ScrolledText(container, wrap=tk.WORD, height=20)
        self.input_text.grid(row=0, column=0, sticky="nsew")

        self.paste_button = ttk.Button(container, text="📋 Paste from Clipboard",
                                       command=self._paste_from_clipboard)

        self.input_text.tag_config("highlight", background="yellow", foreground="black")
        self.input_text.tag_config("selected_match", background="orange", foreground="black")

    def _build_output_panel(self, parent):
        """Right column: read-only output text area with match count, unique toggle, and delimiter."""
        header = ttk.Frame(parent)
        header.grid(row=1, column=1, sticky="ew", pady=(0, 5))

        ttk.Label(header, text="Matches:").pack(side=tk.LEFT)
        self.match_count_label = ttk.Label(header, text="", foreground="blue")
        self.match_count_label.pack(side=tk.LEFT, padx=(5, 0))

        # Unique-matches toggle
        self.unique_matches = tk.BooleanVar()
        ttk.Checkbutton(header, text="Unique", variable=self.unique_matches,
                        command=self._on_content_change).pack(side=tk.LEFT, padx=(10, 0))

        # Output delimiter selector
        ttk.Label(header, text="Delim:").pack(side=tk.LEFT, padx=(10, 0))
        self.delimiter_var = tk.StringVar(value="Newline")
        delim_combo = ttk.Combobox(header, textvariable=self.delimiter_var,
                                   values=["Newline", "Comma", "Tab", "Space"],
                                   state="readonly", width=8)
        delim_combo.pack(side=tk.LEFT, padx=(3, 0))
        delim_combo.bind("<<ComboboxSelected>>", self._on_content_change)

        self.output_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, height=20,
                                                     state="disabled", cursor="hand2")
        self.output_text.grid(row=2, column=1, sticky="nsew", padx=(5, 0))

    def _build_button_bar(self, parent):
        """Bottom action buttons."""
        bar = ttk.Frame(parent)
        bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        for label, cmd in [
            ("Copy to Clipboard", self._copy_to_clipboard),
            ("Save to File", self._save_to_file),
            ("Clear All", self._clear_all),
            ("Load from File", self._load_from_file),
        ]:
            ttk.Button(bar, text=label, command=cmd).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(bar, text="Help", command=self._show_help).pack(side=tk.RIGHT)

    # ── Event bindings ───────────────────────────────────────────────

    def _on_preset_selected(self, _event=None):
        """Populate the regex entry from the chosen preset."""
        name = self.preset_var.get()
        for label, pattern in self._PRESETS:
            if label == name and pattern:
                self.regex_entry.delete(0, tk.END)
                self.regex_entry.insert(0, pattern)
                self._on_content_change()
                break
        # Reset combo display text so the same preset can be re-selected
        self.preset_var.set(self._PRESETS[0][0])

    def _bind_events(self):
        """Wire up keyboard and mouse events."""
        self.regex_entry.bind("<KeyRelease>", self._on_content_change)
        self.input_text.bind("<KeyRelease>", self._on_input_change)
        self.input_text.bind("<FocusIn>", self._check_paste_button)
        self.input_text.bind("<FocusOut>", self._check_paste_button)
        self.output_text.bind("<Button-1>", self._on_output_click)

    def _check_paste_button(self, _event=None):
        """Show a centered paste button when the input area is empty."""
        if self.input_text.get("1.0", tk.END).strip():
            self.paste_button.place_forget()
        else:
            self.paste_button.place(relx=0.5, rely=0.5, anchor="center")

    def _on_input_change(self, event=None):
        """Respond to input text edits (also refreshes the paste button)."""
        self._check_paste_button()
        self._on_content_change(event)

    def _on_content_change(self, _event=None):
        """Debounce content changes - waits 300 ms of inactivity before processing."""
        if self.update_timer:
            self.root.after_cancel(self.update_timer)
        self.update_timer = self.root.after(300, self._process)

    # ── Core regex processing ────────────────────────────────────────

    def _process(self):
        """Run the regex against the input and update highlights + output."""
        pattern_str = self.regex_entry.get().strip()
        text = self.input_text.get("1.0", tk.END).strip()

        # Reset output
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.match_count_label.config(text="")

        if not pattern_str:
            self.input_text.tag_remove("highlight", "1.0", tk.END)
            self.status_label.config(text="Enter a regex pattern to begin", foreground="gray")
            self.output_text.config(state="disabled")
            return

        if not text:
            self.status_label.config(text="Enter text to search", foreground="gray")
            self.output_text.config(state="disabled")
            return

        # Combine selected flags
        flags = 0
        if self.ignore_case.get():
            flags |= re.IGNORECASE
        if self.multiline.get():
            flags |= re.MULTILINE
        if self.dotall.get():
            flags |= re.DOTALL

        try:
            pattern = re.compile(pattern_str, flags)
        except re.error as exc:
            self.input_text.tag_remove("highlight", "1.0", tk.END)
            self.output_text.config(state="disabled")
            self.status_label.config(text=f"Invalid regex: {exc}", foreground="red")
            return

        # Highlight every match in the input pane
        self.match_positions.clear()
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)

        for m in pattern.finditer(text):
            self.match_positions.append((m.start(), m.end()))
            self.input_text.tag_add("highlight",
                                    f"1.0 + {m.start()} chars",
                                    f"1.0 + {m.end()} chars")

        # Build the output list (collapse capture-group tuples into strings)
        raw_matches = pattern.findall(text)
        processed = []
        for match in raw_matches:
            if isinstance(match, tuple):
                processed.append("".join(s for s in match if s))
            else:
                processed.append(str(match))

        total_count = len(processed)

        # Optionally deduplicate while preserving order
        if self.unique_matches.get():
            seen = set()
            unique = []
            for m in processed:
                if m not in seen:
                    seen.add(m)
                    unique.append(m)
            processed = unique

        # Determine output delimiter
        delim_map = {"Newline": "\n", "Comma": ", ", "Tab": "\t", "Space": " "}
        delimiter = delim_map.get(self.delimiter_var.get(), "\n")

        if processed:
            self.output_text.insert("1.0", delimiter.join(processed))

            # Clickable tags only make sense in newline mode
            if delimiter == "\n":
                for i in range(len(processed)):
                    tag = f"match_{i}"
                    self.output_text.tag_add(tag, f"{i + 1}.0", f"{i + 1}.end")
                    self.output_text.tag_config(tag, foreground="blue")

            unique_note = f", {len(processed)} unique" if self.unique_matches.get() else ""
            self.match_count_label.config(text=f"({total_count} matches{unique_note})")
            self.status_label.config(text=f"Found {total_count} match(es)", foreground="green")
        else:
            self.output_text.insert("1.0", "(No matches found)")
            self.status_label.config(text="No matches found", foreground="orange")

        self.output_text.config(state="disabled")

        # Update replacement preview
        self._update_replace_preview(pattern, text)

    # ── Replacement preview ───────────────────────────────────────────

    def _update_replace_preview(self, pattern, text):
        """Update the inline replacement preview label."""
        repl = self.replace_entry.get()
        if not repl:
            self.replace_preview_label.config(text="")
            self.replace_copy_btn.grid_remove()
            self._replace_result = ""
            return

        try:
            result = pattern.sub(repl, text)
            count = len(pattern.findall(text))
        except re.error as exc:
            self.replace_preview_label.config(text=f"Replacement error: {exc}",
                                             foreground="red")
            self.replace_copy_btn.grid_remove()
            self._replace_result = ""
            return

        self._replace_result = result

        # Build a truncated preview string
        preview = result.replace("\n", " ")
        if len(preview) > 80:
            preview = preview[:80] + "…"
        noun = "replacement" if count == 1 else "replacements"
        self.replace_preview_label.config(
            text=f'Preview ({count} {noun}): "{preview}"',
            foreground="#555555",
        )
        self.replace_copy_btn.grid(row=2, column=4, sticky="w", padx=(5, 0), pady=(2, 0))

    def _copy_replace_result(self):
        """Copy the full replacement result to the clipboard."""
        if self._replace_result:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._replace_result)
            self.status_label.config(text="Replacement result copied to clipboard",
                                     foreground="green")

    # ── Click-to-jump ────────────────────────────────────────────────

    def _on_output_click(self, event):
        """Jump to the corresponding match in the input when an output line is clicked."""
        try:
            index = self.output_text.index(f"@{event.x},{event.y}")
            line = int(index.split(".")[0]) - 1
            if 0 <= line < len(self.match_positions):
                self._jump_to_match(line)
        except (ValueError, tk.TclError):
            pass

    def _jump_to_match(self, idx):
        """Scroll the input pane to match *idx* and apply a selection highlight."""
        start, end = self.match_positions[idx]
        start_idx = f"1.0 + {start} chars"

        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self.input_text.tag_add("selected_match", start_idx, f"1.0 + {end} chars")
        self.input_text.tag_raise("selected_match")
        self.input_text.see(start_idx)
        self.input_text.mark_set("insert", start_idx)

        self.status_label.config(
            text=f"Jumped to match {idx + 1} of {len(self.match_positions)}",
            foreground="green",
        )

    # ── Clipboard helpers (tkinter-native, no external deps) ─────────

    def _paste_from_clipboard(self):
        """Paste clipboard contents into the input area."""
        try:
            content = self.root.clipboard_get()
        except tk.TclError:
            self.status_label.config(text="Clipboard is empty", foreground="orange")
            return

        if content:
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", content)
            self._check_paste_button()
            self._on_content_change()
            self.status_label.config(text="Pasted from clipboard", foreground="green")

    def _copy_to_clipboard(self):
        """Copy the output matches to the system clipboard."""
        content = self.output_text.get("1.0", tk.END).strip()
        if not content or content == "(No matches found)":
            messagebox.showwarning("Warning", "No content to copy to clipboard")
            self.status_label.config(text="Nothing to copy", foreground="red")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_label.config(text="Copied to clipboard", foreground="green")

    # ── File I/O ─────────────────────────────────────────────────────

    def _save_to_file(self):
        """Save output matches to a user-chosen text file."""
        content = self.output_text.get("1.0", tk.END).strip()
        if not content or content == "(No matches found)":
            messagebox.showwarning("Warning", "No content to save")
            self.status_label.config(text="Nothing to save", foreground="red")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.status_label.config(text=f"Saved to {path}", foreground="green")
            except OSError as exc:
                messagebox.showerror("Error", f"Failed to save file:\n{exc}")
                self.status_label.config(text="Save failed", foreground="red")

    def _load_from_file(self):
        """Load a text file into the input area."""
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert("1.0", content)
                self.status_label.config(text=f"Loaded {path}", foreground="green")
                self._on_content_change()
            except OSError as exc:
                messagebox.showerror("Error", f"Failed to load file:\n{exc}")
                self.status_label.config(text="Load failed", foreground="red")

    # ── Help window ──────────────────────────────────────────────────

    _HELP_SECTIONS = [
        ("Characters", [
            (r".",        "Any character except newline (all chars if Dot All)"),
            (r"\d",      "Digit [0-9]"),
            (r"\D",      "Non-digit"),
            (r"\w",      "Word character [a-zA-Z0-9_]"),
            (r"\W",      "Non-word character"),
            (r"\s",      "Whitespace (space, tab, newline …)"),
            (r"\S",      "Non-whitespace"),
            (r"\b",      "Word boundary"),
        ]),
        ("Quantifiers", [
            ("*",        "0 or more"),
            ("+",        "1 or more"),
            ("?",        "0 or 1 (optional)"),
            ("{n}",      "Exactly n"),
            ("{n,}",     "n or more"),
            ("{n,m}",    "Between n and m"),
            ("*? +? ??", "Non-greedy versions"),
        ]),
        ("Groups & References", [
            ("(…)",       "Capturing group"),
            ("(?:…)",     "Non-capturing group"),
            ("(?P<n>…)",  "Named group"),
            (r"\1, \2",  "Back-reference to group 1, 2 …"),
            ("(a|b)",     "Alternation (a or b)"),
        ]),
        ("Anchors", [
            ("^",   "Start of string (or line in Multiline)"),
            ("$",   "End of string (or line in Multiline)"),
            (r"\A", "Start of string (ignores Multiline)"),
            (r"\Z", "End of string (ignores Multiline)"),
        ]),
        ("Character Classes", [
            ("[abc]",   "a, b, or c"),
            ("[^abc]",  "Not a, b, or c"),
            ("[a-z]",   "Range a to z"),
            ("[a-zA-Z]", "Any letter"),
        ]),
        ("Lookaround", [
            ("(?=…)",   "Positive lookahead"),
            ("(?!…)",   "Negative lookahead"),
            ("(?<=…)",  "Positive lookbehind"),
            ("(?<!…)",  "Negative lookbehind"),
        ]),
        ("Flags (checkbox equivalents)", [
            ("Ignore Case", "re.IGNORECASE — case-insensitive matching"),
            ("Multiline",   "re.MULTILINE  — ^ and $ match each line"),
            ("Dot All",     "re.DOTALL     — . matches newline too"),
        ]),
    ]

    def _show_help(self):
        """Open (or focus) a non-modal window with a regex syntax reference."""
        # If the window already exists, just bring it to front
        if hasattr(self, "_help_win") and self._help_win.winfo_exists():
            self._help_win.lift()
            self._help_win.focus_set()
            return

        win = tk.Toplevel(self.root)
        win.title("Regex Syntax Reference")
        win.geometry("480x560")
        win.resizable(True, True)
        self._help_win = win

        text = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10),
                                         padx=10, pady=10, state="normal",
                                         cursor="arrow")
        text.pack(fill=tk.BOTH, expand=True)

        # Tag styles
        text.tag_config("heading", font=("Segoe UI", 12, "bold"), spacing3=4)
        text.tag_config("syntax",  font=("Consolas", 10, "bold"), foreground="#0055aa")
        text.tag_config("desc",    font=("Segoe UI", 10))
        text.tag_config("sep",     font=("Segoe UI", 2))

        for section, items in self._HELP_SECTIONS:
            text.insert(tk.END, f"{section}\n", "heading")
            for syntax, desc in items:
                text.insert(tk.END, f"  {syntax:<14}", "syntax")
                text.insert(tk.END, f"  {desc}\n", "desc")
            text.insert(tk.END, "\n", "sep")

        text.config(state="disabled")  # read-only

    # ── Misc ─────────────────────────────────────────────────────────

    def _clear_all(self):
        """Reset every field to its default empty state."""
        self.regex_entry.delete(0, tk.END)
        self.replace_entry.delete(0, tk.END)
        self.input_text.delete("1.0", tk.END)
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")
        self.match_positions.clear()
        self._check_paste_button()
        self.match_count_label.config(text="")
        self.unique_matches.set(False)
        self.delimiter_var.set("Newline")
        self.replace_preview_label.config(text="")
        self.replace_copy_btn.grid_remove()
        self._replace_result = ""
        self.status_label.config(text="Cleared", foreground="green")


def main():
    root = tk.Tk()
    RegexIsolatorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
