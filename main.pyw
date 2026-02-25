"""Regex Isolator - A GUI tool for testing and extracting regex matches."""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import re
import os
import tempfile
import json


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
        self.live_matching = tk.BooleanVar(value=True)
        self.cached_input_path = None
        self.cached_input_chars = 0
        self.custom_presets = {}

        self._build_ui()
        self._load_custom_presets()
        self._refresh_preset_values()
        self._bind_events()
        self._check_paste_button()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

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
        ("Video src URL",  r'(?<=\bsrc=")[^"]+\.(?:mp4|webm|ogg|ogv|mov|m4v|avi|mkv)(?:\?[^"]*)?(?=")'),
        ("Image src URL",  r'(?<=\bsrc=")[^"]+\.(?:png|jpe?g|gif|webp|svg)(?:\?[^"]*)?(?=")'),
        ("Link href URL",  r'(?<=\bhref=")[^"]+(?=")'),
        ("Domain",         r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"),
        ("UUID",           r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
        ("ISO 8601 DateTime", r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})\b"),
        ("Hashtag",        r"(?<!\w)#\w+"),
        ("@Mention",       r"(?<!\w)@[A-Za-z0-9_]+"),
        ("MAC Address",    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        ("IPv4 Address",   r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        ("Phone (US)",     r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
        ("Hex Color",      r"#(?:[0-9a-fA-F]{3}){1,2}\b"),
        ("Date (YYYY-MM-DD)", r"\d{4}-\d{2}-\d{2}"),
        ("HTML Tag",       r"<[^>]+>"),
        ("Integer",        r"-?\d+"),
        ("Decimal Number", r"-?\d+\.\d+"),
    ]

    _LARGE_TEXT_THRESHOLD = 300_000
    _HIGHLIGHT_MAX_CHARS = 200_000
    _OUTPUT_MAX_MATCHES = 5000
    _PRESET_PLACEHOLDER = "— Presets —"
    _CUSTOM_SECTION_LABEL = "— Custom Presets —"
    _PRESET_FILE = ".regex_isolator_presets.json"

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

        self.preset_var = tk.StringVar(value=self._PRESET_PLACEHOLDER)
        self.preset_combo = ttk.Combobox(frame, textvariable=self.preset_var,
                                         values=[self._PRESET_PLACEHOLDER],
                                         state="readonly", width=20)
        self.preset_combo.grid(row=1, column=2, sticky="w", padx=5, pady=(5, 0))
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        ttk.Label(frame, text="Preset Name:").grid(row=1, column=3, sticky="e", padx=(5, 5), pady=(5, 0))
        self.preset_name_entry = ttk.Entry(frame, width=18)
        self.preset_name_entry.grid(row=1, column=4, sticky="w", pady=(5, 0))

        ttk.Button(frame, text="Save Preset", command=self._save_named_preset).grid(
            row=2, column=2, sticky="w", padx=5, pady=(4, 0)
        )
        ttk.Button(frame, text="Delete Preset", command=self._delete_named_preset).grid(
            row=2, column=3, sticky="w", padx=5, pady=(4, 0)
        )

        # Row 3 — inline replacement preview + copy button
        self.replace_preview_label = ttk.Label(frame, text="", foreground="#555555",
                                               font=("Segoe UI", 9))
        self.replace_preview_label.grid(row=3, column=0, columnspan=4, sticky="w",
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

        ttk.Checkbutton(header, text="Live matching", variable=self.live_matching,
                command=self._on_live_toggle).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(header, text="Match", command=self._run_match).pack(side=tk.LEFT, padx=(8, 0))

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
            ("Cache Input", self._cache_input),
            ("Restore Cached", self._restore_cached_input),
        ]:
            ttk.Button(bar, text=label, command=cmd).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(bar, text="Help", command=self._show_help).pack(side=tk.RIGHT)

    # ── Event bindings ───────────────────────────────────────────────

    def _on_preset_selected(self, _event=None):
        """Populate the regex entry from the chosen preset."""
        name = self.preset_var.get()
        if name in (self._PRESET_PLACEHOLDER, self._CUSTOM_SECTION_LABEL):
            return

        if name in self.custom_presets:
            self._apply_custom_preset(name)
            self.preset_name_entry.delete(0, tk.END)
            self.preset_name_entry.insert(0, name)
            self.status_label.config(text=f"Loaded preset '{name}'", foreground="green")
            return

        for label, pattern in self._PRESETS:
            if label == name and pattern:
                self.regex_entry.delete(0, tk.END)
                self.regex_entry.insert(0, pattern)
                self._on_content_change()
                self.status_label.config(text=f"Loaded built-in preset '{name}'", foreground="green")
                break

    def _get_preset_file_path(self):
        """Return on-disk path used for custom preset storage."""
        return os.path.join(os.path.expanduser("~"), self._PRESET_FILE)

    def _load_custom_presets(self):
        """Load custom presets from disk if available."""
        path = self._get_preset_file_path()
        try:
            if not os.path.exists(path):
                self.custom_presets = {}
                return
            with open(path, "r", encoding="utf-8") as file_obj:
                raw = json.load(file_obj)
            if isinstance(raw, dict):
                self.custom_presets = {
                    str(name): value
                    for name, value in raw.items()
                    if isinstance(name, str) and isinstance(value, dict)
                }
            else:
                self.custom_presets = {}
        except (OSError, json.JSONDecodeError):
            self.custom_presets = {}

    def _save_custom_presets(self):
        """Persist custom presets to disk."""
        path = self._get_preset_file_path()
        with open(path, "w", encoding="utf-8") as file_obj:
            json.dump(self.custom_presets, file_obj, indent=2)

    def _refresh_preset_values(self):
        """Refresh preset combobox values with built-ins and custom names."""
        values = [self._PRESET_PLACEHOLDER]
        values.extend([name for name, pattern in self._PRESETS if pattern])
        custom_names = sorted(self.custom_presets.keys(), key=str.lower)
        if custom_names:
            values.append(self._CUSTOM_SECTION_LABEL)
            values.extend(custom_names)
        self.preset_combo["values"] = values
        if self.preset_var.get() not in values:
            self.preset_var.set(self._PRESET_PLACEHOLDER)

    def _current_preset_payload(self):
        """Capture current settings into a serializable preset payload."""
        return {
            "pattern": self.regex_entry.get(),
            "replace": self.replace_entry.get(),
            "ignore_case": self.ignore_case.get(),
            "multiline": self.multiline.get(),
            "dotall": self.dotall.get(),
            "unique": self.unique_matches.get(),
            "delimiter": self.delimiter_var.get(),
            "live_matching": self.live_matching.get(),
        }

    def _apply_custom_preset(self, name):
        """Apply a saved custom preset by name."""
        payload = self.custom_presets.get(name, {})
        self.regex_entry.delete(0, tk.END)
        self.regex_entry.insert(0, payload.get("pattern", ""))

        self.replace_entry.delete(0, tk.END)
        self.replace_entry.insert(0, payload.get("replace", ""))

        self.ignore_case.set(bool(payload.get("ignore_case", False)))
        self.multiline.set(bool(payload.get("multiline", False)))
        self.dotall.set(bool(payload.get("dotall", False)))
        self.unique_matches.set(bool(payload.get("unique", False)))
        self.delimiter_var.set(payload.get("delimiter", "Newline"))
        self.live_matching.set(bool(payload.get("live_matching", True)))
        self._on_live_toggle()
        self._on_content_change()

    def _save_named_preset(self):
        """Save current settings under the provided custom preset name."""
        name = self.preset_name_entry.get().strip()
        if not name:
            self.status_label.config(text="Enter a preset name to save", foreground="orange")
            return

        builtin_names = {label for label, pattern in self._PRESETS if pattern}
        if name in builtin_names:
            self.status_label.config(text="Preset name conflicts with a built-in preset", foreground="red")
            return
        if name in (self._PRESET_PLACEHOLDER, self._CUSTOM_SECTION_LABEL):
            self.status_label.config(text="Choose a different preset name", foreground="red")
            return

        self.custom_presets[name] = self._current_preset_payload()
        try:
            self._save_custom_presets()
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to save preset:\n{exc}")
            self.status_label.config(text="Preset save failed", foreground="red")
            return

        self._refresh_preset_values()
        self.preset_var.set(name)
        self.status_label.config(text=f"Saved preset '{name}'", foreground="green")

    def _delete_named_preset(self):
        """Delete a custom preset by name."""
        typed_name = self.preset_name_entry.get().strip()
        selected_name = self.preset_var.get()
        name = typed_name or (selected_name if selected_name in self.custom_presets else "")

        if not name:
            self.status_label.config(text="Enter or select a custom preset to delete", foreground="orange")
            return
        if name not in self.custom_presets:
            self.status_label.config(text=f"No custom preset named '{name}'", foreground="orange")
            return

        if not messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            return

        del self.custom_presets[name]
        try:
            self._save_custom_presets()
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to delete preset:\n{exc}")
            self.status_label.config(text="Preset delete failed", foreground="red")
            return

        self._refresh_preset_values()
        self.preset_name_entry.delete(0, tk.END)
        self.status_label.config(text=f"Deleted preset '{name}'", foreground="green")

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
        if not self.live_matching.get():
            if self.update_timer:
                self.root.after_cancel(self.update_timer)
                self.update_timer = None
            self.status_label.config(text="Live matching off — press Match", foreground="gray")
            return

        if self.update_timer:
            self.root.after_cancel(self.update_timer)
        self.update_timer = self.root.after(300, self._process)

    def _on_live_toggle(self):
        """Switch between automatic debounced matching and manual matching."""
        if self.live_matching.get():
            self.status_label.config(text="Live matching on", foreground="green")
            self._on_content_change()
            return

        if self.update_timer:
            self.root.after_cancel(self.update_timer)
            self.update_timer = None
        self.status_label.config(text="Live matching off — press Match", foreground="gray")

    def _run_match(self):
        """Run matching immediately regardless of live-matching mode."""
        if self.update_timer:
            self.root.after_cancel(self.update_timer)
            self.update_timer = None
        self._process()

    # ── Core regex processing ────────────────────────────────────────

    def _process(self):
        """Run the regex against the input and update highlights + output."""
        pattern_str = self.regex_entry.get().strip()
        text, text_source = self._get_active_text()

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

        # Highlight every match in the input pane + build match strings in one pass
        self.match_positions.clear()
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)

        processed = []
        total_count = 0
        group_count = pattern.groups
        can_highlight = text_source == "input" and len(text) <= self._HIGHLIGHT_MAX_CHARS
        output_limit_reached = False

        for m in pattern.finditer(text):
            total_count += 1

            if can_highlight:
                self.match_positions.append((m.start(), m.end()))
                self.input_text.tag_add("highlight",
                                        f"1.0 + {m.start()} chars",
                                        f"1.0 + {m.end()} chars")

            if group_count == 0:
                value = m.group(0)
            elif group_count == 1:
                value = m.group(1) or ""
            else:
                value = "".join(g for g in m.groups() if g)

            if len(processed) < self._OUTPUT_MAX_MATCHES:
                processed.append(value)
            else:
                output_limit_reached = True

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

            if output_limit_reached:
                self.output_text.insert(
                    tk.END,
                    f"\n\n(Output capped at first {self._OUTPUT_MAX_MATCHES} matches)",
                )

            # Clickable tags only make sense in newline mode
            if delimiter == "\n" and can_highlight:
                for i in range(len(processed)):
                    tag = f"match_{i}"
                    self.output_text.tag_add(tag, f"{i + 1}.0", f"{i + 1}.end")
                    self.output_text.tag_config(tag, foreground="blue")

            unique_note = f", {len(processed)} unique" if self.unique_matches.get() else ""
            source_note = " (cached input)" if text_source == "cache" else ""
            self.match_count_label.config(text=f"({total_count} matches{unique_note})")
            if can_highlight:
                self.status_label.config(text=f"Found {total_count} match(es){source_note}",
                                         foreground="green")
            else:
                self.status_label.config(
                    text=f"Found {total_count} match(es){source_note} — highlighting disabled for large text",
                    foreground="green",
                )
        else:
            self.output_text.insert("1.0", "(No matches found)")
            self.status_label.config(text="No matches found", foreground="orange")

        self.output_text.config(state="disabled")

        # Update replacement preview
        self._update_replace_preview(pattern, text, total_count)

    # ── Replacement preview ───────────────────────────────────────────

    def _update_replace_preview(self, pattern, text, match_count):
        """Update the inline replacement preview label."""
        repl = self.replace_entry.get()
        if not repl:
            self.replace_preview_label.config(text="")
            self.replace_copy_btn.grid_remove()
            self._replace_result = ""
            return

        if len(text) > self._LARGE_TEXT_THRESHOLD:
            self.replace_preview_label.config(
                text="Preview disabled for large input (use Copy Result to run replacement)",
                foreground="#555555",
            )
            self.replace_copy_btn.grid_remove()
            self._replace_result = ""
            return

        try:
            result = pattern.sub(repl, text)
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
        noun = "replacement" if match_count == 1 else "replacements"
        self.replace_preview_label.config(
            text=f'Preview ({match_count} {noun}): "{preview}"',
            foreground="#555555",
        )
        self.replace_copy_btn.grid(row=3, column=4, sticky="w", padx=(5, 0), pady=(2, 0))

    def _copy_replace_result(self):
        """Copy the full replacement result to the clipboard."""
        if self._replace_result:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._replace_result)
            self.status_label.config(text="Replacement result copied to clipboard",
                                     foreground="green")
            return

        repl = self.replace_entry.get()
        if not repl:
            self.status_label.config(text="No replacement pattern set", foreground="orange")
            return

        pattern_str = self.regex_entry.get().strip()
        text, _ = self._get_active_text()
        if not pattern_str or not text:
            self.status_label.config(text="Need pattern and input text", foreground="orange")
            return

        flags = 0
        if self.ignore_case.get():
            flags |= re.IGNORECASE
        if self.multiline.get():
            flags |= re.MULTILINE
        if self.dotall.get():
            flags |= re.DOTALL

        try:
            pattern = re.compile(pattern_str, flags)
            result = pattern.sub(repl, text)
        except re.error as exc:
            self.status_label.config(text=f"Replacement error: {exc}", foreground="red")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self.status_label.config(text="Replacement result copied to clipboard", foreground="green")

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
            self._clear_cached_input_file()
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
                self._clear_cached_input_file()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert("1.0", content)
                self.status_label.config(text=f"Loaded {path}", foreground="green")
                self._on_content_change()
            except OSError as exc:
                messagebox.showerror("Error", f"Failed to load file:\n{exc}")
                self.status_label.config(text="Load failed", foreground="red")

    def _cache_input(self):
        """Move current input text into a temp file cache and unload textbox content."""
        text = self.input_text.get("1.0", "end-1c")
        if not text:
            self.status_label.config(text="No input text to cache", foreground="orange")
            return

        self._clear_cached_input_file()

        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False, suffix=".regex-isolator-cache.txt"
            ) as tmp:
                tmp.write(text)
                self.cached_input_path = tmp.name
        except OSError as exc:
            self.status_label.config(text=f"Cache failed: {exc}", foreground="red")
            return

        self.cached_input_chars = len(text)
        self.input_text.delete("1.0", tk.END)
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self.match_positions.clear()
        self._check_paste_button()
        self.live_matching.set(False)
        self.status_label.config(
            text=f"Input cached ({self.cached_input_chars:,} chars). Press Match to process.",
            foreground="green",
        )

    def _restore_cached_input(self):
        """Restore cached text back into the input textbox."""
        if not self.cached_input_path:
            self.status_label.config(text="No cached input to restore", foreground="orange")
            return

        try:
            with open(self.cached_input_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as exc:
            self.status_label.config(text=f"Restore failed: {exc}", foreground="red")
            return

        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", content)
        self._clear_cached_input_file()
        self._check_paste_button()
        self.status_label.config(text="Restored cached input", foreground="green")
        self._on_content_change()

    def _get_active_text(self):
        """Return active input text and source ('input' or 'cache')."""
        text = self.input_text.get("1.0", "end-1c")
        if text:
            return text, "input"

        if self.cached_input_path:
            try:
                with open(self.cached_input_path, "r", encoding="utf-8") as f:
                    return f.read(), "cache"
            except OSError:
                self._clear_cached_input_file()

        return "", "input"

    def _clear_cached_input_file(self):
        """Delete and forget the current cache file if it exists."""
        if self.cached_input_path:
            try:
                os.remove(self.cached_input_path)
            except OSError:
                pass
        self.cached_input_path = None
        self.cached_input_chars = 0

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
        self.preset_var.set(self._PRESET_PLACEHOLDER)
        self.preset_name_entry.delete(0, tk.END)
        self.replace_preview_label.config(text="")
        self.replace_copy_btn.grid_remove()
        self._replace_result = ""
        self._clear_cached_input_file()
        self.status_label.config(text="Cleared", foreground="green")

    def _on_close(self):
        """Clean up temporary cache files before exiting."""
        self._clear_cached_input_file()
        self.root.destroy()


def main():
    root = tk.Tk()
    RegexIsolatorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
