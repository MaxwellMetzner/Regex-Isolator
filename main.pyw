"""Regex Isolator - A GUI tool for testing and extracting regex matches."""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter import font as tkfont
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
        self.update_timer = None
        self.match_positions = []
        self.output_click_enabled = False
        self.live_matching = tk.BooleanVar(value=True)
        self.cached_input_path = None
        self.cached_input_chars = 0
        self.file_source_path = None
        self.file_source_size = 0
        self.file_scan_context = None
        self.scan_in_progress = False
        self.scan_generation = 0
        self.result_records = []
        self.custom_presets = {}

        self._configure_window()
        self._build_ui()
        self._load_custom_presets()
        self._refresh_preset_values()
        self._bind_events()
        self._check_paste_button()
        self._sync_live_mode_badge()
        self._update_pattern_coach()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # Common regex presets: (display name, pattern)
    _PRESETS = [
        ("— Presets —", ""),
        ("Email", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        ("URL", r"https?://[^\s/$.?#].[^\s]*"),
        ("Video src URL", r'(?<=\bsrc=")[^"]+\.(?:mp4|webm|ogg|ogv|mov|m4v|avi|mkv)(?:\?[^"]*)?(?=")'),
        ("Image src URL", r'(?<=\bsrc=")[^"]+\.(?:png|jpe?g|gif|webp|svg)(?:\?[^"]*)?(?=")'),
        ("Link href URL", r'(?<=\bhref=")[^"]+(?=")'),
        ("Domain", r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"),
        ("UUID", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
        ("ISO 8601 DateTime", r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})\b"),
        ("Hashtag", r"(?<!\w)#\w+"),
        ("@Mention", r"(?<!\w)@[A-Za-z0-9_]+"),
        ("MAC Address", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        ("IPv4 Address", r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        ("Phone (US)", r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
        ("Hex Color", r"#(?:[0-9a-fA-F]{3}){1,2}\b"),
        ("Date (YYYY-MM-DD)", r"\d{4}-\d{2}-\d{2}"),
        ("HTML Tag", r"<[^>]+>"),
        ("Integer", r"-?\d+"),
        ("Decimal Number", r"-?\d+\.\d+"),
    ]

    _LARGE_TEXT_THRESHOLD = 300_000
    _HIGHLIGHT_MAX_CHARS = 200_000
    _OUTPUT_MAX_MATCHES = 5000
    _EDITOR_LOAD_MAX_BYTES = 16 * 1024 * 1024
    _FILE_SCAN_BATCH_LINES = 1500
    _LIVE_TEXT_MAX_CHARS = 500_000
    _PREVIEW_MAX_CHARS = 180
    _PRESET_PLACEHOLDER = "— Presets —"
    _CUSTOM_SECTION_LABEL = "— Custom Presets —"
    _PRESET_FILE = ".regex_isolator_presets.json"
    _PALETTE = {
        "bg": "#efe6dc",
        "surface": "#fcf7f0",
        "surface_alt": "#f4e8da",
        "hero": "#20343a",
        "hero_muted": "#d2ddd8",
        "text": "#18242b",
        "muted": "#6c6359",
        "border": "#d7c5b3",
        "accent": "#0f766e",
        "accent_dark": "#0b5d57",
        "accent_soft": "#d8efeb",
        "warning": "#a16207",
        "warning_soft": "#fbe5b8",
        "error": "#b42318",
        "error_soft": "#fde5e4",
        "success": "#166534",
        "success_soft": "#dff4e8",
        "editor": "#fffdfa",
        "editor_alt": "#fbf4ea",
        "highlight": "#f7df8a",
        "selected": "#f4b56a",
    }

    def _configure_window(self):
        """Configure root window sizing, palette, fonts, and ttk theme."""
        self.root.title("Regex Isolator")
        self.root.geometry("1240x820")
        self.root.minsize(1080, 720)
        self.root.configure(bg=self._PALETTE["bg"])

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self._font_families = set(tkfont.families(self.root))
        title_family = self._pick_font("Bahnschrift", "Aptos Display", "Trebuchet MS")
        body_family = self._pick_font("Aptos", "Segoe UI", "Arial")
        mono_family = self._pick_font("Cascadia Code", "Consolas", "Courier New")

        self._fonts = {
            "title": (title_family, 24, "bold"),
            "subtitle": (body_family, 11),
            "section": (body_family, 12, "bold"),
            "body": (body_family, 10),
            "body_bold": (body_family, 10, "bold"),
            "caption": (body_family, 9),
            "button": (body_family, 10, "bold"),
            "text": (body_family, 11),
            "mono": (mono_family, 11),
            "mono_bold": (mono_family, 11, "bold"),
            "badge": (body_family, 9, "bold"),
        }
        self._status_colors = {
            "neutral": self._PALETTE["muted"],
            "success": self._PALETTE["success"],
            "warning": self._PALETTE["warning"],
            "error": self._PALETTE["error"],
        }

        self.root.option_add("*Font", self._fonts["body"])
        self.root.option_add("*TCombobox*Listbox*Font", self._fonts["body"])
        self._configure_styles()

    def _pick_font(self, *candidates):
        """Return the first available font family from *candidates*."""
        for family in candidates:
            if family in self._font_families:
                return family
        return "TkDefaultFont"

    def _configure_styles(self):
        """Apply the visual language for frames, labels, inputs, and buttons."""
        palette = self._PALETTE
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", background=palette["bg"], foreground=palette["text"])
        style.configure("App.TFrame", background=palette["bg"])
        style.configure("Hero.TFrame", background=palette["hero"])
        style.configure("Card.TFrame", background=palette["surface"])
        style.configure("SoftCard.TFrame", background=palette["surface_alt"])
        style.configure("Footer.TFrame", background=palette["surface_alt"])
        style.configure("EmptyState.TFrame", background=palette["surface"])
        style.configure("EmptyStateMuted.TFrame", background=palette["editor_alt"])

        style.configure("HeroTitle.TLabel", background=palette["hero"], foreground="#ffffff", font=self._fonts["title"])
        style.configure("HeroSub.TLabel", background=palette["hero"], foreground=palette["hero_muted"], font=self._fonts["subtitle"])
        style.configure("Section.TLabel", background=palette["surface"], foreground=palette["text"], font=self._fonts["section"])
        style.configure("SoftSection.TLabel", background=palette["surface_alt"], foreground=palette["text"], font=self._fonts["section"])
        style.configure("FieldLabel.TLabel", background=palette["surface"], foreground=palette["muted"], font=self._fonts["caption"])
        style.configure("SoftFieldLabel.TLabel", background=palette["surface_alt"], foreground=palette["muted"], font=self._fonts["caption"])
        style.configure("Caption.TLabel", background=palette["surface"], foreground=palette["muted"], font=self._fonts["caption"])
        style.configure("SoftCaption.TLabel", background=palette["surface_alt"], foreground=palette["muted"], font=self._fonts["caption"])
        style.configure("Status.TLabel", background=palette["surface_alt"], foreground=palette["muted"], font=self._fonts["body_bold"])
        style.configure("Footer.TLabel", background=palette["surface_alt"], foreground=palette["muted"], font=self._fonts["caption"])
        style.configure("EmptyStateTitle.TLabel", background=palette["surface"], foreground=palette["text"], font=self._fonts["section"])
        style.configure("EmptyStateBody.TLabel", background=palette["surface"], foreground=palette["muted"], font=self._fonts["body"])
        style.configure("EmptyStateMutedTitle.TLabel", background=palette["editor_alt"], foreground=palette["text"], font=self._fonts["section"])
        style.configure("EmptyStateMutedBody.TLabel", background=palette["editor_alt"], foreground=palette["muted"], font=self._fonts["body"])

        style.configure(
            "TEntry",
            fieldbackground=palette["editor"],
            foreground=palette["text"],
            bordercolor=palette["border"],
            lightcolor=palette["border"],
            darkcolor=palette["border"],
            padding=(10, 8),
            relief="flat",
        )
        style.map(
            "TEntry",
            bordercolor=[("focus", palette["accent"])],
            lightcolor=[("focus", palette["accent"])],
            darkcolor=[("focus", palette["accent"])],
        )

        style.configure(
            "TCombobox",
            fieldbackground=palette["editor"],
            foreground=palette["text"],
            background=palette["editor"],
            arrowcolor=palette["accent_dark"],
            bordercolor=palette["border"],
            lightcolor=palette["border"],
            darkcolor=palette["border"],
            padding=(10, 6),
            relief="flat",
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", palette["editor"])],
            selectbackground=[("readonly", palette["editor"])],
            selectforeground=[("readonly", palette["text"])],
            bordercolor=[("focus", palette["accent"])],
            lightcolor=[("focus", palette["accent"])],
            darkcolor=[("focus", palette["accent"])],
        )

        style.configure("Card.TCheckbutton", background=palette["surface"], foreground=palette["text"], font=self._fonts["body"])
        style.configure("SoftCard.TCheckbutton", background=palette["surface_alt"], foreground=palette["text"], font=self._fonts["body"])

        style.configure("Accent.TButton", font=self._fonts["button"], background=palette["accent"], foreground="#ffffff", borderwidth=0, padding=(16, 10))
        style.map("Accent.TButton", background=[("active", palette["accent_dark"]), ("pressed", palette["accent_dark"])], foreground=[("disabled", "#f1f1f1")])
        style.configure("Secondary.TButton", font=self._fonts["button"], background=palette["surface_alt"], foreground=palette["text"], borderwidth=0, padding=(12, 8))
        style.map("Secondary.TButton", background=[("active", "#e6d8c8"), ("pressed", "#dccbb9")])
        style.configure("HeroPrimary.TButton", font=self._fonts["button"], background=palette["accent"], foreground="#ffffff", borderwidth=0, padding=(14, 9))
        style.map("HeroPrimary.TButton", background=[("active", palette["accent_dark"]), ("pressed", palette["accent_dark"])])
        style.configure(
            "HeroSecondary.TButton",
            font=self._fonts["button"],
            background=palette["hero"],
            foreground="#ffffff",
            bordercolor=palette["hero_muted"],
            lightcolor=palette["hero_muted"],
            darkcolor=palette["hero_muted"],
            padding=(14, 9),
        )
        style.map("HeroSecondary.TButton", background=[("active", "#2a434a"), ("pressed", "#2a434a")])
        style.configure(
            "TScrollbar",
            background=palette["surface_alt"],
            troughcolor=palette["surface_alt"],
            bordercolor=palette["surface_alt"],
            lightcolor=palette["surface_alt"],
            darkcolor=palette["surface_alt"],
            arrowsize=13,
        )
        style.configure("Pane.TPanedwindow", background=palette["bg"])

    def _configure_text_area(self, widget, *, role):
        """Style the input and output text editors."""
        palette = self._PALETTE
        editor_bg = palette["editor"] if role == "input" else palette["editor_alt"]
        widget.configure(
            bg=editor_bg,
            fg=palette["text"],
            insertbackground=palette["text"],
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=palette["border"],
            highlightcolor=palette["accent"],
            selectbackground=palette["accent_soft"],
            selectforeground=palette["text"],
            inactiveselectbackground=palette["accent_soft"],
            font=self._fonts["text"],
            padx=16,
            pady=16,
            spacing1=2,
            spacing3=2,
            undo=(role == "input"),
        )
        widget.frame.configure(bg=palette["surface"])
        widget.vbar.configure(
            bg=palette["surface_alt"],
            activebackground=palette["accent_soft"],
            troughcolor=palette["surface_alt"],
            relief="flat",
            borderwidth=0,
            width=12,
        )

    def _set_status(self, text, tone="neutral"):
        """Update the footer status line using the app palette."""
        self.status_label.config(text=text, foreground=self._status_colors.get(tone, self._PALETTE["muted"]))

    def _set_match_badge(self, text, tone="neutral"):
        """Update the match-count badge text and emphasis."""
        tones = {
            "neutral": (self._PALETTE["surface_alt"], self._PALETTE["muted"]),
            "accent": (self._PALETTE["accent_soft"], self._PALETTE["accent_dark"]),
            "warning": (self._PALETTE["warning_soft"], self._PALETTE["warning"]),
            "error": (self._PALETTE["error_soft"], self._PALETTE["error"]),
        }
        background, foreground = tones.get(tone, tones["neutral"])
        self.match_count_label.config(text=text, bg=background, fg=foreground)

    def _set_long_operation_active(self, active):
        """Show or hide cancellation affordances for incremental file work."""
        if not hasattr(self, "cancel_scan_btn"):
            return

        if active:
            self.cancel_scan_btn.grid()
        else:
            self.cancel_scan_btn.grid_remove()

    def _current_pattern_text(self):
        """Return the pattern exactly as typed so whitespace regexes are valid."""
        return self.regex_entry.get()

    def _delimiter_text(self):
        """Return the configured output delimiter as concrete text."""
        delim_map = {"Newline": "\n", "Comma": ", ", "Tab": "\t", "Space": " "}
        return delim_map.get(self.delimiter_var.get(), "\n")

    def _format_flag_summary(self):
        """Return a compact label for the active regex flags."""
        active = []
        if self.ignore_case.get():
            active.append("Ignore Case")
        if self.multiline.get():
            active.append("Multiline")
        if self.dotall.get():
            active.append("Dot All")
        return ", ".join(active) if active else "no flags"

    def _line_mode_dotall_requested(self, pattern_text):
        """Return True when checkbox or inline syntax asks dot to match newlines."""
        return self.dotall.get() or re.search(r"\(\?[a-zA-Z-]*s", pattern_text) is not None

    def _find_literal_prefix(self, pattern_text):
        """Best-effort prefix hint for the performance coach."""
        text = pattern_text
        if text.startswith("^"):
            text = text[1:]

        prefix = []
        escaped = False
        for char in text:
            if escaped:
                if char in "AbBdDsSwWZ0123456789":
                    break
                prefix.append(char)
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue
            if char.isalnum() or char in " _-:/@.":
                prefix.append(char)
                continue
            break

        return "".join(prefix).strip()

    def _analyze_pattern(self, pattern_text):
        """Return static performance and correctness hints for a pattern."""
        if not pattern_text:
            return ["Enter a pattern to get performance and syntax guidance."], "neutral"

        hints = []
        tone = "success"

        if pattern_text.startswith(".*") or pattern_text.startswith("^.*"):
            hints.append("Leading dot-star makes the engine try broad spans before it can prove a match. Anchor to a literal prefix when possible.")
            tone = "warning"
        if re.search(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{)", pattern_text):
            hints.append("Nested unbounded quantifiers can cause catastrophic backtracking on Python's regex engine.")
            tone = "error"
        if re.search(r"\.\*.*\.\*", pattern_text) or re.search(r"\.\+.*\.\+", pattern_text):
            hints.append("Multiple wildcard repeats in one pattern are expensive on large lines; replace them with narrower character classes.")
            if tone != "error":
                tone = "warning"
        if re.search(r"\\[1-9]", pattern_text) or "\\g<" in pattern_text:
            hints.append("Backreferences are powerful but can be slow at gigabyte scale; use them only when equality between groups is required.")
            if tone != "error":
                tone = "warning"
        if any(token in pattern_text for token in ("(?=", "(?!", "(?<=", "(?<!")):
            hints.append("Lookaround keeps output precise, but it can be slower than a consuming expression on huge files.")
            if tone != "error":
                tone = "warning"
        if "[\\s\\S]" in pattern_text and self.dotall.get():
            hints.append("Dot All is enabled, so [\\s\\S] can usually be simplified to a dot.")
        if self.file_source_path and self._line_mode_dotall_requested(pattern_text):
            hints.append("Dot All is disabled for file-backed scans because the gigabyte-safe path scans one line at a time.")
            tone = "error"
        if pattern_text.count("|") >= 8:
            hints.append("Large alternation lists are faster when the most common or most selective alternatives appear first.")
            if tone != "error":
                tone = "warning"

        literal_prefix = self._find_literal_prefix(pattern_text)
        if literal_prefix:
            hints.append(f"Literal prefix '{literal_prefix[:32]}' gives the engine a useful starting point.")

        if not hints:
            hints.append("Looks line-scan friendly. Prefer literal prefixes, bounded repeats, and non-capturing groups when captures are not needed.")

        return hints, tone

    def _update_pattern_coach(self):
        """Refresh the inline pattern preview and performance coach labels."""
        if not hasattr(self, "pattern_preview_label"):
            return

        pattern_text = self._current_pattern_text()
        if not pattern_text:
            self.pattern_preview_label.config(
                text="Pattern preview: waiting for a regex.",
                foreground=self._PALETTE["muted"],
            )
            self.pattern_coach_label.config(
                text="Performance coach: enter a pattern to get optimization hints.",
                foreground=self._PALETTE["muted"],
            )
            return

        try:
            compiled = re.compile(pattern_text, self._get_regex_flags())
        except re.error as exc:
            self.pattern_preview_label.config(
                text=f"Pattern preview: invalid regex ({exc}).",
                foreground=self._PALETTE["error"],
            )
            self.pattern_coach_label.config(
                text="Performance coach: fix the syntax error before tuning the pattern.",
                foreground=self._PALETTE["error"],
            )
            return

        named_groups = ", ".join(list(compiled.groupindex.keys())[:4])
        group_note = f"{compiled.groups} capture group{'s' if compiled.groups != 1 else ''}"
        if named_groups:
            group_note = f"{group_note}; named: {named_groups}"

        self.pattern_preview_label.config(
            text=f"Pattern preview: {group_note}; {self._format_flag_summary()}.",
            foreground=self._PALETTE["muted"],
        )
        hints, tone = self._analyze_pattern(pattern_text)
        colors = {
            "neutral": self._PALETTE["muted"],
            "success": self._PALETTE["success"],
            "warning": self._PALETTE["warning"],
            "error": self._PALETTE["error"],
        }
        self.pattern_coach_label.config(
            text="Performance coach: " + " ".join(hints[:2]),
            foreground=colors.get(tone, self._PALETTE["muted"]),
        )

    def _format_file_size(self, size_bytes):
        """Return a compact human-readable file size label."""
        size = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024

    def _refresh_input_overview(self):
        """Refresh small UI summaries describing where the source text lives."""
        text = self.input_text.get("1.0", "end-1c")
        if text:
            summary = f"{len(text):,} characters in the editor"
            source = "Source: editor"
        elif self.cached_input_path:
            summary = f"Input cached off-screen • {self.cached_input_chars:,} characters"
            source = "Source: cache"
        elif self.file_source_path:
            filename = os.path.basename(self.file_source_path)
            summary = f"File-backed source • {filename} • {self._format_file_size(self.file_source_size)}"
            source = "Source: direct file scan"
        else:
            summary = "Paste, type, or load text to start testing"
            source = "Source: empty"

        self.input_meta_label.config(text=summary)
        self.context_label.config(text=source)

    def _sync_live_mode_badge(self):
        """Keep the hero badge aligned with the current matching mode."""
        if self.live_matching.get():
            self.mode_badge_label.config(text="LIVE", bg=self._PALETTE["accent"], fg="#ffffff")
            return

        self.mode_badge_label.config(text="MANUAL", bg=self._PALETTE["warning"], fg="#ffffff")

    def _toggle_output_empty_state(self, show):
        """Show or hide the centered results placeholder."""
        if show:
            self.output_empty_state.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.output_empty_state.place_forget()

    def _build_ui(self):
        """Build the refreshed single-window workspace."""
        main = ttk.Frame(self.root, style="App.TFrame", padding=(24, 20, 24, 20))
        main.grid(row=0, column=0, sticky="nsew")
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        self._build_header(main)
        self._build_regex_bar(main)
        self._build_workspace(main)
        self._build_status_bar(main)

    def _build_header(self, parent):
        """Hero header with title, actions, and mode badge."""
        hero = ttk.Frame(parent, style="Hero.TFrame", padding=(24, 22))
        hero.grid(row=0, column=0, sticky="ew")
        hero.grid_columnconfigure(0, weight=1)

        copy = ttk.Frame(hero, style="Hero.TFrame")
        copy.grid(row=0, column=0, sticky="w")
        ttk.Label(copy, text="Regex Isolator", style="HeroTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            copy,
            text="A calmer workspace for sculpting patterns, previewing replacements, and isolating matches.",
            style="HeroSub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        controls = ttk.Frame(hero, style="Hero.TFrame")
        controls.grid(row=0, column=1, sticky="e")
        self.mode_badge_label = tk.Label(
            controls,
            text="LIVE",
            bg=self._PALETTE["accent"],
            fg="#ffffff",
            font=self._fonts["badge"],
            padx=12,
            pady=7,
        )
        self.mode_badge_label.grid(row=0, column=0, padx=(0, 14))
        self.cancel_scan_btn = ttk.Button(controls, text="Cancel Job", style="HeroSecondary.TButton", command=self._cancel_active_operation)
        self.cancel_scan_btn.grid(row=0, column=1, padx=(0, 8))
        self.cancel_scan_btn.grid_remove()
        ttk.Button(controls, text="Help", style="HeroSecondary.TButton", command=self._show_help).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(controls, text="Clear All", style="HeroPrimary.TButton", command=self._clear_all).grid(row=0, column=3)

    def _build_regex_bar(self, parent):
        """Compact control card for pattern editing, presets, and matching options."""
        frame = ttk.Frame(parent, style="Card.TFrame", padding=(22, 20))
        frame.grid(row=1, column=0, sticky="ew", pady=(18, 18))
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=2)

        ttk.Label(frame, text="Pattern Studio", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            frame,
            text="Keep the working regex, presets, and mode toggles in one compact strip.",
            style="Caption.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 16))

        editor_col = ttk.Frame(frame, style="Card.TFrame")
        editor_col.grid(row=2, column=0, sticky="nsew", padx=(0, 16))
        editor_col.grid_columnconfigure(0, weight=1)
        editor_col.grid_columnconfigure(1, weight=0)

        ttk.Label(editor_col, text="Pattern", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        self.regex_entry = ttk.Entry(editor_col)
        self.regex_entry.grid(row=1, column=0, columnspan=2, sticky="ew")

        ttk.Label(editor_col, text="Replacement", style="FieldLabel.TLabel").grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.replace_entry = ttk.Entry(editor_col)
        self.replace_entry.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.replace_entry.bind("<KeyRelease>", self._on_content_change)

        self.replace_preview_label = ttk.Label(editor_col, text="", style="Caption.TLabel", justify="left", wraplength=560)
        self.replace_preview_label.grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.replace_copy_btn = ttk.Button(editor_col, text="Copy Result", style="Secondary.TButton", command=self._copy_replace_result)
        self.replace_copy_btn.grid(row=4, column=1, sticky="e", padx=(12, 0), pady=(10, 0))
        self.replace_copy_btn.grid_remove()
        self._replace_result = ""

        self.pattern_preview_label = ttk.Label(editor_col, text="", style="Caption.TLabel", justify="left", wraplength=560)
        self.pattern_preview_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.pattern_coach_label = ttk.Label(editor_col, text="", style="Caption.TLabel", justify="left", wraplength=560)
        self.pattern_coach_label.grid(row=6, column=0, columnspan=2, sticky="w", pady=(4, 0))

        preset_col = ttk.Frame(frame, style="SoftCard.TFrame", padding=(16, 16))
        preset_col.grid(row=2, column=1, sticky="nsew")
        preset_col.grid_columnconfigure(0, weight=1)
        preset_col.grid_columnconfigure(1, weight=1)

        ttk.Label(preset_col, text="Preset Library", style="SoftSection.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(
            preset_col,
            text="Start with a built-in pattern or save the exact combo of flags and output settings you use most.",
            style="SoftCaption.TLabel",
            justify="left",
            wraplength=300,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 12))

        ttk.Label(preset_col, text="Preset", style="SoftFieldLabel.TLabel").grid(row=2, column=0, columnspan=2, sticky="w")
        self.preset_var = tk.StringVar(value=self._PRESET_PLACEHOLDER)
        self.preset_combo = ttk.Combobox(preset_col, textvariable=self.preset_var, values=[self._PRESET_PLACEHOLDER], state="readonly")
        self.preset_combo.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        ttk.Label(preset_col, text="Preset name", style="SoftFieldLabel.TLabel").grid(row=4, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.preset_name_entry = ttk.Entry(preset_col)
        self.preset_name_entry.grid(row=5, column=0, columnspan=2, sticky="ew")

        ttk.Button(preset_col, text="Save Preset", style="Secondary.TButton", command=self._save_named_preset).grid(row=6, column=0, sticky="ew", pady=(12, 0), padx=(0, 6))
        ttk.Button(preset_col, text="Delete Preset", style="Secondary.TButton", command=self._delete_named_preset).grid(row=6, column=1, sticky="ew", pady=(12, 0))

        options = ttk.Frame(frame, style="Card.TFrame")
        options.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(18, 0))

        self.ignore_case = tk.BooleanVar()
        self.multiline = tk.BooleanVar()
        self.dotall = tk.BooleanVar()

        left = ttk.Frame(options, style="Card.TFrame")
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(left, text="Options", style="FieldLabel.TLabel").pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(left, text="Live matching", variable=self.live_matching, style="Card.TCheckbutton", command=self._on_live_toggle).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(left, text="Ignore Case", variable=self.ignore_case, style="Card.TCheckbutton", command=self._on_content_change).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(left, text="Multiline", variable=self.multiline, style="Card.TCheckbutton", command=self._on_content_change).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(left, text="Dot All", variable=self.dotall, style="Card.TCheckbutton", command=self._on_content_change).pack(side=tk.LEFT, padx=(0, 10))

        right = ttk.Frame(options, style="Card.TFrame")
        right.pack(side=tk.RIGHT)
        ttk.Button(right, text="Match Now", style="Accent.TButton", command=self._run_match).pack(side=tk.RIGHT)

    def _build_workspace(self, parent):
        """Create the resizable source/results split view."""
        split = ttk.Panedwindow(parent, orient=tk.HORIZONTAL, style="Pane.TPanedwindow")
        split.grid(row=2, column=0, sticky="nsew")

        input_panel = ttk.Frame(split, style="Card.TFrame", padding=(18, 18))
        output_panel = ttk.Frame(split, style="Card.TFrame", padding=(18, 18))
        split.add(input_panel, weight=3)
        split.add(output_panel, weight=2)

        self._build_input_panel(input_panel)
        self._build_output_panel(output_panel)

    def _build_input_panel(self, parent):
        """Left panel: source text editor and source-focused actions."""
        parent.grid_rowconfigure(2, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        header = ttk.Frame(parent, style="Card.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ttk.Frame(header, style="Card.TFrame")
        title.grid(row=0, column=0, sticky="w")
        ttk.Label(title, text="Source Text", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.input_meta_label = ttk.Label(title, text="Paste, type, or load text to start testing", style="Caption.TLabel")
        self.input_meta_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        actions = ttk.Frame(header, style="Card.TFrame")
        actions.grid(row=0, column=1, sticky="e")
        ttk.Button(actions, text="Paste", style="Accent.TButton", command=self._paste_from_clipboard).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(actions, text="Load", style="Secondary.TButton", command=self._load_from_file).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(actions, text="Cache", style="Secondary.TButton", command=self._cache_input).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(actions, text="Restore", style="Secondary.TButton", command=self._restore_cached_input).grid(row=0, column=3)

        editor_shell = ttk.Frame(parent, style="Card.TFrame")
        editor_shell.grid(row=2, column=0, sticky="nsew", pady=(14, 0))
        editor_shell.grid_rowconfigure(0, weight=1)
        editor_shell.grid_columnconfigure(0, weight=1)

        self.input_text = scrolledtext.ScrolledText(editor_shell, wrap=tk.WORD, height=20)
        self.input_text.grid(row=0, column=0, sticky="nsew")
        self._configure_text_area(self.input_text, role="input")
        self.input_text.tag_config("highlight", background=self._PALETTE["highlight"], foreground=self._PALETTE["text"])
        self.input_text.tag_config("selected_match", background=self._PALETTE["selected"], foreground=self._PALETTE["text"])

        self.input_empty_state = ttk.Frame(editor_shell, style="EmptyState.TFrame", padding=(24, 22))
        self.input_empty_title_label = ttk.Label(self.input_empty_state, text="Bring in some source text", style="EmptyStateTitle.TLabel")
        self.input_empty_title_label.grid(row=0, column=0, columnspan=2)
        self.input_empty_body_label = ttk.Label(
            self.input_empty_state,
            text="Paste from the clipboard, type directly, or load a file. Matching starts as soon as the pattern is ready.",
            style="EmptyStateBody.TLabel",
            justify="center",
            wraplength=300,
        )
        self.input_empty_body_label.grid(row=1, column=0, columnspan=2, pady=(8, 16))
        self.empty_state_primary_btn = ttk.Button(self.input_empty_state, text="Paste from Clipboard", style="Accent.TButton", command=self._paste_from_clipboard)
        self.empty_state_primary_btn.grid(row=2, column=0, padx=(0, 8))
        self.empty_state_secondary_btn = ttk.Button(self.input_empty_state, text="Load from File", style="Secondary.TButton", command=self._load_from_file)
        self.empty_state_secondary_btn.grid(row=2, column=1)

    def _build_output_panel(self, parent):
        """Right panel: result view, output controls, and match summary."""
        parent.grid_rowconfigure(2, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        header = ttk.Frame(parent, style="Card.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ttk.Frame(header, style="Card.TFrame")
        title.grid(row=0, column=0, sticky="w")
        ttk.Label(title, text="Matches", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.output_meta_label = ttk.Label(
            title,
            text="Run a pattern to isolate results. In newline mode, clicking a line jumps back to the source span.",
            style="Caption.TLabel",
            wraplength=360,
            justify="left",
        )
        self.output_meta_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        actions = ttk.Frame(header, style="Card.TFrame")
        actions.grid(row=0, column=1, sticky="e")
        ttk.Button(actions, text="Copy", style="Secondary.TButton", command=self._copy_to_clipboard).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(actions, text="Save", style="Secondary.TButton", command=self._save_to_file).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(actions, text="Export JSONL", style="Secondary.TButton", command=self._export_results_jsonl).grid(row=0, column=2)

        tools = ttk.Frame(parent, style="Card.TFrame")
        tools.grid(row=1, column=0, sticky="ew", pady=(14, 12))

        filter_row = ttk.Frame(tools, style="Card.TFrame")
        filter_row.pack(fill=tk.X)

        self.match_count_label = tk.Label(
            filter_row,
            text="0 matches",
            bg=self._PALETTE["surface_alt"],
            fg=self._PALETTE["muted"],
            font=self._fonts["badge"],
            padx=12,
            pady=6,
        )
        self.match_count_label.pack(side=tk.LEFT)

        self.unique_matches = tk.BooleanVar()
        ttk.Checkbutton(filter_row, text="Unique only", variable=self.unique_matches, style="Card.TCheckbutton", command=self._on_content_change).pack(side=tk.LEFT, padx=(16, 14))
        ttk.Label(filter_row, text="Delimiter", style="FieldLabel.TLabel").pack(side=tk.LEFT, padx=(0, 8))
        self.delimiter_var = tk.StringVar(value="Newline")
        delim_combo = ttk.Combobox(filter_row, textvariable=self.delimiter_var, values=["Newline", "Comma", "Tab", "Space"], state="readonly", width=10)
        delim_combo.pack(side=tk.LEFT)
        delim_combo.bind("<<ComboboxSelected>>", self._on_content_change)

        action_row = ttk.Frame(tools, style="Card.TFrame")
        action_row.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(action_row, text="Keep Matches", style="Secondary.TButton", command=self._keep_only_matches_in_source).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(action_row, text="Delete Matches", style="Secondary.TButton", command=self._delete_matches_from_source).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(action_row, text="Save Matches", style="Secondary.TButton", command=self._save_all_matches_to_file).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(action_row, text="Save Cleaned", style="Secondary.TButton", command=self._save_text_without_matches).pack(side=tk.LEFT)

        editor_shell = ttk.Frame(parent, style="Card.TFrame")
        editor_shell.grid(row=2, column=0, sticky="nsew")
        editor_shell.grid_rowconfigure(0, weight=1)
        editor_shell.grid_columnconfigure(0, weight=1)

        self.output_text = scrolledtext.ScrolledText(editor_shell, wrap=tk.WORD, height=20, state="disabled", cursor="arrow")
        self.output_text.grid(row=0, column=0, sticky="nsew")
        self._configure_text_area(self.output_text, role="output")

        self.output_empty_state = ttk.Frame(editor_shell, style="EmptyStateMuted.TFrame", padding=(24, 22))
        ttk.Label(self.output_empty_state, text="Matches appear here", style="EmptyStateMutedTitle.TLabel").grid(row=0, column=0)
        ttk.Label(
            self.output_empty_state,
            text="The result pane fills as soon as the pattern and source text line up.",
            style="EmptyStateMutedBody.TLabel",
            justify="center",
            wraplength=300,
        ).grid(row=1, column=0, pady=(8, 0))
        self._toggle_output_empty_state(True)
        self._set_match_badge("0 matches", tone="neutral")

    def _build_status_bar(self, parent):
        """Bottom footer with status feedback and source summary."""
        bar = ttk.Frame(parent, style="Footer.TFrame", padding=(18, 12))
        bar.grid(row=3, column=0, sticky="ew", pady=(18, 0))
        bar.grid_columnconfigure(0, weight=1)

        self.status_label = ttk.Label(bar, text="Ready", style="Status.TLabel")
        self.status_label.grid(row=0, column=0, sticky="w")
        self.context_label = ttk.Label(bar, text="Source: empty", style="Footer.TLabel")
        self.context_label.grid(row=0, column=1, sticky="e")

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
            self._set_status(f"Loaded preset '{name}'", "success")
            return

        for label, pattern in self._PRESETS:
            if label == name and pattern:
                self.regex_entry.delete(0, tk.END)
                self.regex_entry.insert(0, pattern)
                self._on_content_change()
                self._set_status(f"Loaded built-in preset '{name}'", "success")
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
            self._set_status("Enter a preset name to save", "warning")
            return

        builtin_names = {label for label, pattern in self._PRESETS if pattern}
        if name in builtin_names:
            self._set_status("Preset name conflicts with a built-in preset", "error")
            return
        if name in (self._PRESET_PLACEHOLDER, self._CUSTOM_SECTION_LABEL):
            self._set_status("Choose a different preset name", "error")
            return

        self.custom_presets[name] = self._current_preset_payload()
        try:
            self._save_custom_presets()
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to save preset:\n{exc}")
            self._set_status("Preset save failed", "error")
            return

        self._refresh_preset_values()
        self.preset_var.set(name)
        self._set_status(f"Saved preset '{name}'", "success")

    def _delete_named_preset(self):
        """Delete a custom preset by name."""
        typed_name = self.preset_name_entry.get().strip()
        selected_name = self.preset_var.get()
        name = typed_name or (selected_name if selected_name in self.custom_presets else "")

        if not name:
            self._set_status("Enter or select a custom preset to delete", "warning")
            return
        if name not in self.custom_presets:
            self._set_status(f"No custom preset named '{name}'", "warning")
            return

        if not messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            return

        del self.custom_presets[name]
        try:
            self._save_custom_presets()
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to delete preset:\n{exc}")
            self._set_status("Preset delete failed", "error")
            return

        self._refresh_preset_values()
        self.preset_name_entry.delete(0, tk.END)
        self._set_status(f"Deleted preset '{name}'", "success")

    def _bind_events(self):
        """Wire up keyboard and mouse events."""
        self.regex_entry.bind("<KeyRelease>", self._on_content_change)
        self.input_text.bind("<KeyRelease>", self._on_input_change)
        self.input_text.bind("<FocusIn>", self._check_paste_button)
        self.input_text.bind("<FocusOut>", self._check_paste_button)
        self.output_text.bind("<Button-1>", self._on_output_click)

    def _check_paste_button(self, _event=None):
        """Show a centered empty state when the source editor is empty or off-screen."""
        text = self.input_text.get("1.0", "end-1c").strip()
        if text:
            self.input_empty_state.place_forget()
            self._refresh_input_overview()
            return

        if self.cached_input_path:
            self.input_empty_title_label.config(text="Input moved to cache")
            self.input_empty_body_label.config(
                text=(
                    f"{self.cached_input_chars:,} characters are stored off-screen so matching stays fast. "
                    "Restore them when you need the full text back in the editor."
                )
            )
            self.empty_state_primary_btn.config(
                text="Restore Cached",
                style="Secondary.TButton",
                command=self._restore_cached_input,
            )
            self.empty_state_secondary_btn.config(
                text="Match Now",
                style="Accent.TButton",
                command=self._run_match,
            )
        elif self.file_source_path:
            filename = os.path.basename(self.file_source_path)
            self.input_empty_title_label.config(text="Large file ready")
            self.input_empty_body_label.config(
                text=(
                    f"{filename} stays on disk in file-backed mode ({self._format_file_size(self.file_source_size)}). "
                    "Press Match Now to scan it line by line without loading the full file into the editor."
                )
            )
            self.empty_state_primary_btn.config(
                text="Match Now",
                style="Accent.TButton",
                command=self._run_match,
            )
            self.empty_state_secondary_btn.config(
                text="Load Another File",
                style="Secondary.TButton",
                command=self._load_from_file,
            )
        else:
            self.input_empty_title_label.config(text="Bring in some source text")
            self.input_empty_body_label.config(
                text=(
                    "Paste from the clipboard, type directly, or load a file. "
                    "Matching starts as soon as the pattern is ready."
                )
            )
            self.empty_state_primary_btn.config(
                text="Paste from Clipboard",
                style="Accent.TButton",
                command=self._paste_from_clipboard,
            )
            self.empty_state_secondary_btn.config(
                text="Load from File",
                style="Secondary.TButton",
                command=self._load_from_file,
            )

        self.input_empty_state.place(relx=0.5, rely=0.5, anchor="center")
        self._refresh_input_overview()

    def _on_input_change(self, event=None):
        """Respond to input text edits (also refreshes the paste button)."""
        self._check_paste_button()
        self._on_content_change(event)

    def _on_content_change(self, _event=None):
        """Debounce content changes - waits 300 ms of inactivity before processing."""
        self._update_pattern_coach()
        self.output_click_enabled = False
        self.output_text.config(cursor="arrow")

        if self.scan_in_progress:
            self._set_status("An active file job is running. Cancel it before changing scan settings.", "warning")
            return

        if not self.live_matching.get():
            if self.update_timer:
                self.root.after_cancel(self.update_timer)
                self.update_timer = None
            if not self.scan_in_progress:
                self._set_status("Live matching off. Press Match Now to refresh results.", "neutral")
            return

        editor_chars = len(self.input_text.get("1.0", "end-1c"))
        if editor_chars > self._LIVE_TEXT_MAX_CHARS:
            if self.update_timer:
                self.root.after_cancel(self.update_timer)
                self.update_timer = None
            self._set_status(
                f"Live matching paused for {editor_chars:,} editor characters. Press Match Now when ready.",
                "warning",
            )
            return

        if self.update_timer:
            self.root.after_cancel(self.update_timer)
        self.update_timer = self.root.after(300, self._process)

    def _on_live_toggle(self):
        """Switch between automatic debounced matching and manual matching."""
        if self.file_source_path and self.live_matching.get():
            self.live_matching.set(False)
            self._sync_live_mode_badge()
            self._set_status(
                "File-backed scans stay manual so large files are not re-scanned on every keystroke.",
                "warning",
            )
            return

        self._sync_live_mode_badge()
        self._update_pattern_coach()
        if self.live_matching.get():
            self._set_status("Live matching on", "success")
            self._on_content_change()
            return

        if self.update_timer:
            self.root.after_cancel(self.update_timer)
            self.update_timer = None
        self._set_status("Live matching off. Press Match Now to refresh results.", "neutral")

    def _run_match(self):
        """Run matching immediately regardless of live-matching mode."""
        if self.scan_in_progress and self.file_scan_context and self.file_scan_context.get("operation") != "scan":
            self._set_status("Wait for the active file save job to finish, or cancel it first.", "warning")
            return
        if self.update_timer:
            self.root.after_cancel(self.update_timer)
            self.update_timer = None
        self._process()

    # ── Core regex processing ────────────────────────────────────────

    def _reset_output_state(self):
        """Clear result widgets before a new scan starts."""
        self.output_click_enabled = False
        self.match_positions.clear()
        self.result_records = []
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled", cursor="arrow")
        self._set_match_badge("0 matches", tone="neutral")
        self.output_meta_label.config(
            text="Run a pattern to isolate results. In newline mode, clicking a line jumps back to the source span."
        )
        self._toggle_output_empty_state(True)
        self.replace_preview_label.config(text="", foreground=self._PALETTE["muted"])
        self.replace_copy_btn.grid_remove()
        self._replace_result = ""

    def _get_regex_flags(self):
        """Combine the checkbox state into Python regex flags."""
        flags = 0
        if self.ignore_case.get():
            flags |= re.IGNORECASE
        if self.multiline.get():
            flags |= re.MULTILINE
        if self.dotall.get():
            flags |= re.DOTALL
        return flags

    def _extract_match_value(self, match, group_count):
        """Return the displayed value and all capture-group values for *match*."""
        captures = list(match.groups())
        if group_count == 0:
            value = match.group(0)
        elif group_count == 1:
            value = match.group(1) or ""
        else:
            value = "".join(group for group in captures if group)
        return value, captures

    def _build_editor_result_record(self, match, value, captures, text_source):
        """Build a structured export record for editor/cache matches."""
        return {
            "match": value,
            "full_match": match.group(0),
            "captures": captures,
            "start": match.start(),
            "end": match.end(),
            "source": text_source,
        }

    def _format_line_preview(self, line):
        """Return a single-line preview snippet for structured exports."""
        preview = line.rstrip("\r\n").replace("\t", "    ")
        if len(preview) > self._PREVIEW_MAX_CHARS:
            preview = preview[: self._PREVIEW_MAX_CHARS - 3] + "..."
        return preview

    def _build_file_result_record(self, match, value, captures, line_number, line_text):
        """Build a structured export record for file-backed line scans."""
        return {
            "match": value,
            "full_match": match.group(0),
            "captures": captures,
            "file_path": self.file_source_path,
            "line": line_number,
            "column_start": match.start() + 1,
            "column_end": match.end(),
            "preview": self._format_line_preview(line_text),
            "source": "file",
        }

    def _render_results(
        self,
        processed,
        total_count,
        *,
        detail,
        no_match_detail,
        status_text,
        can_click=False,
        match_positions=None,
        output_limit_reached=False,
    ):
        """Render processed matches into the output pane."""
        delimiter = self._delimiter_text()
        positions = list(match_positions or [])

        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)

        if processed:
            self._toggle_output_empty_state(False)
            self.output_text.insert("1.0", delimiter.join(processed))

            if output_limit_reached:
                self.output_text.insert(
                    tk.END,
                    f"\n\n(Output capped at first {self._OUTPUT_MAX_MATCHES} matches)",
                )

            self.output_click_enabled = delimiter == "\n" and can_click and bool(positions)
            self.output_text.config(cursor="hand2" if self.output_click_enabled else "arrow")
            self.match_positions = positions
            if self.output_click_enabled:
                for i in range(len(processed)):
                    tag = f"match_{i}"
                    self.output_text.tag_add(tag, f"{i + 1}.0", f"{i + 1}.end")
                    self.output_text.tag_config(tag, foreground=self._PALETTE["accent_dark"])

            self.output_meta_label.config(text=detail)
            self._set_match_badge(
                f"{total_count} match{'es' if total_count != 1 else ''}",
                tone="accent",
            )
            self._set_status(status_text, "success")
        else:
            self.output_click_enabled = False
            self.match_positions = []
            self._toggle_output_empty_state(False)
            self.output_text.insert("1.0", "(No matches found)")
            self.output_meta_label.config(text=no_match_detail)
            self._set_match_badge("0 matches", tone="warning")
            self._set_status("No matches found", "warning")

        self.output_text.config(state="disabled")

    def _set_file_source_replace_state(self):
        """Explain why whole-text replacement preview is disabled in file-backed mode."""
        if not self.replace_entry.get():
            return

        self.replace_preview_label.config(
            text=(
                "Replacement preview is unavailable in file-backed line mode. "
                "Load smaller text into the editor or cache to preview or copy replacement output."
            ),
            foreground=self._PALETTE["muted"],
        )

    def _cancel_file_scan(self):
        """Invalidate any pending incremental file scan."""
        self.scan_generation += 1
        if self.file_scan_context:
            file_obj = self.file_scan_context.get("file_obj")
            if file_obj:
                try:
                    file_obj.close()
                except OSError:
                    pass
            output_file_obj = context.get("output_file_obj")
            if output_file_obj:
                try:
                    output_file_obj.close()
                except OSError:
                    pass
            output_file_obj = self.file_scan_context.get("output_file_obj")
            if output_file_obj:
                try:
                    output_file_obj.close()
                except OSError:
                    pass
        self.file_scan_context = None
        self.scan_in_progress = False
        self._set_long_operation_active(False)

    def _cancel_active_operation(self):
        """Cancel an active file-backed scan or streaming save job."""
        if not self.scan_in_progress:
            self._set_status("No active file job to cancel", "neutral")
            return

        operation = "file job"
        if self.file_scan_context:
            operation = self.file_scan_context.get("operation_label", operation)
        self._cancel_file_scan()
        self._set_match_badge("Canceled", tone="warning")
        self.output_meta_label.config(text=f"Canceled {operation}.")
        self._set_status(f"Canceled {operation}", "warning")

    def _process_file_backed(self, pattern):
        """Scan the current file-backed source incrementally on the Tk event loop."""
        if not self.file_source_path:
            return

        file_path = self.file_source_path
        self._cancel_file_scan()
        try:
            file_obj = open(file_path, "rb")
        except OSError as exc:
            self._set_match_badge("File error", tone="error")
            self.output_meta_label.config(text="The file-backed source could not be opened.")
            self._set_status(f"Failed to open file: {exc}", "error")
            return

        generation = self.scan_generation
        self.scan_in_progress = True
        self._set_long_operation_active(True)
        self.file_scan_context = {
            "generation": generation,
            "operation": "scan",
            "operation_label": "file scan",
            "file_path": file_path,
            "file_obj": file_obj,
            "pattern": pattern,
            "group_count": pattern.groups,
            "total_count": 0,
            "display_items": [],
            "records": [],
            "output_limit_reached": False,
            "seen": set() if self.unique_matches.get() else None,
            "line_number": 0,
            "processed_bytes": 0,
            "file_size": self.file_source_size,
        }

        self._toggle_output_empty_state(False)
        self.output_text.config(state="normal")
        self.output_text.insert(
            "1.0",
            "Scanning file-backed source...\n\nThe file stays on disk and is processed one line at a time.",
        )
        self.output_text.config(state="disabled")
        self._set_match_badge("Scanning...", tone="accent")
        self.output_meta_label.config(
            text="Large-file mode is scanning directly from disk in line mode to keep memory usage low."
        )
        self._set_status(f"Scanning {os.path.basename(file_path)}...", "neutral")
        self.root.after(1, lambda: self._continue_file_scan(generation))

    def _format_scan_progress(self, context):
        """Return a compact progress message for file-backed operations."""
        filename = os.path.basename(context["file_path"])
        processed = context.get("processed_bytes", 0)
        total = context.get("file_size", 0)
        if total:
            pct = min(100, int((processed / total) * 100))
            return (
                f"Scanning {filename}... {context['line_number']:,} lines checked, "
                f"{self._format_file_size(processed)} / {self._format_file_size(total)} ({pct}%)"
            )
        return f"Scanning {filename}... {context['line_number']:,} lines checked"

    def _continue_file_scan(self, generation):
        """Process the next slice of a file-backed scan."""
        context = self.file_scan_context
        if not context or generation != self.scan_generation or context.get("generation") != generation:
            return

        try:
            for _ in range(self._FILE_SCAN_BATCH_LINES):
                line_bytes = context["file_obj"].readline()
                if not line_bytes:
                    self._finish_file_scan(generation)
                    return

                line = line_bytes.decode("utf-8", errors="replace")
                context["line_number"] += 1
                context["processed_bytes"] += len(line_bytes)
                for match in context["pattern"].finditer(line):
                    context["total_count"] += 1
                    value, captures = self._extract_match_value(match, context["group_count"])

                    seen = context["seen"]
                    if seen is not None:
                        if value in seen:
                            continue
                        seen.add(value)

                    if len(context["display_items"]) < self._OUTPUT_MAX_MATCHES:
                        context["display_items"].append(value)
                        context["records"].append(
                            self._build_file_result_record(
                                match,
                                value,
                                captures,
                                context["line_number"],
                                line,
                            )
                        )
                    else:
                        context["output_limit_reached"] = True
        except OSError as exc:
            self._fail_file_scan(generation, exc)
            return

        progress = self._format_scan_progress(context)
        self._set_status(progress, "neutral")
        if context["total_count"]:
            self._set_match_badge(f"{context['total_count']:,} matches", tone="accent")
        self.root.after(1, lambda: self._continue_file_scan(generation))

    def _finish_file_scan(self, generation):
        """Render final results for a completed file-backed scan."""
        context = self.file_scan_context
        if not context or generation != self.scan_generation or context.get("generation") != generation:
            return

        file_obj = context.get("file_obj")
        if file_obj:
            try:
                file_obj.close()
            except OSError:
                pass

        self.file_scan_context = None
        self.scan_in_progress = False
        self._set_long_operation_active(False)
        self.result_records = context["records"]

        detail = (
            "Scanned directly from disk in line mode. Export JSONL keeps line numbers, columns, previews, and capture groups. "
            "Whole-file anchors and cross-line patterns still require editor or cache mode."
        )
        if self.unique_matches.get():
            noun = "result" if len(context["display_items"]) == 1 else "results"
            detail = f"{detail} Showing {len(context['display_items']):,} unique {noun}."
        if context["output_limit_reached"]:
            detail = f"{detail} Output is capped at the first {self._OUTPUT_MAX_MATCHES:,} matches."

        filename = os.path.basename(context["file_path"])
        self._render_results(
            context["display_items"],
            context["total_count"],
            detail=detail,
            no_match_detail="No line-based matches found in the current file-backed source.",
            status_text=(
                f"Scanned {context['line_number']:,} lines in {filename} and found "
                f"{context['total_count']} match(es)"
            ),
            can_click=False,
            output_limit_reached=context["output_limit_reached"],
        )
        self._set_file_source_replace_state()

    def _fail_file_scan(self, generation, exc):
        """Handle an error raised while scanning a file-backed source."""
        context = self.file_scan_context
        if context:
            file_obj = context.get("file_obj")
            if file_obj:
                try:
                    file_obj.close()
                except OSError:
                    pass

        self.file_scan_context = None
        self.scan_in_progress = False
        self._set_long_operation_active(False)
        if generation != self.scan_generation:
            return

        self._toggle_output_empty_state(True)
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")
        self._set_match_badge("File error", tone="error")
        label = "file-backed scan"
        if context:
            label = context.get("operation_label", label)
        self.output_meta_label.config(text=f"The {label} could not finish.")
        self._set_status(f"File job failed: {exc}", "error")

    def _process(self):
        """Run the regex against the input and update highlights + output."""
        pattern_str = self._current_pattern_text()
        self._reset_output_state()

        if pattern_str == "":
            self.input_text.tag_remove("highlight", "1.0", tk.END)
            self._set_status("Enter a regex pattern to begin", "neutral")
            self.output_meta_label.config(text="Start with a pattern to wake up the result pane.")
            return

        flags = self._get_regex_flags()
        try:
            pattern = re.compile(pattern_str, flags)
        except re.error as exc:
            self.input_text.tag_remove("highlight", "1.0", tk.END)
            self._set_match_badge("Invalid pattern", tone="error")
            self.output_meta_label.config(text="Fix the pattern to see fresh results.")
            self._set_status(f"Invalid regex: {exc}", "error")
            return

        if self.file_source_path:
            if self._line_mode_dotall_requested(pattern_str):
                self._set_match_badge("Line mode only", tone="warning")
                self.output_meta_label.config(
                    text=(
                        "File-backed mode scans one line at a time. Use the editor or cache mode for cross-line "
                        "patterns, whole-file anchors, or replacement previews."
                    )
                )
                self._set_status("Dot All requires editor or cache mode", "warning")
                return
            self._process_file_backed(pattern)
            return

        text, text_source = self._get_active_text()

        if not text:
            self._set_status("Paste or load text to search", "neutral")
            self.output_meta_label.config(text="The result pane fills once source text is available.")
            return

        # Highlight every match in the input pane and capture the displayed results.
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)

        display_items = []
        result_records = []
        match_positions = []
        total_count = 0
        group_count = pattern.groups
        can_highlight = text_source == "input" and len(text) <= self._HIGHLIGHT_MAX_CHARS
        output_limit_reached = False
        unique_only = self.unique_matches.get()
        seen = set() if unique_only else None

        for match in pattern.finditer(text):
            total_count += 1

            if can_highlight:
                self.input_text.tag_add(
                    "highlight",
                    f"1.0 + {match.start()} chars",
                    f"1.0 + {match.end()} chars",
                )

            value, captures = self._extract_match_value(match, group_count)

            if seen is not None:
                if value in seen:
                    continue
                seen.add(value)

            if len(display_items) < self._OUTPUT_MAX_MATCHES:
                display_items.append(value)
                result_records.append(self._build_editor_result_record(match, value, captures, text_source))
                if can_highlight:
                    match_positions.append((match.start(), match.end()))
            else:
                output_limit_reached = True

        self.result_records = result_records
        source_note = " (cached input)" if text_source == "cache" else ""
        detail = (
            "Click a result line to jump back to the source."
            if can_highlight
            else "Results extracted. Jump highlighting is disabled for cached or very large input."
        )
        detail = f"{detail} Export JSONL keeps offsets and capture groups."
        if unique_only:
            noun = "result" if len(display_items) == 1 else "results"
            detail = f"{detail} Showing {len(display_items):,} unique {noun}."
        if output_limit_reached:
            detail = f"{detail} Output is capped at the first {self._OUTPUT_MAX_MATCHES:,} matches."

        status_text = (
            f"Found {total_count} match(es){source_note}"
            if can_highlight
            else (
                f"Found {total_count} match(es){source_note}. "
                "Highlight jumps are paused for large or cached input."
            )
        )
        self._render_results(
            display_items,
            total_count,
            detail=detail,
            no_match_detail="No results for the current pattern.",
            status_text=status_text,
            can_click=can_highlight,
            match_positions=match_positions,
            output_limit_reached=output_limit_reached,
        )

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

        if self.file_source_path:
            self._replace_result = ""
            self.replace_copy_btn.grid_remove()
            self._set_file_source_replace_state()
            return

        if len(text) > self._LARGE_TEXT_THRESHOLD:
            self.replace_preview_label.config(
                text="Preview skipped for large input. Copy Result will run the full replacement.",
                foreground=self._PALETTE["muted"],
            )
            self.replace_copy_btn.grid()
            self._replace_result = ""
            return

        try:
            result = pattern.sub(repl, text)
        except re.error as exc:
            self.replace_preview_label.config(
                text=f"Replacement error: {exc}",
                foreground=self._PALETTE["error"],
            )
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
            foreground=self._PALETTE["muted"],
        )
        self.replace_copy_btn.grid()

    def _copy_replace_result(self):
        """Copy the full replacement result to the clipboard."""
        if self._replace_result:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._replace_result)
            self._set_status("Replacement result copied to clipboard", "success")
            return

        if self.file_source_path:
            self._set_status(
                "Replacement copy is disabled in file-backed line mode. Load smaller text into the editor or cache first.",
                "warning",
            )
            return

        repl = self.replace_entry.get()
        if not repl:
            self._set_status("No replacement pattern set", "warning")
            return

        pattern_str = self._current_pattern_text()
        text, _ = self._get_active_text()
        if pattern_str == "" or not text:
            self._set_status("Need pattern and input text", "warning")
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
            self._set_status(f"Replacement error: {exc}", "error")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self._set_status("Replacement result copied to clipboard", "success")

    # ── Click-to-jump ────────────────────────────────────────────────

    def _on_output_click(self, event):
        """Jump to the corresponding match in the input when an output line is clicked."""
        if not self.output_click_enabled:
            return

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

        self._set_status(
            f"Jumped to match {idx + 1} of {len(self.match_positions)}",
            "success",
        )

    # ── Clipboard helpers (tkinter-native, no external deps) ─────────

    def _paste_from_clipboard(self):
        """Paste clipboard contents into the input area."""
        try:
            content = self.root.clipboard_get()
        except tk.TclError:
            self._set_status("Clipboard is empty", "warning")
            return

        if content:
            self._cancel_file_scan()
            self._clear_cached_input_file()
            self._clear_file_source()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", content)
            self._check_paste_button()
            self._on_content_change()
            self._set_status("Pasted from clipboard", "success")

    def _copy_to_clipboard(self):
        """Copy the output matches to the system clipboard."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish before copying results", "warning")
            return

        content = self.output_text.get("1.0", tk.END).strip()
        if not content or content == "(No matches found)":
            messagebox.showwarning("Warning", "No content to copy to clipboard")
            self._set_status("Nothing to copy", "error")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("Copied to clipboard", "success")

    # ── File I/O ─────────────────────────────────────────────────────

    def _compile_current_pattern_for_action(self, *, require_line_mode=False):
        """Compile the current pattern for save/delete actions."""
        pattern_str = self._current_pattern_text()
        if pattern_str == "":
            self._set_status("Enter a regex pattern first", "warning")
            return None

        try:
            compiled = re.compile(pattern_str, self._get_regex_flags())
        except re.error as exc:
            self._set_status(f"Invalid regex: {exc}", "error")
            return None

        if require_line_mode and self._line_mode_dotall_requested(pattern_str):
            self._set_status("Dot All is not available for gigabyte-safe line-mode file operations", "warning")
            return None

        return compiled

    def _iter_match_values(self, pattern, text, *, unique_only=None):
        """Yield displayed match values from text using the app's capture rules."""
        seen = set() if (self.unique_matches.get() if unique_only is None else unique_only) else None
        group_count = pattern.groups
        for match in pattern.finditer(text):
            value, _captures = self._extract_match_value(match, group_count)
            if seen is not None:
                if value in seen:
                    continue
                seen.add(value)
            yield value

    def _write_match_values_to_file(self, pattern, text, path):
        """Write every match value from text to path without the preview cap."""
        delimiter = self._delimiter_text()
        count = 0
        with open(path, "w", encoding="utf-8") as file_obj:
            for value in self._iter_match_values(pattern, text):
                if count:
                    file_obj.write(delimiter)
                file_obj.write(value)
                count += 1
        return count

    def _keep_only_matches_in_source(self):
        """Replace editor text with the full match-only output."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish first", "warning")
            return
        if self.file_source_path or self.cached_input_path:
            self._set_status("Use Save Matches for file-backed or cached sources.", "warning")
            return

        text = self.input_text.get("1.0", "end-1c")
        if not text:
            self._set_status("Paste or load editor text first", "warning")
            return

        pattern = self._compile_current_pattern_for_action()
        if pattern is None:
            return

        replacement = self._delimiter_text().join(self._iter_match_values(pattern, text))
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", replacement)
        self._reset_output_state()
        self._check_paste_button()
        self._set_status("Source replaced with regex matches only", "success")
        self._on_content_change()

    def _delete_matches_from_source(self):
        """Delete current regex matches from editor text."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish first", "warning")
            return
        if self.file_source_path or self.cached_input_path:
            self._set_status("Use Save Cleaned for file-backed or cached sources.", "warning")
            return

        text = self.input_text.get("1.0", "end-1c")
        if not text:
            self._set_status("Paste or load editor text first", "warning")
            return

        pattern = self._compile_current_pattern_for_action()
        if pattern is None:
            return

        cleaned, deleted_count = pattern.subn("", text)
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", cleaned)
        self._reset_output_state()
        self._check_paste_button()
        self._set_status(f"Deleted {deleted_count:,} regex match(es) from the editor source", "success")
        self._on_content_change()

    def _save_all_matches_to_file(self):
        """Save every match, not just the previewed rows, to a text file."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish first", "warning")
            return

        pattern = self._compile_current_pattern_for_action(require_line_mode=bool(self.file_source_path))
        if pattern is None:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        if self.file_source_path:
            self._start_file_output_job(pattern, path, mode="matches")
            return

        text, _source = self._get_active_text()
        if not text:
            self._set_status("Paste, restore, or load text first", "warning")
            return

        try:
            count = self._write_match_values_to_file(pattern, text, path)
        except (OSError, re.error) as exc:
            messagebox.showerror("Error", f"Failed to save matches:\n{exc}")
            self._set_status("Save matches failed", "error")
            return

        self._set_status(f"Saved {count:,} match(es) to {path}", "success")

    def _save_text_without_matches(self):
        """Save a copy of the source with regex matches removed."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish first", "warning")
            return

        pattern = self._compile_current_pattern_for_action(require_line_mode=bool(self.file_source_path))
        if pattern is None:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        if self.file_source_path:
            self._start_file_output_job(pattern, path, mode="cleaned")
            return

        text, _source = self._get_active_text()
        if not text:
            self._set_status("Paste, restore, or load text first", "warning")
            return

        try:
            cleaned, deleted_count = pattern.subn("", text)
            with open(path, "w", encoding="utf-8") as file_obj:
                file_obj.write(cleaned)
        except (OSError, re.error) as exc:
            messagebox.showerror("Error", f"Failed to save cleaned text:\n{exc}")
            self._set_status("Save cleaned text failed", "error")
            return

        self._set_status(f"Saved cleaned copy to {path} after removing {deleted_count:,} match(es)", "success")

    def _start_file_output_job(self, pattern, output_path, *, mode):
        """Start a streaming file-backed output job."""
        if not self.file_source_path:
            return

        self._cancel_file_scan()
        file_obj = None
        try:
            file_obj = open(self.file_source_path, "rb")
            output_file_obj = open(output_path, "w", encoding="utf-8")
        except OSError as exc:
            if file_obj:
                try:
                    file_obj.close()
                except OSError:
                    pass
            self._set_status(f"Could not start file job: {exc}", "error")
            return

        generation = self.scan_generation
        operation_label = "save matches" if mode == "matches" else "save cleaned copy"
        self.scan_in_progress = True
        self._set_long_operation_active(True)
        self.file_scan_context = {
            "generation": generation,
            "operation": mode,
            "operation_label": operation_label,
            "file_path": self.file_source_path,
            "output_path": output_path,
            "file_obj": file_obj,
            "output_file_obj": output_file_obj,
            "pattern": pattern,
            "group_count": pattern.groups,
            "total_count": 0,
            "written_count": 0,
            "seen": set() if self.unique_matches.get() and mode == "matches" else None,
            "line_number": 0,
            "processed_bytes": 0,
            "file_size": self.file_source_size,
            "delimiter": self._delimiter_text(),
        }

        self._set_match_badge("Saving...", tone="accent")
        self._set_status(f"Streaming {operation_label} from {os.path.basename(self.file_source_path)}...", "neutral")
        self.root.after(1, lambda: self._continue_file_output_job(generation))

    def _continue_file_output_job(self, generation):
        """Process the next slice of a streaming file output job."""
        context = self.file_scan_context
        if not context or generation != self.scan_generation or context.get("generation") != generation:
            return

        try:
            for _ in range(self._FILE_SCAN_BATCH_LINES):
                line_bytes = context["file_obj"].readline()
                if not line_bytes:
                    self._finish_file_output_job(generation)
                    return

                line = line_bytes.decode("utf-8", errors="replace")
                context["line_number"] += 1
                context["processed_bytes"] += len(line_bytes)

                if context["operation"] == "matches":
                    for match in context["pattern"].finditer(line):
                        context["total_count"] += 1
                        value, _captures = self._extract_match_value(match, context["group_count"])
                        seen = context["seen"]
                        if seen is not None:
                            if value in seen:
                                continue
                            seen.add(value)
                        if context["written_count"]:
                            context["output_file_obj"].write(context["delimiter"])
                        context["output_file_obj"].write(value)
                        context["written_count"] += 1
                else:
                    cleaned, deleted_count = context["pattern"].subn("", line)
                    context["total_count"] += deleted_count
                    context["output_file_obj"].write(cleaned)
        except (OSError, re.error) as exc:
            self._fail_file_scan(generation, exc)
            return

        filename = os.path.basename(context["file_path"])
        processed = context["processed_bytes"]
        total = context["file_size"]
        pct = min(100, int((processed / total) * 100)) if total else 0
        if context["operation"] == "matches":
            badge = f"{context['written_count']:,} saved"
        else:
            badge = f"{context['total_count']:,} removed"
        self._set_match_badge(badge, tone="accent")
        self._set_status(
            (
                f"Streaming {context['operation_label']} from {filename}... "
                f"{self._format_file_size(processed)} / {self._format_file_size(total)} ({pct}%)"
            ),
            "neutral",
        )
        self.root.after(1, lambda: self._continue_file_output_job(generation))

    def _finish_file_output_job(self, generation):
        """Finish a streaming file-backed output job."""
        context = self.file_scan_context
        if not context or generation != self.scan_generation or context.get("generation") != generation:
            return

        for key in ("file_obj", "output_file_obj"):
            file_obj = context.get(key)
            if file_obj:
                try:
                    file_obj.close()
                except OSError:
                    pass

        self.file_scan_context = None
        self.scan_in_progress = False
        self._set_long_operation_active(False)

        if context["operation"] == "matches":
            self._set_match_badge(f"{context['written_count']:,} saved", tone="accent")
            self._set_status(
                f"Saved {context['written_count']:,} match(es) to {context['output_path']}",
                "success",
            )
        else:
            self._set_match_badge(f"{context['total_count']:,} removed", tone="accent")
            self._set_status(
                f"Saved cleaned copy to {context['output_path']} after removing {context['total_count']:,} match(es)",
                "success",
            )

    def _save_to_file(self):
        """Save output matches to a user-chosen text file."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish before saving results", "warning")
            return

        content = self.output_text.get("1.0", tk.END).strip()
        if not content or content == "(No matches found)":
            messagebox.showwarning("Warning", "No content to save")
            self._set_status("Nothing to save", "error")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                self._set_status(f"Saved to {path}", "success")
            except OSError as exc:
                messagebox.showerror("Error", f"Failed to save file:\n{exc}")
                self._set_status("Save failed", "error")

    def _export_results_jsonl(self):
        """Export the current structured result rows as JSON Lines."""
        if self.scan_in_progress:
            self._set_status("Wait for the active file job to finish before exporting JSONL", "warning")
            return

        if not self.result_records:
            messagebox.showwarning("Warning", "No structured results to export")
            self._set_status("Nothing to export", "error")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as file_obj:
                for record in self.result_records:
                    file_obj.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._set_status(f"Exported {len(self.result_records):,} structured rows to {path}", "success")
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to export JSONL:\n{exc}")
            self._set_status("JSONL export failed", "error")

    def _load_from_file(self):
        """Load a text file into the input area."""
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            try:
                size = os.path.getsize(path)
                self._cancel_file_scan()
                if size > self._EDITOR_LOAD_MAX_BYTES:
                    self._activate_file_source(path, size)
                    return

                content = self._read_text_file(path)
                self._clear_cached_input_file()
                self._clear_file_source()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert("1.0", content)
                self._reset_output_state()
                self._check_paste_button()
                self._set_status(f"Loaded {path}", "success")
                self._on_content_change()
            except OSError as exc:
                messagebox.showerror("Error", f"Failed to load file:\n{exc}")
                self._set_status("Load failed", "error")

    def _cache_input(self):
        """Move current input text into a temp file cache and unload textbox content."""
        text = self.input_text.get("1.0", "end-1c")
        if not text and self.file_source_path:
            self._set_status("The current source is already file-backed. Press Match Now to scan it directly.", "warning")
            return
        if not text:
            self._set_status("No input text to cache", "warning")
            return

        self._cancel_file_scan()
        self._clear_file_source()
        self._clear_cached_input_file()

        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False, suffix=".regex-isolator-cache.txt"
            ) as tmp:
                tmp.write(text)
                self.cached_input_path = tmp.name
        except OSError as exc:
            self._set_status(f"Cache failed: {exc}", "error")
            return

        self.cached_input_chars = len(text)
        self.input_text.delete("1.0", tk.END)
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self.match_positions.clear()
        self.output_click_enabled = False
        self.output_text.config(cursor="arrow")
        self._check_paste_button()
        self.live_matching.set(False)
        self._sync_live_mode_badge()
        self._set_status(
            f"Input cached ({self.cached_input_chars:,} chars). Press Match Now to process.",
            "success",
        )

    def _restore_cached_input(self):
        """Restore cached text back into the input textbox."""
        if not self.cached_input_path:
            self._set_status("No cached input to restore", "warning")
            return

        try:
            self._cancel_file_scan()
            content = self._read_text_file(self.cached_input_path)
        except OSError as exc:
            self._set_status(f"Restore failed: {exc}", "error")
            return

        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", content)
        self._clear_file_source()
        self._clear_cached_input_file()
        self._check_paste_button()
        self._set_status("Restored cached input", "success")
        self._on_content_change()

    def _read_text_file(self, path):
        """Read text using UTF-8 with replacement so large logs are more forgiving."""
        with open(path, "r", encoding="utf-8", errors="replace") as file_obj:
            return file_obj.read()

    def _activate_file_source(self, path, size):
        """Switch the app into direct file mode without loading the file into the editor."""
        self._clear_cached_input_file()
        self._clear_file_source()
        self.file_source_path = path
        self.file_source_size = size
        self.input_text.delete("1.0", tk.END)
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self._reset_output_state()
        self.live_matching.set(False)
        self._sync_live_mode_badge()
        self._check_paste_button()
        self._update_pattern_coach()
        self._set_status(
            (
                f"Loaded {os.path.basename(path)} in file-backed mode "
                f"({self._format_file_size(size)}). Press Match Now to scan it line by line."
            ),
            "success",
        )

    def _get_active_text(self):
        """Return active input text and source ('input' or 'cache')."""
        text = self.input_text.get("1.0", "end-1c")
        if text:
            return text, "input"

        if self.cached_input_path:
            try:
                return self._read_text_file(self.cached_input_path), "cache"
            except OSError:
                self._clear_cached_input_file()

        return "", "input"

    def _clear_file_source(self):
        """Forget the current file-backed source selection."""
        self.file_source_path = None
        self.file_source_size = 0
        self._update_pattern_coach()

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
        ("Replacement", [
            (r"\1",          "Insert capture group 1 in a replacement"),
            (r"\g<name>",    "Insert a named capture group"),
            (r"\n \t",       "Insert newline or tab in replacement text"),
            ("Delete",       "Use an empty replacement to remove matches"),
        ]),
        ("Large File Workflow", [
            ("Line mode",    "Files over 16 MiB stay on disk and scan one line at a time"),
            ("Save Matches", "Streams every match to a file without the 5,000-row preview cap"),
            ("Save Cleaned", "Streams a copy with matches removed without loading the source"),
            ("Cancel Job",   "Stops long file scans and streaming save jobs"),
        ]),
        ("Performance Tips", [
            ("literal",      "Start with a literal or anchored prefix when possible"),
            (".*",           "Avoid leading or repeated dot-star on huge input"),
            ("(?:...)",      "Use non-capturing groups when you do not need captures"),
            ("{0,200}",      "Prefer bounded repeats over open-ended wildcards"),
            ("line-safe",    "Use file-backed mode for gigabyte logs; avoid Dot All there"),
        ]),
        ("Common Recipes", [
            ("Email",        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
            ("IPv4",         r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
            ("Quoted text",  r'"([^"\\]|\\.)*"'),
            ("Log level",    r"\b(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\b"),
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
        win.title("Regex Tutorial and Syntax Reference")
        win.geometry("640x720")
        win.resizable(True, True)
        win.configure(bg=self._PALETTE["bg"])
        self._help_win = win

        text = scrolledtext.ScrolledText(
            win,
            wrap=tk.WORD,
            font=self._fonts["mono"],
            padx=10,
            pady=10,
            state="normal",
            cursor="arrow",
        )
        text.pack(fill=tk.BOTH, expand=True, padx=18, pady=18)
        self._configure_text_area(text, role="output")
        text.configure(bg=self._PALETTE["editor"], padx=18, pady=18)

        # Tag styles
        text.tag_config(
            "heading",
            font=self._fonts["section"],
            foreground=self._PALETTE["text"],
            spacing3=6,
        )
        text.tag_config(
            "syntax",
            font=self._fonts["mono_bold"],
            foreground=self._PALETTE["accent_dark"],
        )
        text.tag_config(
            "desc",
            font=self._fonts["body"],
            foreground=self._PALETTE["muted"],
        )
        text.tag_config("sep", spacing3=4)

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
        self._cancel_file_scan()
        self.regex_entry.delete(0, tk.END)
        self.replace_entry.delete(0, tk.END)
        self.input_text.delete("1.0", tk.END)
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self._reset_output_state()
        self._check_paste_button()
        self.unique_matches.set(False)
        self.delimiter_var.set("Newline")
        self.preset_var.set(self._PRESET_PLACEHOLDER)
        self.preset_name_entry.delete(0, tk.END)
        self._clear_file_source()
        self._clear_cached_input_file()
        self._set_status("Cleared", "success")

    def _on_close(self):
        """Clean up temporary cache files before exiting."""
        self._cancel_file_scan()
        self._clear_cached_input_file()
        self.root.destroy()


def main():
    root = tk.Tk()
    RegexIsolatorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
