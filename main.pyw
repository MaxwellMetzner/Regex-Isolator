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
        self.custom_presets = {}

        self._configure_window()
        self._build_ui()
        self._load_custom_presets()
        self._refresh_preset_values()
        self._bind_events()
        self._check_paste_button()
        self._sync_live_mode_badge()
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

    def _refresh_input_overview(self):
        """Refresh small UI summaries describing where the source text lives."""
        text = self.input_text.get("1.0", "end-1c")
        if text:
            summary = f"{len(text):,} characters in the editor"
            source = "Source: editor"
        elif self.cached_input_path:
            summary = f"Input cached off-screen • {self.cached_input_chars:,} characters"
            source = "Source: cache"
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
        ttk.Button(controls, text="Help", style="HeroSecondary.TButton", command=self._show_help).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(controls, text="Clear All", style="HeroPrimary.TButton", command=self._clear_all).grid(row=0, column=2)

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
        ttk.Button(actions, text="Save", style="Secondary.TButton", command=self._save_to_file).grid(row=0, column=1)

        tools = ttk.Frame(parent, style="Card.TFrame")
        tools.grid(row=1, column=0, sticky="ew", pady=(14, 12))

        self.match_count_label = tk.Label(
            tools,
            text="0 matches",
            bg=self._PALETTE["surface_alt"],
            fg=self._PALETTE["muted"],
            font=self._fonts["badge"],
            padx=12,
            pady=6,
        )
        self.match_count_label.pack(side=tk.LEFT)

        self.unique_matches = tk.BooleanVar()
        ttk.Checkbutton(tools, text="Unique only", variable=self.unique_matches, style="Card.TCheckbutton", command=self._on_content_change).pack(side=tk.LEFT, padx=(16, 14))
        ttk.Label(tools, text="Delimiter", style="FieldLabel.TLabel").pack(side=tk.LEFT, padx=(0, 8))
        self.delimiter_var = tk.StringVar(value="Newline")
        delim_combo = ttk.Combobox(tools, textvariable=self.delimiter_var, values=["Newline", "Comma", "Tab", "Space"], state="readonly", width=10)
        delim_combo.pack(side=tk.LEFT)
        delim_combo.bind("<<ComboboxSelected>>", self._on_content_change)

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
        """Show a centered empty state when the source editor is empty or cached."""
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
        self.output_click_enabled = False
        self.output_text.config(cursor="arrow")

        if not self.live_matching.get():
            if self.update_timer:
                self.root.after_cancel(self.update_timer)
                self.update_timer = None
            self._set_status("Live matching off. Press Match Now to refresh results.", "neutral")
            return

        if self.update_timer:
            self.root.after_cancel(self.update_timer)
        self.update_timer = self.root.after(300, self._process)

    def _on_live_toggle(self):
        """Switch between automatic debounced matching and manual matching."""
        self._sync_live_mode_badge()
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
        if self.update_timer:
            self.root.after_cancel(self.update_timer)
            self.update_timer = None
        self._process()

    # ── Core regex processing ────────────────────────────────────────

    def _process(self):
        """Run the regex against the input and update highlights + output."""
        pattern_str = self.regex_entry.get().strip()
        text, text_source = self._get_active_text()

        # Reset output state
        self.output_click_enabled = False
        self.match_positions.clear()
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(cursor="arrow")
        self._set_match_badge("0 matches", tone="neutral")
        self.output_meta_label.config(
            text="Run a pattern to isolate results. In newline mode, clicking a line jumps back to the source span."
        )
        self._toggle_output_empty_state(True)
        self.replace_preview_label.config(text="", foreground=self._PALETTE["muted"])
        self.replace_copy_btn.grid_remove()
        self._replace_result = ""

        if not pattern_str:
            self.input_text.tag_remove("highlight", "1.0", tk.END)
            self._set_status("Enter a regex pattern to begin", "neutral")
            self.output_meta_label.config(text="Start with a pattern to wake up the result pane.")
            self.output_text.config(state="disabled")
            return

        if not text:
            self._set_status("Paste or load text to search", "neutral")
            self.output_meta_label.config(text="The result pane fills once source text is available.")
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
            self._set_match_badge("Invalid pattern", tone="error")
            self.output_meta_label.config(text="Fix the pattern to see fresh results.")
            self._set_status(f"Invalid regex: {exc}", "error")
            return

        # Highlight every match in the input pane and capture the displayed results.
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)

        display_items = []
        total_count = 0
        group_count = pattern.groups
        can_highlight = text_source == "input" and len(text) <= self._HIGHLIGHT_MAX_CHARS
        output_limit_reached = False

        for match in pattern.finditer(text):
            total_count += 1

            if can_highlight:
                self.input_text.tag_add(
                    "highlight",
                    f"1.0 + {match.start()} chars",
                    f"1.0 + {match.end()} chars",
                )

            if group_count == 0:
                value = match.group(0)
            elif group_count == 1:
                value = match.group(1) or ""
            else:
                value = "".join(group for group in match.groups() if group)

            if len(display_items) < self._OUTPUT_MAX_MATCHES:
                display_items.append((value, (match.start(), match.end())))
            else:
                output_limit_reached = True

        # Optionally deduplicate while preserving order
        if self.unique_matches.get():
            seen = set()
            unique_items = []
            for value, position in display_items:
                if value not in seen:
                    seen.add(value)
                    unique_items.append((value, position))
            display_items = unique_items

        processed = [value for value, _position in display_items]
        if can_highlight:
            self.match_positions = [position for _value, position in display_items]

        # Determine output delimiter
        delim_map = {"Newline": "\n", "Comma": ", ", "Tab": "\t", "Space": " "}
        delimiter = delim_map.get(self.delimiter_var.get(), "\n")

        if processed:
            self._toggle_output_empty_state(False)
            self.output_text.insert("1.0", delimiter.join(processed))

            if output_limit_reached:
                self.output_text.insert(
                    tk.END,
                    f"\n\n(Output capped at first {self._OUTPUT_MAX_MATCHES} matches)",
                )

            # Clickable tags only make sense in newline mode
            self.output_click_enabled = delimiter == "\n" and can_highlight
            self.output_text.config(cursor="hand2" if self.output_click_enabled else "arrow")
            if self.output_click_enabled:
                for i in range(len(processed)):
                    tag = f"match_{i}"
                    self.output_text.tag_add(tag, f"{i + 1}.0", f"{i + 1}.end")
                    self.output_text.tag_config(tag, foreground=self._PALETTE["accent_dark"])

            source_note = " (cached input)" if text_source == "cache" else ""
            detail = (
                "Click a result line to jump back to the source."
                if self.output_click_enabled
                else "Results are grouped with the selected delimiter."
                if can_highlight
                else "Results extracted. Jump highlighting is disabled for cached or very large input."
            )
            if self.unique_matches.get():
                noun = "result" if len(processed) == 1 else "results"
                detail = f"{detail} Showing {len(processed):,} unique {noun}."
            if output_limit_reached:
                detail = f"{detail} Output is capped at the first {self._OUTPUT_MAX_MATCHES:,} matches."

            self.output_meta_label.config(text=detail)
            self._set_match_badge(
                f"{total_count} match{'es' if total_count != 1 else ''}",
                tone="accent",
            )
            if can_highlight:
                self._set_status(f"Found {total_count} match(es){source_note}", "success")
            else:
                self._set_status(
                    (
                        f"Found {total_count} match(es){source_note}. "
                        "Highlight jumps are paused for large or cached input."
                    ),
                    "success",
                )
        else:
            self._toggle_output_empty_state(False)
            self.output_text.insert("1.0", "(No matches found)")
            self.output_meta_label.config(text="No results for the current pattern.")
            self._set_match_badge("0 matches", tone="warning")
            self._set_status("No matches found", "warning")

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

        repl = self.replace_entry.get()
        if not repl:
            self._set_status("No replacement pattern set", "warning")
            return

        pattern_str = self.regex_entry.get().strip()
        text, _ = self._get_active_text()
        if not pattern_str or not text:
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
            self._clear_cached_input_file()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", content)
            self._check_paste_button()
            self._on_content_change()
            self._set_status("Pasted from clipboard", "success")

    def _copy_to_clipboard(self):
        """Copy the output matches to the system clipboard."""
        content = self.output_text.get("1.0", tk.END).strip()
        if not content or content == "(No matches found)":
            messagebox.showwarning("Warning", "No content to copy to clipboard")
            self._set_status("Nothing to copy", "error")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("Copied to clipboard", "success")

    # ── File I/O ─────────────────────────────────────────────────────

    def _save_to_file(self):
        """Save output matches to a user-chosen text file."""
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
                self._check_paste_button()
                self._set_status(f"Loaded {path}", "success")
                self._on_content_change()
            except OSError as exc:
                messagebox.showerror("Error", f"Failed to load file:\n{exc}")
                self._set_status("Load failed", "error")

    def _cache_input(self):
        """Move current input text into a temp file cache and unload textbox content."""
        text = self.input_text.get("1.0", "end-1c")
        if not text:
            self._set_status("No input text to cache", "warning")
            return

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
            with open(self.cached_input_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as exc:
            self._set_status(f"Restore failed: {exc}", "error")
            return

        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", content)
        self._clear_cached_input_file()
        self._check_paste_button()
        self._set_status("Restored cached input", "success")
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
        win.geometry("520x600")
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
        self.regex_entry.delete(0, tk.END)
        self.replace_entry.delete(0, tk.END)
        self.input_text.delete("1.0", tk.END)
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        self.input_text.tag_remove("selected_match", "1.0", tk.END)
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled", cursor="arrow")
        self.match_positions.clear()
        self.output_click_enabled = False
        self._check_paste_button()
        self._set_match_badge("0 matches", tone="neutral")
        self.output_meta_label.config(
            text="Run a pattern to isolate results. In newline mode, clicking a line jumps back to the source span."
        )
        self._toggle_output_empty_state(True)
        self.unique_matches.set(False)
        self.delimiter_var.set("Newline")
        self.preset_var.set(self._PRESET_PLACEHOLDER)
        self.preset_name_entry.delete(0, tk.END)
        self.replace_preview_label.config(text="")
        self.replace_copy_btn.grid_remove()
        self._replace_result = ""
        self._clear_cached_input_file()
        self._set_status("Cleared", "success")

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
