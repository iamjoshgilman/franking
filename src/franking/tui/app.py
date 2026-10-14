"""The interactive browser.

Layout is a spine of sections on the left, the contents of the selected
section in the middle, and a detail pane on the right that shows the value
together with the reasoning behind it. The middle column can be descended
into, ranger-style, with the breadcrumb tracking depth.
"""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Input, OptionList, Static
from textual.widgets.option_list import Option

from franking import clipboard
from franking.model import Finding, Node, Severity
from franking.parse import EmailDoc
from franking.report import json_report
from franking.view import build_tree

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold #ff5c57",
    Severity.HIGH: "#ff9f43",
    Severity.MEDIUM: "#f6c744",
    Severity.LOW: "#5ac8fa",
    Severity.INFO: "#7a8290",
}


def _row(node: Node, width: int) -> Text:
    """Render one list row: glyph, label, and a badge or value preview.

    Rows are truncated to ``width`` here rather than left to the widget.
    Textual converts a Rich ``Text`` into its own ``Content`` type, which
    drops ``no_wrap``, so an over-long row would wrap and break the columns.
    """
    text = Text(no_wrap=True, overflow="ellipsis", end="")
    if node.severity is not None:
        text.append(f"{node.severity.glyph} ", style=SEVERITY_STYLE[node.severity])
    else:
        text.append("  ")

    label_style = SEVERITY_STYLE[node.severity] if node.severity else ""
    text.append(node.label, style=label_style)

    if node.badge:
        text.append(f" [{node.badge}]", style="#7a8290")
    elif node.children:
        text.append(f" › {len(node.children)}", style="#7a8290")
    elif node.value and node.value != node.label:
        room = width - text.cell_len - 2
        if room >= 6:
            preview = node.value.replace("\n", " ").strip()
            text.append("  " + preview, style="#7a8290")

    text.truncate(max(width, 8), overflow="ellipsis")
    return text


class FrankingApp(App):
    """Interactive .eml analysis."""

    CSS_PATH = "app.tcss"
    TITLE = "franking"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("y", "copy_value", "Copy"),
        Binding("Y", "copy_section", "Copy section"),
        Binding("a", "copy_iocs", "Copy IOCs"),
        Binding("H", "copy_hash", "Copy SHA-256"),
        Binding("e", "export", "Export JSON"),
        Binding("slash", "search", "Search", key_display="/"),
        Binding("f", "goto_findings", "Findings"),
        Binding("escape", "dismiss_search", "", show=False),
        # priority, or Textual's own focus walk claims tab first.
        Binding("tab", "focus_next_pane", "", show=False, priority=True),
        Binding("j", "cursor_down", "", show=False),
        Binding("k", "cursor_up", "", show=False),
        Binding("l", "descend", "", show=False),
        Binding("right", "descend", "", show=False),
        Binding("enter", "descend", "", show=False),
        Binding("h", "ascend", "", show=False),
        Binding("left", "ascend", "", show=False),
        Binding("backspace", "ascend", "", show=False),
    ]

    def __init__(self, doc: EmailDoc, findings: list[Finding]):
        super().__init__()
        self.doc = doc
        self.findings = findings
        self.doc_tree = build_tree(doc, findings)
        self.sections = self.doc_tree.children
        # Ancestors of the middle column; the last entry is what it shows.
        self.stack: list[Node] = [self.sections[0]]
        self._search_hits: list[Node] = []

    # -- layout ----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._banner(), id="banner")
        with Horizontal(id="columns"):
            yield OptionList(id="spine")
            yield OptionList(id="items")
            with Vertical(id="detail-wrap"):
                with VerticalScroll(id="detail-scroll"):
                    yield Static(Text(""), id="detail")
                # The fields of the selected row, as their own cursor. The
                # values people actually want to copy -- hashes, IPs, URLs --
                # live here, so this pane has to be reachable.
                yield OptionList(id="fields")
        yield Input(placeholder="search labels and values…", id="search")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#search", Input).display = False
        # The prose is read, not driven; keeping it out of the focus chain
        # means tab only ever lands on the three real columns.
        self.query_one("#detail-scroll", VerticalScroll).can_focus = False
        self._rebuild()
        # Widths are zero until the first layout pass, so rebuild the rows
        # once real sizes exist, otherwise long labels wrap.
        self.call_after_refresh(self._rebuild)
        self.query_one("#spine", OptionList).focus()

    def on_resize(self, event) -> None:
        self._rebuild()

    def _rebuild(self) -> None:
        """Re-render every list against the current column widths."""
        keep = self.query_one("#items", OptionList).highlighted or 0
        self._refresh_spine()
        self._refresh_items(keep=keep)

    @staticmethod
    def _usable_width(widget: OptionList, fallback: int) -> int:
        # One column of slack keeps a full-width row off the wrap boundary,
        # and another leaves room for the scrollbar when one appears.
        width = widget.content_size.width
        return width - 2 if width > 10 else fallback - 2

    def _refresh_spine(self) -> None:
        spine = self.query_one("#spine", OptionList)
        keep = spine.highlighted or 0
        width = self._usable_width(spine, 20)
        spine.clear_options()
        spine.add_options([Option(_row(s, width), id=str(i))
                           for i, s in enumerate(self.sections)])
        spine.highlighted = min(keep, len(self.sections) - 1)

    def _banner(self) -> Text:
        name = self.doc.path.name if self.doc.path else "message"
        worst = max((f.severity for f in self.findings),
                    key=lambda s: s.rank, default=Severity.INFO)
        text = Text()
        text.append(f" {name} ", style="bold #e8eaed")
        text.append(f" {self.doc.subject[:60]} ", style="#7a8290")
        text.append("\n ")
        text.append(f"{len(self.findings)} findings ",
                    style=SEVERITY_STYLE[worst] + " bold")
        text.append(f"· {self.doc.from_addr} ", style="#7a8290")
        text.append(f"· {len(self.doc.attachments)} attachment(s) ",
                    style="#7a8290")
        return text

    def _breadcrumb(self) -> str:
        return "  ›  ".join(n.label for n in self.stack)

    # -- state -----------------------------------------------------------

    @property
    def current_container(self) -> Node:
        return self.stack[-1]

    @property
    def selected(self) -> Node | None:
        """The row highlighted in the middle column."""
        return self._pick(self.query_one("#items", OptionList),
                          self.current_container.children)

    @property
    def selected_field(self) -> Node | None:
        """The row highlighted in the detail column."""
        node = self.selected
        if node is None:
            return None
        return self._pick(self.query_one("#fields", OptionList), node.children)

    @property
    def focused_node(self) -> Node | None:
        """Whatever the focused pane is pointing at.

        This is what ``y`` copies, so the key does the same thing in every
        pane rather than silently meaning "the attachment" when the cursor
        is on its hash.
        """
        if self.query_one("#fields", OptionList).has_focus:
            return self.selected_field or self.selected
        if self.query_one("#spine", OptionList).has_focus:
            return self.current_container
        return self.selected

    @staticmethod
    def _pick(widget: OptionList, children: list[Node]) -> Node | None:
        index = widget.highlighted
        if index is None or not (0 <= index < len(children)):
            return None
        return children[index]

    def _refresh_items(self, keep: int = 0) -> None:
        items = self.query_one("#items", OptionList)
        width = self._usable_width(items, 44)
        items.clear_options()
        children = self.current_container.children
        if children:
            items.add_options([Option(_row(c, width), id=str(i))
                               for i, c in enumerate(children)])
            items.highlighted = min(max(keep, 0), len(children) - 1)
        items.border_title = self._breadcrumb()
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        node = self.selected
        self._render_prose(node)
        self._refresh_fields(node)

    def _render_prose(self, node: Node | None) -> None:
        """Describe one node above the field list.

        When the field cursor is active this describes the selected *field*,
        so a value too wide for the narrow list -- a SHA-256, a long URL --
        is always readable in full somewhere on screen.
        """
        detail = self.query_one("#detail", Static)
        if node is None:
            detail.update(Text("nothing selected", style="#7a8290"))
            return

        text = Text()
        style = SEVERITY_STYLE[node.severity] if node.severity else "bold #e8eaed"
        text.append(node.label + "\n", style=style + " bold")

        if node.severity is not None:
            text.append(f"{node.severity.value.upper()}\n",
                        style=SEVERITY_STYLE[node.severity])
        text.append("\n")

        if node.value:
            text.append("value\n", style="#7a8290")
            text.append(node.value + "\n", style="#9ae66e")
            text.append("\n")

        if node.note:
            text.append("why it matters\n", style="#7a8290")
            text.append(node.note + "\n", style="#c8ccd4")
            text.append("\n")

        detail.update(text)

    def _refresh_fields(self, node: Node | None) -> None:
        """Fill the detail column with the selected row's fields."""
        fields = self.query_one("#fields", OptionList)
        fields.clear_options()
        if node is None or not node.children:
            fields.display = False
            return
        fields.display = True
        width = self._usable_width(fields, 44)
        fields.add_options([Option(_row(c, width), id=str(i))
                            for i, c in enumerate(node.children)])
        fields.highlighted = 0
        fields.border_title = f"{node.label} · fields"

    # -- events ----------------------------------------------------------

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        if event.option_list.id == "spine":
            index = event.option_index
            if index is not None and 0 <= index < len(self.sections):
                self.stack = [self.sections[index]]
                self._refresh_items()
        elif event.option_list.id == "items":
            self._refresh_detail()
        elif event.option_list.id == "fields" and event.option_list.has_focus:
            # Only once the field cursor is in use; repopulating the list
            # also fires this, and that must not clobber the row's own prose.
            self._render_prose(self.selected_field or self.selected)

    def on_descendant_focus(self, event) -> None:
        widget_id = getattr(event.widget, "id", None)
        if widget_id == "fields":
            self._render_prose(self.selected_field or self.selected)
        elif widget_id == "items":
            self._render_prose(self.selected)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        query = event.value.strip().lower()
        self.action_dismiss_search()
        if not query:
            return
        hits: list[Node] = []

        def walk(node: Node) -> None:
            haystack = f"{node.label} {node.value or ''} {node.note or ''}".lower()
            if query in haystack:
                hits.append(node)
            for child in node.children:
                walk(child)

        for section in self.sections:
            walk(section)

        if not hits:
            self.notify(f"no match for {query!r}", severity="warning")
            return
        results = Node(f"Search: {query}", badge=str(len(hits)))
        results.children = hits
        self.stack = [results]
        self._refresh_items()
        self.query_one("#items", OptionList).focus()
        self.notify(f"{len(hits)} match(es)")

    # -- actions ---------------------------------------------------------

    def _panes(self) -> list[OptionList]:
        return [
            self.query_one("#spine", OptionList),
            self.query_one("#items", OptionList),
            self.query_one("#fields", OptionList),
        ]

    def action_focus_next_pane(self) -> None:
        panes = [p for p in self._panes() if p.display]
        current = next((i for i, p in enumerate(panes) if p.has_focus), -1)
        panes[(current + 1) % len(panes)].focus()

    def action_cursor_down(self) -> None:
        self._focused_list().action_cursor_down()

    def action_cursor_up(self) -> None:
        self._focused_list().action_cursor_up()

    def _focused_list(self) -> OptionList:
        for pane in self._panes():
            if pane.has_focus:
                return pane
        return self.query_one("#items", OptionList)

    def action_descend(self) -> None:
        """Move rightwards: spine -> items -> fields, then re-root."""
        spine, items, fields = self._panes()
        if spine.has_focus:
            items.focus()
            return
        if items.has_focus:
            node = self.selected
            if node is not None and node.children:
                fields.focus()
            return
        # Already in the detail column. If this field has detail of its own,
        # promote its parent to the middle column so the field becomes the
        # selected row and its children fill the detail pane in turn.
        field = self.selected_field
        parent = self.selected
        if field is None or parent is None or not field.children:
            return
        index = parent.children.index(field)
        self.stack.append(parent)
        self._refresh_items(keep=index)
        fields.focus()

    def action_ascend(self) -> None:
        spine, items, fields = self._panes()
        if fields.has_focus:
            items.focus()
            return
        if len(self.stack) > 1:
            child = self.stack.pop()
            parent_children = self.current_container.children
            index = parent_children.index(child) if child in parent_children else 0
            self._refresh_items(keep=index)
            items.focus()
        else:
            spine.focus()

    def _copy(self, value: str, what: str = "") -> None:
        # osc52=False: writing that escape to stdout ourselves would land in
        # the middle of Textual's own output. Textual drives the same
        # sequence properly, so it is the fallback instead.
        ok, how = clipboard.copy(value, osc52=False)
        if not ok:
            try:
                self.copy_to_clipboard(value)
                ok, how = True, "terminal"
            except Exception:  # noqa: BLE001 - a failed copy is not fatal
                self.notify(f"copy failed: {how}", severity="error")
                return
        preview = value if len(value) <= 48 else value[:45] + "…"
        self.notify(f"copied {what}{preview}", title=how)

    def action_copy_value(self) -> None:
        node = self.focused_node
        if node is None:
            return
        self._copy(node.value or node.label)

    def action_copy_hash(self) -> None:
        """Copy the SHA-256 of the attachment in context.

        Hashes are the most-copied value in the whole tool and the most
        painful to retype, so they get a key of their own that works from
        anywhere in an attachment's subtree.
        """
        hashes = [
            node.value for node in self._context_nodes()
            if node.label == "SHA-256" and node.value
        ]
        if not hashes:
            if len(self.doc.attachments) == 1:
                self._copy(self.doc.attachments[0].sha256, "SHA-256: ")
                return
            self.notify("no SHA-256 in context; open an attachment first",
                        severity="warning")
            return
        self._copy(hashes[0], "SHA-256: ")

    def _context_nodes(self) -> list[Node]:
        """The selection and everything around it, nearest first."""
        nodes: list[Node] = []
        for candidate in (self.selected_field, self.selected,
                          *reversed(self.stack)):
            if candidate is None:
                continue
            nodes.append(candidate)
            nodes.extend(candidate.children)
        return nodes

    def action_copy_section(self) -> None:
        container = self.current_container
        lines = [
            f"{c.label}: {c.value}" if c.value else c.label
            for c in container.children
        ]
        payload = f"# {container.label}\n" + "\n".join(lines)
        ok, how = clipboard.copy(payload)
        self.notify(
            f"copied {len(lines)} rows via {how}" if ok else f"copy failed: {how}",
            severity="information" if ok else "error",
        )

    def action_copy_iocs(self) -> None:
        section = next((s for s in self.sections if s.label == "IOCs"), None)
        if section is None:
            return
        payload = "\n".join(f"{c.label}: {c.value}" for c in section.children)
        ok, how = clipboard.copy(payload)
        self.notify(
            f"copied {len(section.children)} IOCs via {how}"
            if ok else f"copy failed: {how}",
            severity="information" if ok else "error",
        )

    def action_goto_findings(self) -> None:
        for index, section in enumerate(self.sections):
            if section.label == "Findings":
                spine = self.query_one("#spine", OptionList)
                spine.highlighted = index
                self.query_one("#items", OptionList).focus()
                return

    def action_search(self) -> None:
        search = self.query_one("#search", Input)
        search.display = True
        search.value = ""
        search.focus()

    def action_dismiss_search(self) -> None:
        search = self.query_one("#search", Input)
        if search.display:
            search.display = False
            self.query_one("#items", OptionList).focus()

    def action_export(self) -> None:
        stem = self.doc.path.stem if self.doc.path else "message"
        target = Path.cwd() / f"{stem}.franking.json"
        try:
            # Explicit utf-8: the default is the locale encoding, which on
            # Windows cannot represent the homoglyphs the report exists to show.
            target.write_text(json_report(self.doc, self.findings),
                              encoding="utf-8")
        except OSError as exc:
            self.notify(f"export failed: {exc}", severity="error")
            return
        self.notify(f"wrote {target}")

    def action_help(self) -> None:
        self.notify(
            "j/k move  l/↵ right  h/⌫ left  tab cycle panes\n"
            "y copy the highlighted row, in whichever pane has focus\n"
            "H copy SHA-256  Y copy section  a copy all IOCs\n"
            "/ search  f findings  e export JSON  q quit\n"
            "shift+drag to select text with the mouse",
            title="keys",
            timeout=15,
        )


def run(doc: EmailDoc, findings: list[Finding]) -> None:
    FrankingApp(doc, findings).run()
