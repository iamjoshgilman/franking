"""TUI smoke tests.

These drive the real app through Textual's pilot rather than snapshotting,
so they check behaviour (navigation, search, copy payloads) and stay stable
when the styling changes.
"""

import asyncio
import time

import pytest

textual = pytest.importorskip("textual")

from textual.css.query import NoMatches  # noqa: E402

from franking.model import Node, Severity  # noqa: E402
from franking.tui.app import FrankingApp, _row  # noqa: E402

MOUNT_TIMEOUT = 10.0


async def _await_mount(app, pilot, timeout: float = MOUNT_TIMEOUT) -> None:
    """Wait until the widgets the tests query actually exist.

    A single pilot.pause() is enough on a quiet machine but not on a loaded CI
    runner, where the app has not finished composing yet and the tests fail
    with a confusing NoMatches instead of a timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            app.query_one("#spine")
            app.query_one("#items")
            return
        except NoMatches:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"app did not finish mounting within {timeout:g}s"
                ) from None
            await pilot.pause()


def drive(app, coro):
    async def runner():
        async with app.run_test(size=(120, 32)) as pilot:
            await pilot.pause()
            await _await_mount(app, pilot)
            return await coro(app, pilot)
    return asyncio.run(runner())


@pytest.fixture
def app(phish, phish_findings):
    return FrankingApp(phish, phish_findings)


async def goto(app, pilot, section: str):
    """Put the cursor on a named section with the spine focused.

    Tests have to say which section they mean: the panes to the right only
    exist when the selected row actually has children, so starting in
    Summary (whose first row is a leaf) proves nothing about navigation.
    """
    index = next(i for i, s in enumerate(app.sections) if s.label == section)
    spine = app.query_one("#spine")
    spine.focus()
    spine.highlighted = index
    await pilot.pause()


class TestRowRendering:
    def test_truncates_to_the_given_width(self):
        node = Node("a-very-long-label-that-will-not-fit", value="x" * 200)
        assert _row(node, 20).cell_len <= 20

    def test_shows_a_badge_when_present(self):
        assert "[7]" in _row(Node("Findings", badge="7"), 40).plain

    def test_shows_child_count_for_a_branch(self):
        node = Node("Parent", children=[Node("a"), Node("b")])
        assert "2" in _row(node, 40).plain

    def test_severity_glyph_is_prefixed(self):
        row = _row(Node("Bad", severity=Severity.CRITICAL), 40).plain
        assert row.startswith(Severity.CRITICAL.glyph)


class TestNavigation:
    def test_mounts_with_every_section(self, app):
        async def check(app, pilot):
            return [s.label for s in app.sections]
        labels = drive(app, check)
        assert "Findings" in labels
        assert "IOCs" in labels

    def test_f_jumps_to_findings(self, app):
        async def check(app, pilot):
            await pilot.press("f")
            await pilot.pause()
            return app.current_container.label
        assert drive(app, check) == "Findings"

    def test_right_walks_the_three_panes(self, app):
        async def check(app, pilot):
            await goto(app, pilot, "Attachments")
            seen = [app.focused.id]
            for _ in range(2):
                await pilot.press("l")
                await pilot.pause()
                seen.append(app.focused.id)
            return seen
        assert drive(app, check) == ["spine", "items", "fields"]

    def test_left_walks_back(self, app):
        async def check(app, pilot):
            await goto(app, pilot, "Attachments")
            await pilot.press("l", "l")
            await pilot.pause()
            seen = [app.focused.id]
            for _ in range(2):
                await pilot.press("h")
                await pilot.pause()
                seen.append(app.focused.id)
            return seen
        assert drive(app, check) == ["fields", "items", "spine"]

    def test_tab_cycles_panes(self, app):
        async def check(app, pilot):
            await goto(app, pilot, "Attachments")
            seen = []
            for _ in range(4):
                await pilot.press("tab")
                await pilot.pause()
                seen.append(app.focused.id)
            return seen
        assert drive(app, check) == ["items", "fields", "spine", "items"]

    def test_fields_pane_hides_for_a_leaf_row(self, app):
        async def check(app, pilot):
            await goto(app, pilot, "Summary")
            await pilot.press("l")  # items; first row "Verdict" is a leaf
            await pilot.pause()
            return app.query_one("#fields").display, app.focused.id
        displayed, focus = drive(app, check)
        assert displayed is False
        assert focus == "items"

    def test_a_field_with_children_reroots_the_middle_column(self, app):
        """Archive contents live a level below the attachment's fields."""
        async def check(app, pilot):
            await goto(app, pilot, "Attachments")
            await pilot.press("l", "l")
            await pilot.pause()
            before = app.current_container.label
            while not (app.selected_field and app.selected_field.children):
                await pilot.press("j")
                await pilot.pause()
            promoted = app.selected_field.label
            await pilot.press("l")
            await pilot.pause()
            return before, promoted, app.current_container.label
        before, promoted, after = drive(app, check)
        assert promoted == "Contents"
        assert after != before

    def test_ascend_at_the_root_does_not_crash(self, app):
        async def check(app, pilot):
            for _ in range(5):
                await pilot.press("h")
                await pilot.pause()
            return app.current_container.label
        assert drive(app, check)

    def test_right_on_a_leaf_field_is_a_no_op(self, app):
        async def check(app, pilot):
            await pilot.press("f")
            await pilot.press("l", "l")
            await pilot.pause()
            before = app.current_container.label
            await pilot.press("l")  # "Rule" is a leaf
            await pilot.pause()
            return before, app.current_container.label
        before, after = drive(app, check)
        assert before == after


class TestCopyTarget:
    """`y` must copy whatever the focused pane points at."""

    def test_copies_the_row_when_items_has_focus(self, app):
        async def check(app, pilot):
            await pilot.press("l")
            await pilot.pause()
            return app.focused.id, app.focused_node.value
        pane, value = drive(app, check)
        assert pane == "items"
        assert value == app.sections[0].children[0].value

    def test_copies_the_field_when_the_field_cursor_is_active(self, app):
        """The bug this pane exists to fix: y on a hash must give the hash."""
        async def check(app, pilot):
            index = next(i for i, s in enumerate(app.sections)
                         if s.label == "Attachments")
            for _ in range(index):
                await pilot.press("j")
            await pilot.press("l", "l")
            await pilot.pause()
            while app.selected_field.label != "SHA-256":
                await pilot.press("j")
                await pilot.pause()
            return app.focused_node.label, app.focused_node.value
        label, value = drive(app, check)
        assert label == "SHA-256"
        assert value == app.doc.attachments[0].sha256
        assert len(value) == 64

    def test_hash_shortcut_works_from_the_section_row(self, app):
        async def check(app, pilot):
            index = next(i for i, s in enumerate(app.sections)
                         if s.label == "Attachments")
            for _ in range(index):
                await pilot.press("j")
            await pilot.press("l")
            await pilot.pause()
            return [n.value for n in app._context_nodes()
                    if n.label == "SHA-256" and n.value]
        hashes = drive(app, check)
        assert hashes and hashes[0] == app.doc.attachments[0].sha256


class TestSearch:
    def test_finds_matching_nodes(self, app):
        async def check(app, pilot):
            await pilot.press("slash")
            await pilot.pause()
            app.query_one("#search").value = "sha-256"
            await pilot.press("enter")
            await pilot.pause()
            return app.current_container
        container = drive(app, check)
        assert container.label.startswith("Search:")
        assert container.children

    def test_no_match_leaves_the_view_alone(self, app):
        async def check(app, pilot):
            before = app.current_container.label
            await pilot.press("slash")
            await pilot.pause()
            app.query_one("#search").value = "zzzz-not-present"
            await pilot.press("enter")
            await pilot.pause()
            return before, app.current_container.label
        before, after = drive(app, check)
        assert before == after


class TestCopyPayloads:
    """Clipboard writes are environment-dependent, so assert on the payload."""

    def test_section_payload_covers_every_row(self, app):
        async def check(app, pilot):
            await pilot.press("f")
            await pilot.pause()
            return [
                f"{c.label}: {c.value}" if c.value else c.label
                for c in app.current_container.children
            ]
        lines = drive(app, check)
        assert len(lines) == len(app.findings)

    def test_ioc_payload_contains_the_key_indicators(self, app):
        section = next(s for s in app.sections if s.label == "IOCs")
        payload = "\n".join(f"{c.label}: {c.value}" for c in section.children)
        assert "billing@acme-invoices.example" in payload
        assert "statement_march.pdf.exe" in payload
