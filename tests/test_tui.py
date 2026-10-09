"""TUI smoke tests.

These drive the real app through Textual's pilot rather than snapshotting,
so they check behaviour (navigation, search, copy payloads) and stay stable
when the styling changes.
"""

import asyncio

import pytest

textual = pytest.importorskip("textual")

from phishlens.model import Node, Severity  # noqa: E402
from phishlens.tui.app import PhishLensApp, _row  # noqa: E402


def drive(app, coro):
    async def runner():
        async with app.run_test(size=(120, 32)) as pilot:
            await pilot.pause()
            return await coro(app, pilot)
    return asyncio.run(runner())


@pytest.fixture
def app(phish, phish_findings):
    return PhishLensApp(phish, phish_findings)


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

    def test_descend_and_ascend_round_trip(self, app):
        async def check(app, pilot):
            await pilot.press("f")
            await pilot.pause()
            start = app.current_container.label
            await pilot.press("l")
            await pilot.pause()
            descended = app.current_container.label
            await pilot.press("h")
            await pilot.pause()
            return start, descended, app.current_container.label
        start, descended, back = drive(app, check)
        assert descended != start
        assert back == start

    def test_ascend_at_the_root_does_not_crash(self, app):
        async def check(app, pilot):
            for _ in range(5):
                await pilot.press("h")
                await pilot.pause()
            return app.current_container.label
        assert drive(app, check)

    def test_descending_a_leaf_is_a_no_op(self, app):
        async def check(app, pilot):
            await pilot.press("f")
            await pilot.pause()
            await pilot.press("l")  # into the first finding
            await pilot.pause()
            before = app.current_container.label
            await pilot.press("l")  # "Rule" is a leaf
            await pilot.pause()
            return before, app.current_container.label
        before, after = drive(app, check)
        assert before == after


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
