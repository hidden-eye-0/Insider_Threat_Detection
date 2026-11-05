"""Dashboard integration: every page renders against real workspace data without exceptions."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from insider import db

PAGES = {"overview": "Overview", "security_events": "Security Events", "employee_risk": "Employee Risk", "behavior": "Behavioral Analytics",
         "investigations": "Threat Investigations", "timeline_page": "Forensic Timeline", "alerts_cases": "Alerts & Cases",
         "reports": "Reports", "settings": "System Settings"}
ROOT = str(Path(__file__).resolve().parent.parent).replace("\\", "/")


def page_app(fn: str) -> AppTest:
    """Run a single page function inside the design shell (without st.navigation)."""
    code = chr(10).join([f"import sys; sys.path.insert(0, r'{ROOT}')", "import streamlit as st",
                      "from dashboard import design as ds, views", "ds.inject_css()", f"views.{fn}()"])
    return AppTest.from_string(code, default_timeout=120)


@pytest.fixture(scope="module")
def demo_ready():
    if not db.workspace_path("demo").exists():
        from insider.cli import init_demo
        init_demo("demo")
    db.set_active_workspace("demo")


def test_shell_renders(demo_ready):
    at = AppTest.from_file("dashboard/app.py", default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    assert len(at.title) + len(at.markdown) > 0


@pytest.mark.parametrize("fn", list(PAGES))
def test_page_renders(demo_ready, fn):
    at = page_app(fn).run()
    assert not at.exception, f"{fn}: {[e.value for e in at.exception]}"
    assert not at.error, f"{fn}: {[e.value for e in at.error]}"
    page_title = PAGES[fn].replace("&", "&amp;")
    assert any(page_title in m.value for m in at.markdown), f"{fn}: header not rendered"


def test_light_theme_configured():
    import tomllib
    cfg = tomllib.loads((Path(ROOT) / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert cfg["theme"]["base"] == "light" and cfg["theme"]["backgroundColor"].lower() == "#f5f7fb"


def test_analyst_actions_persist_through_ui(demo_ready):
    """Drive the Forensic Investigation page on a throwaway copy of the workspace."""
    import shutil
    src, dst = db.workspace_path("demo"), db.workspace_path("pytest_ui")
    shutil.copy(src, dst)
    db.set_active_workspace("pytest_ui")
    try:
        at = page_app("investigations").run()
        assert not at.exception
        alert_id = next(s for s in at.selectbox if s.label == "Case").value
        next(t for t in at.text_area if t.label == "Add note").set_value("UI test note").run()
        next(b for b in at.button if b.label == "Add note").click().run()
        assert not at.exception
        sel = {s.label: s for s in at.selectbox}
        sel["Status"].set_value("Escalated")
        sel["Final disposition"].set_value(db.DISPOSITIONS[1])
        next(b for b in at.button if b.label == "Save status and disposition").click().run()
        assert not at.exception
        con = db.connect(dst)
        inv = con.execute("SELECT * FROM investigations WHERE alert_id=?", (alert_id,)).fetchone()
        notes = con.execute("SELECT note FROM notes WHERE alert_id=?", (alert_id,)).fetchall()
        con.close()
        assert inv["status"] == "Escalated" and inv["disposition"] == db.DISPOSITIONS[1]
        assert [n["note"] for n in notes] == ["UI test note"]
    finally:
        db.set_active_workspace("demo")
        dst.unlink(missing_ok=True)
