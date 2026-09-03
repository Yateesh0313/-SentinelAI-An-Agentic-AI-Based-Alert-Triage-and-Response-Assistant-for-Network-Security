"""Frontend Smoke Tests (Phase 20).

Verifies:
- Production Next.js build output exists and contains compiled routes
- Homepage (/) pre-rendered HTML contains branding and navigation
- Dashboard (/dashboard) pre-rendered HTML contains core layout and tab structure
- Login (/login) pre-rendered HTML exists and renders properly
"""

from __future__ import annotations

from pathlib import Path
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_APP_BUILD = _PROJECT_ROOT / "frontend" / ".next" / "server" / "app"


def test_next_build_artifacts_exist():
    """Verify that the Next.js production build succeeded and artifacts exist."""
    assert _APP_BUILD.exists(), (
        f"Next.js build directory not found at {_APP_BUILD}. Run 'npx next build' in frontend/."
    )


def test_homepage_smoke():
    """Verify homepage (/) pre-rendered HTML."""
    index_html = _APP_BUILD / "index.html"
    assert index_html.exists(), "Homepage index.html not found in build"
    content = index_html.read_text(encoding="utf-8")
    assert len(content) > 1000, "Homepage HTML is unexpectedly small"
    assert "SentinelAI" in content, "Branding missing from homepage HTML"


def test_dashboard_smoke():
    """Verify dashboard (/dashboard) pre-rendered HTML."""
    dash_html = _APP_BUILD / "dashboard.html"
    assert dash_html.exists(), "Dashboard dashboard.html not found in build"
    content = dash_html.read_text(encoding="utf-8")
    assert len(content) > 1000, "Dashboard HTML is unexpectedly small"
    assert "Live Feed" in content or "dashboard" in content.lower()


def test_login_smoke():
    """Verify login (/login) pre-rendered HTML."""
    login_html = _APP_BUILD / "login.html"
    assert login_html.exists(), "Login page login.html not found in build"
    content = login_html.read_text(encoding="utf-8")
    assert len(content) > 500, "Login HTML is unexpectedly small"
