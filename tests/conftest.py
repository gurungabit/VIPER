"""Shared test fixtures for VIPER tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def npm_report_path() -> Path:
    return FIXTURES_DIR / "snyk_report_npm.json"


@pytest.fixture
def python_report_path() -> Path:
    return FIXTURES_DIR / "snyk_report_python.json"


@pytest.fixture
def maven_report_path() -> Path:
    return FIXTURES_DIR / "snyk_report_maven.json"


@pytest.fixture
def npm_report_data(npm_report_path: Path) -> dict:
    return json.loads(npm_report_path.read_text())


@pytest.fixture
def python_report_data(python_report_path: Path) -> dict:
    return json.loads(python_report_path.read_text())


@pytest.fixture
def maven_report_data(maven_report_path: Path) -> dict:
    return json.loads(maven_report_path.read_text())


@pytest.fixture
def sample_node_project(tmp_path: Path) -> Path:
    """Copy sample node project to a temp directory."""
    src = FIXTURES_DIR / "sample_projects" / "node_project"
    dst = tmp_path / "node_project"
    shutil.copytree(src, dst)
    return dst


@pytest.fixture
def sample_python_project(tmp_path: Path) -> Path:
    """Copy sample python project to a temp directory."""
    src = FIXTURES_DIR / "sample_projects" / "python_project"
    dst = tmp_path / "python_project"
    shutil.copytree(src, dst)
    return dst


@pytest.fixture
def sample_java_project(tmp_path: Path) -> Path:
    """Copy sample java project to a temp directory."""
    src = FIXTURES_DIR / "sample_projects" / "java_project"
    dst = tmp_path / "java_project"
    shutil.copytree(src, dst)
    return dst
