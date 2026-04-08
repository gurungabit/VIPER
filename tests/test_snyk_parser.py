"""Tests for Snyk report parser."""

from pathlib import Path

import pytest

from viper.models.vulnerability import Severity, SnykReport
from viper.parsers.snyk_parser import SnykParser


class TestSnykParser:
    def test_parse_npm_report(self, npm_report_path: Path):
        report = SnykParser.parse_file(npm_report_path)
        assert isinstance(report, SnykReport)
        assert report.ok is False
        assert len(report.vulnerabilities) == 3
        assert report.package_manager == "npm"
        assert report.project_name == "my-project"

    def test_parse_python_report(self, python_report_path: Path):
        report = SnykParser.parse_file(python_report_path)
        assert len(report.vulnerabilities) == 2
        assert report.package_manager == "pip"

    def test_parse_maven_report(self, maven_report_path: Path):
        report = SnykParser.parse_file(maven_report_path)
        assert len(report.vulnerabilities) == 2
        assert report.package_manager == "maven"

    def test_parse_json_dict(self, npm_report_data: dict):
        report = SnykParser.parse_json(npm_report_data)
        assert len(report.vulnerabilities) == 3

    def test_parse_json_list(self, npm_report_data: dict, python_report_data: dict):
        report = SnykParser.parse_json([npm_report_data, python_report_data])
        assert len(report.vulnerabilities) == 5  # 3 + 2

    def test_parse_empty_list(self):
        report = SnykParser.parse_json([])
        assert len(report.vulnerabilities) == 0

    def test_filter_by_severity(self, npm_report_path: Path):
        report = SnykParser.parse_file(npm_report_path)
        high_and_above = SnykParser.filter_by_severity(report, Severity.high)
        assert len(high_and_above) == 2  # critical + high

        critical_only = SnykParser.filter_by_severity(report, Severity.critical)
        assert len(critical_only) == 1
        assert critical_only[0].package_name == "axios"

    def test_group_by_package(self, npm_report_path: Path):
        report = SnykParser.parse_file(npm_report_path)
        groups = SnykParser.group_by_package(report.vulnerabilities)
        assert "lodash" in groups
        assert "axios" in groups
        assert "express" in groups

    def test_deduplicate(self, npm_report_path: Path):
        report = SnykParser.parse_file(npm_report_path)
        # Double the vulns
        duped = report.vulnerabilities + report.vulnerabilities
        unique = SnykParser.deduplicate(duped)
        assert len(unique) == 3

    def test_vulnerability_severity_ordering(self):
        assert Severity.critical > Severity.high
        assert Severity.high > Severity.medium
        assert Severity.medium > Severity.low
        assert Severity.critical >= Severity.critical

    def test_parse_missing_file(self):
        from viper import ViperParseError

        with pytest.raises(ViperParseError, match="not found"):
            SnykParser.parse_file(Path("/nonexistent/report.json"))

    def test_vulnerability_fields(self, npm_report_path: Path):
        report = SnykParser.parse_file(npm_report_path)
        axios = next(v for v in report.vulnerabilities if v.package_name == "axios")
        assert axios.severity == Severity.critical
        assert axios.version == "0.21.1"
        assert axios.is_upgradable is True
        assert axios.cvss_score == 9.1
        assert "CVE-2023-45857" in axios.identifiers.cve
