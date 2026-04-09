"""Tests for VIPER configuration defaults."""

from viper.config import ViperConfig


def test_agent_default_max_iterations_is_40():
    cfg = ViperConfig()
    assert cfg.agent.max_iterations == 40


def test_agent_default_pre_edit_budget_is_10():
    cfg = ViperConfig()
    assert cfg.agent.max_no_edit_iterations == 10


def test_default_severity_threshold_is_high():
    cfg = ViperConfig()
    assert cfg.severity_threshold == "high"
