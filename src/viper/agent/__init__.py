"""Agent package exports."""

from __future__ import annotations

__all__ = ["ViperAgent"]


def __getattr__(name: str):
    if name == "ViperAgent":
        from viper.agent.loop import ViperAgent

        return ViperAgent
    raise AttributeError(name)
