"""Tracker backend registry.

Backends register under a stable ``name``. Add one by subclassing
:class:`~secledger.trackers.base.Tracker` and calling :func:`register`
(or importing it here). The name becomes the key the ledger uses to stamp
per-tracker filing state, so keep it stable.
"""
from __future__ import annotations

from .base import Tracker, TrackerError, Transport, urllib_transport
from .github import GitHubTracker
from .gitlab import GitLabTracker
from .jira import JiraError, JiraTracker

_REGISTRY: dict[str, type[Tracker]] = {}


def register(cls: type[Tracker]) -> type[Tracker]:
    _REGISTRY[cls.name] = cls
    return cls


def get_tracker_class(name: str) -> type[Tracker]:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise TrackerError(
            f"unknown tracker {name!r}; available: {', '.join(sorted(_REGISTRY))}"
        )


def available() -> list[str]:
    return sorted(_REGISTRY)


register(GitLabTracker)
register(GitHubTracker)
register(JiraTracker)

__all__ = [
    "Tracker",
    "TrackerError",
    "Transport",
    "urllib_transport",
    "GitLabTracker",
    "GitHubTracker",
    "JiraTracker",
    "JiraError",
    "register",
    "get_tracker_class",
    "available",
]
