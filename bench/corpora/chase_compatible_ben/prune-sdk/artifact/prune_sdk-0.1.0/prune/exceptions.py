"""Prune SDK exceptions."""


class PruneError(Exception):
    """Base error for Prune SDK."""


class PruneConfigError(PruneError):
    """Missing or invalid configuration."""


class PruneProxyError(PruneError):
    """Prune proxy request failed."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code
