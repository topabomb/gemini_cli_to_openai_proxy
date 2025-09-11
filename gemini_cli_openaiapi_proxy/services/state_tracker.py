class SystemStateTracker:
    """
    A lightweight, non-blocking tracker for active system requests.

    This class maintains a simple counter for concurrent requests.
    In CPython, simple integer increments/decrements are atomic due to the
    Global Interpreter Lock (GIL), so no explicit locking is required for
    this specific use case, making it highly efficient.
    """
    def __init__(self):
        self._active_requests = 0

    def increment(self):
        """Increments the active request counter."""
        self._active_requests += 1

    def decrement(self):
        """
        Decrements the active request counter.

        Ensures the counter does not go below zero.
        """
        self._active_requests = max(0, self._active_requests - 1)

    @property
    def active_requests_count(self) -> int:
        """Returns the current number of active requests."""
        return self._active_requests
