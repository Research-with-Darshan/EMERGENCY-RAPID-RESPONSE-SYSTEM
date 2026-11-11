"""Small in-memory request limit for public report submission and staff login."""

from time import time

_hits = {}


def allow(key, limit=30, window=60):
    now = time()
    recent = [stamp for stamp in _hits.get(key, []) if now - stamp < window]
    if len(recent) >= limit:
        _hits[key] = recent
        return False
    recent.append(now)
    _hits[key] = recent
    return True
