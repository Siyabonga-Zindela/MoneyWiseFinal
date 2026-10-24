"""Shared slowapi limiter (in-memory counters; swap for Redis if we scale out)."""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
