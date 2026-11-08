import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from stub import Clock, make_setup


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def setup(clock):
    """Starts a stub relay and a keyring for it: setup(live=[...], world=..., exec=..., github=...,
    plus relay.Relay's options)."""
    relays = []
    yield make_setup(clock, relays)
    for r in relays:
        r.close()
