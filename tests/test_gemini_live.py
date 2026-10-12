"""M6A live smoke (opt-in only).

Runs only when CLOUDSEC_LIVE_GEMINI=1. Sends a harmless synthetic
prompt through the real GeminiModelPort: no M1 content, no bucket,
user, secret, or function names. Authentication problems fail;
model unavailability or rate limiting skips as environment capacity.
"""

import os

import pytest

from cloudsec_agent.agent.model_port import ModelContext, ModelTurn
from cloudsec_agent.providers.gemini import (GeminiModelPort,
                                             GeminiProviderError)

pytestmark = pytest.mark.skipif(
    os.environ.get("CLOUDSEC_LIVE_GEMINI") != "1",
    reason="live Gemini smoke is opt-in via CLOUDSEC_LIVE_GEMINI=1")


def test_live_provider_smoke_is_synthetic_only():
    port = GeminiModelPort()
    try:
        turn = port.complete(ModelContext(run_id="live-smoke-1",
                                          turn_number=1, observations=()))
    except GeminiProviderError as exc:
        if exc.code == "auth_error":
            pytest.fail("live smoke authentication failed")
        pytest.skip(f"live provider unavailable: {exc.code}")
    assert isinstance(turn, ModelTurn)
