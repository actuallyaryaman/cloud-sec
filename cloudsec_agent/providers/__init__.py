__all__ = [
    "gemini",
    "kilo",
    "KiloModelPort",
    "GeminiModelPort",
    "create_model_port",
]

from .gemini import GeminiModelPort
from .kilo import KiloModelPort
from .model_config import load_model_settings, resolve_provider


def create_model_port(provider=None, model=None, **kwargs):
    settings = load_model_settings()
    name = resolve_provider(provider, settings)
    if name == "kilo":
        return KiloModelPort(model=model, **kwargs)
    return GeminiModelPort(model=model, **kwargs)
