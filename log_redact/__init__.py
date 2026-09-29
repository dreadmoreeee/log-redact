"""log-redact: redact personal data and secrets from logs and text files."""

from .core import BUILTIN, Config, Redactor

__version__ = "0.1.0"
__all__ = ["BUILTIN", "Config", "Redactor", "__version__"]
