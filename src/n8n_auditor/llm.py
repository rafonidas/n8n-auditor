"""AI review layer (Gemini). Implemented in M4; this stub keeps --no-llm optional."""
from __future__ import annotations


class LLMError(Exception):
    pass


class LLMReviewer:
    def __init__(self, max_calls: int = 20) -> None:
        raise LLMError("AI layer not yet available")
