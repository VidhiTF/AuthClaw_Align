from typing import Any, Dict, List

from .base import BaseProvider


class LocalProvider(BaseProvider):
    """
    Deterministic local provider used only when no external provider credential is
    configured in non-production environments.
    """

    model_name = "authclaw-local-secure"
    api_url = "local://authclaw"

    def generate(
        self,
        prompt: str,
        system_instruction: str = None,
        history: List[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        return (
            "AuthClaw local provider response: the request completed through the "
            "gateway policy, redaction, and audit pipeline. Configure an OpenAI, "
            "Anthropic, Cohere, or Azure OpenAI credential on the Providers page "
            "to forward prompts to an external model."
        )
