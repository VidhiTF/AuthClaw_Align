import os

from .base import BaseProvider
from .gemini_provider import GeminiProvider
from .config import MODEL_PROVIDER

def get_provider() -> BaseProvider:
    provider_name = MODEL_PROVIDER.lower().replace(" ", "_")
    if provider_name == "gemini":
        return GeminiProvider()
    if provider_name == "openai":
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(api_key=os.getenv("OPENAI_API_KEY"))
    if provider_name == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=os.getenv("ANTHROPIC_API_KEY"))
    if provider_name == "cohere":
        from .cohere_provider import CohereProvider

        return CohereProvider(api_key=os.getenv("COHERE_API_KEY"))
    if provider_name in {"azure", "azure_openai"}:
        from .azure_openai_provider import AzureOpenAIProvider

        return AzureOpenAIProvider(
            api_key=os.getenv("AZURE_OPENAI_API_KEY"),
            deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT") or os.getenv("MODEL_NAME"),
            api_url=os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
        )
    raise ValueError(f"Unsupported model provider configured: {MODEL_PROVIDER}")
