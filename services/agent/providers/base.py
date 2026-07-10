from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_instruction: str = None, history: List[Dict[str, Any]] = None, **kwargs) -> str:
        """
        Generate a text response from the model provider.
        """
        pass
